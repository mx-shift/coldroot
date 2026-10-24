//! Init on one HSM, then a drill on a different, empty HSM, with shares
//! presented from discs and from paper.
//!
//! The HSM here is a software stand-in that implements [`Hsm`] just well
//! enough to tell a right wrap key from a wrong one. `coldroot-hsm` runs the
//! same ceremonies against the YubiHSM mock.

use std::collections::{BTreeMap, VecDeque};

use coldroot_ceremony::{
    Aborted, Console, Hsm, HsmError, KeyId, Participant, ShareInput, State, drill,
    init::{self, InitConfig, KeySpec},
};
use coldroot_core::{
    shares::KeyShare,
    transcript::{Anchor, Event, ParticipantId, verify},
};
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

/// Keys live in a map; a "wrapped" blob is a tag of the wrap key, the key ID
/// and the plain scalar. Nothing about it is secure; it only has to behave
/// like a device that refuses blobs made under a different wrap key.
#[derive(Default)]
struct FakeHsm {
    wrap_key: Option<[u8; 32]>,
    keys: BTreeMap<KeyId, SigningKey>,
}

impl FakeHsm {
    fn tag(&self) -> Result<[u8; 32], HsmError> {
        let wrap_key = self.wrap_key.ok_or("no wrap key installed")?;
        Ok(Sha256::digest([b"fake wrap".as_slice(), &wrap_key].concat()).into())
    }
}

impl Hsm for FakeHsm {
    fn install_wrap_key(&mut self, key: &[u8; 32]) -> Result<(), HsmError> {
        self.wrap_key = Some(*key);
        Ok(())
    }

    fn generate_signing_key(&mut self, id: KeyId, _label: &str) -> Result<(), HsmError> {
        self.keys.insert(id, SigningKey::random(&mut OsRng));
        Ok(())
    }

    fn public_key(&mut self, id: KeyId) -> Result<Vec<u8>, HsmError> {
        let key = self.keys.get(&id).ok_or("no such key")?;
        Ok(key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec())
    }

    fn export_wrapped(&mut self, id: KeyId) -> Result<Vec<u8>, HsmError> {
        let tag = self.tag()?;
        let key = self.keys.get(&id).ok_or("no such key")?;
        Ok([&tag[..], &id.to_be_bytes(), &key.to_bytes()].concat())
    }

    fn import_wrapped(&mut self, blob: &[u8]) -> Result<KeyId, HsmError> {
        let (tag, rest) = blob.split_at_checked(32).ok_or("short blob")?;
        if tag != self.tag()? {
            return Err("blob was wrapped under a different key".into());
        }
        let (id, scalar) = rest.split_at_checked(2).ok_or("short blob")?;
        let id = KeyId::from_be_bytes(id.try_into()?);
        self.keys.insert(id, SigningKey::from_slice(scalar)?);
        Ok(id)
    }

    fn sign_prehash(&mut self, id: KeyId, digest: &[u8; 32]) -> Result<Vec<u8>, HsmError> {
        let key = self.keys.get(&id).ok_or("no such key")?;
        let signature: p256::ecdsa::Signature = key.sign_prehash(digest)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn reset(&mut self) -> Result<(), HsmError> {
        *self = Self::default();
        Ok(())
    }
}

fn people() -> Vec<Participant> {
    ["Operator", "Ana", "Bo", "Cy", "Di", "Ed"]
        .iter()
        .map(|name| Participant {
            name: name.to_string(),
        })
        .collect()
}

/// Custodian `index` is participant `index` (the operator is 0).
#[derive(Default)]
struct Scripted {
    /// Shares handed out at init, as (paper lines, disc record).
    issued: Vec<(Vec<String>, String)>,
    /// What to present at a drill, in order.
    to_present: VecDeque<(ParticipantId, ShareInput)>,
    notices: Vec<String>,
}

impl Console for Scripted {
    fn notice(&mut self, text: &str) {
        self.notices.push(text.to_string());
    }

    fn confirm(&mut self, _prompt: &str) -> Result<ParticipantId, Aborted> {
        Ok(0)
    }

    fn issue_share(&mut self, share: &KeyShare) -> Result<ParticipantId, Aborted> {
        let lines = share.to_lines().iter().map(|l| l.to_string()).collect();
        self.issued.push((lines, share.to_json().to_string()));
        Ok(share.index())
    }

    fn collect_share(&mut self, _generation: u32) -> Result<(ParticipantId, ShareInput), Aborted> {
        self.to_present.pop_front().ok_or(Aborted)
    }
}

fn run_init(console: &mut Scripted) -> State {
    let config = InitConfig {
        organization: "example.org".into(),
        public_anchor: Some("drand quicknet round 1234567".into()),
        participants: people(),
        threshold: 3,
        limit: 5,
        keys: vec![
            KeySpec {
                id: 0x100,
                label: "root-x509".into(),
            },
            KeySpec {
                id: 0x101,
                label: "root-ssh-users".into(),
            },
        ],
    };
    let mut hsm = FakeHsm::default();
    let outcome = init::run(&config, &mut hsm, console).unwrap();

    assert_eq!(console.issued.len(), 5);
    assert_eq!(outcome.state.keys.len(), 2);
    assert!(outcome.state.keys.iter().all(|k| !k.blob.is_empty()));
    let anchor = Anchor::Genesis(outcome.state.genesis.clone());
    assert_eq!(
        verify(&anchor, &outcome.transcript).unwrap(),
        outcome.state.transcript_head
    );
    // The HSM was wiped.
    assert!(hsm.public_key(0x100).is_err());
    outcome.state
}

#[test]
fn init_then_drill_on_a_different_hsm() {
    let mut console = Scripted::default();
    let state = run_init(&mut console);

    // Custodians 1 and 4 bring their discs, 3 reads from paper.
    console.to_present = VecDeque::from([
        (1, ShareInput::Disc(console.issued[0].1.clone())),
        (
            3,
            ShareInput::Paper {
                index: 3,
                lines: console.issued[2].0.clone(),
            },
        ),
        (4, ShareInput::Disc(console.issued[3].1.clone())),
    ]);
    let mut hsm = FakeHsm::default();
    let outcome = drill::run(&state, people(), &mut hsm, &mut console).unwrap();

    let anchor = Anchor::Previous(state.transcript_head);
    assert_eq!(
        verify(&anchor, &outcome.transcript).unwrap(),
        outcome.state.transcript_head
    );
    let accepted: Vec<_> = outcome
        .transcript
        .iter()
        .filter_map(|e| match &e.event {
            Event::ShareAccepted { custodian, by } => Some((*custodian, *by)),
            _ => None,
        })
        .collect();
    assert_eq!(accepted, [(1, 1), (3, 3), (4, 4)]);
    assert!(outcome.transcript.iter().any(|e| matches!(
        e.event,
        Event::Performed(
            coldroot_core::transcript::Operation::TestSignatureVerified { key_id: 0x101 }
        )
    )));
    assert_eq!(outcome.state.keys, state.keys);
    assert!(hsm.public_key(0x100).is_err());
}

#[test]
fn drill_rejects_bad_shares_and_keeps_asking() {
    let mut console = Scripted::default();
    let state = run_init(&mut console);

    let mut typo = console.issued[1].0.clone();
    typo[0].replace_range(3..4, "x");
    let mut old_generation = console.issued[4].1.clone();
    old_generation = old_generation.replace("\"generation\":1", "\"generation\":0");

    console.to_present = VecDeque::from([
        (1, ShareInput::Disc(console.issued[0].1.clone())),
        (1, ShareInput::Disc(console.issued[0].1.clone())), // duplicate
        (
            2,
            ShareInput::Paper {
                index: 2,
                lines: typo,
            },
        ),
        (5, ShareInput::Disc(old_generation)),
        (2, ShareInput::Disc(console.issued[1].1.clone())),
        (5, ShareInput::Disc(console.issued[4].1.clone())),
    ]);
    let outcome = drill::run(&state, people(), &mut FakeHsm::default(), &mut console).unwrap();

    let notices = console.notices.join("\n");
    assert!(notices.contains("already been presented"), "{notices}");
    assert!(notices.contains("line 1"), "{notices}");
    assert!(notices.contains("generation 0"), "{notices}");
    let accepted = outcome
        .transcript
        .iter()
        .filter(|e| matches!(e.event, Event::ShareAccepted { .. }))
        .count();
    assert_eq!(accepted, 3);
}

#[test]
fn drill_fails_when_the_quorum_gives_up() {
    let mut console = Scripted::default();
    let state = run_init(&mut console);
    console.to_present = VecDeque::from([(1, ShareInput::Disc(console.issued[0].1.clone()))]);
    assert!(matches!(
        drill::run(&state, people(), &mut FakeHsm::default(), &mut console),
        Err(coldroot_ceremony::CeremonyError::Aborted(_))
    ));
}
