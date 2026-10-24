//! Init on one HSM, then a drill on a different, empty HSM, with shares
//! presented from discs and from paper.

use std::collections::VecDeque;

use coldroot_ceremony::{
    Aborted, Console, Participant, ShareInput, State, drill,
    init::{self, InitConfig, KeySpec},
};
use coldroot_core::{
    shares::KeyShare,
    transcript::{Anchor, Event, ParticipantId, verify},
};
use yubihsm::{Client, Connector, Credentials};

fn fresh_hsm() -> Client {
    Client::open(Connector::mockhsm(), Credentials::default(), true).unwrap()
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
    let hsm = fresh_hsm();
    let outcome = init::run(&config, &hsm, console).unwrap();

    assert_eq!(console.issued.len(), 5);
    assert_eq!(outcome.state.keys.len(), 2);
    assert!(outcome.state.keys.iter().all(|k| !k.blob.is_empty()));
    let anchor = Anchor::Genesis(outcome.state.genesis.clone());
    assert_eq!(
        verify(&anchor, &outcome.transcript).unwrap(),
        outcome.state.transcript_head
    );
    // The HSM was wiped: a fresh session finds no key.
    assert!(fresh_hsm().get_public_key(0x100).is_err());
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
    let hsm = fresh_hsm();
    let outcome = drill::run(&state, people(), &hsm, &mut console).unwrap();

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
    assert!(fresh_hsm().get_public_key(0x100).is_err());
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
    let outcome = drill::run(&state, people(), &fresh_hsm(), &mut console).unwrap();

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
        drill::run(&state, people(), &fresh_hsm(), &mut console),
        Err(coldroot_ceremony::CeremonyError::Aborted(_))
    ));
}
