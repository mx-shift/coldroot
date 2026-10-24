//! The drill ceremony: prove that the shares, the state disc, the HSM and
//! the machine still work together, without issuing anything.
//!
//! A quorum of custodians presents shares, the wrap key is rebuilt, the root
//! keys are restored into the HSM, each one signs a test message that is
//! checked against its recorded public key, and the HSM is wiped. The only
//! output is a new state disc whose transcript records the drill.

use std::collections::BTreeSet;

use coldroot_core::{
    shares::{KeyShare, ShareError},
    transcript::{Anchor, Confirmation, Event, Operation, Participant, Transcript},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};

use crate::{
    CeremonyError, Console, Hsm, Outcome, ShareInput, State, reset, sha256, verifier_committed,
};

pub fn run(
    state: &State,
    participants: Vec<Participant>,
    hsm: &mut dyn Hsm,
    console: &mut dyn Console,
) -> Result<Outcome, CeremonyError> {
    if state.keys.is_empty() {
        return Err(CeremonyError::NoKeys);
    }
    let mut transcript = Transcript::new(&Anchor::Previous(state.transcript_head));
    transcript.append(Event::CeremonyStarted { participants })?;

    let by = console.confirm("The machine clock matches an independent time source.")?;
    transcript.append(Event::Confirmed {
        by,
        what: Confirmation::ClockCorrect,
    })?;

    let verifier = &state.verifier;
    transcript.append(verifier_committed(verifier))?;

    // Collect shares until a quorum has verified. A share that fails is
    // reported and the custodian can try again; nothing about it is recorded.
    let mut accepted: Vec<KeyShare> = Vec::new();
    let mut seen = BTreeSet::new();
    while accepted.len() < usize::from(verifier.threshold) {
        let (by, input) = console.collect_share(verifier.generation)?;
        let share = match parse(verifier.generation, input).and_then(|share| {
            verifier.check(&share)?;
            Ok(share)
        }) {
            Ok(share) => share,
            Err(e) => {
                console.notice(&format!("Share not accepted: {e}"));
                continue;
            }
        };
        if !seen.insert(share.index()) {
            console.notice(&format!(
                "Share {} has already been presented.",
                share.index()
            ));
            continue;
        }
        transcript.append(Event::ShareAccepted {
            custodian: share.index(),
            by,
        })?;
        accepted.push(share);
    }

    let wrap_key = verifier.combine(&accepted)?;
    drop(accepted);
    hsm.install_wrap_key(wrap_key.as_bytes())?;
    transcript.append(Event::Performed(Operation::InstallWrapKey))?;
    drop(wrap_key);

    for key in &state.keys {
        let restored = hsm.import_wrapped(&key.blob)?;
        if restored != key.id {
            return Err(CeremonyError::WrongKeyRestored {
                key_id: key.id,
                restored,
            });
        }
        transcript.append(Event::Performed(Operation::ImportWrapped {
            key_id: key.id,
        }))?;
    }

    // Each key must still be the key that was recorded, and must still sign.
    let challenge = sha256(&[b"coldroot drill".as_slice(), &state.transcript_head].concat());
    for key in &state.keys {
        if hsm.public_key(key.id)? != key.public_key {
            return Err(CeremonyError::PublicKeyMismatch { key_id: key.id });
        }
        let verifying_key = VerifyingKey::from_sec1_bytes(&key.public_key)
            .map_err(|_| CeremonyError::PublicKeyMismatch { key_id: key.id })?;
        let signature = hsm.sign_prehash(key.id, &challenge)?;
        Signature::from_der(&signature)
            .and_then(|sig| verifying_key.verify_prehash(&challenge, &sig))
            .map_err(|_| CeremonyError::BadSignature { key_id: key.id })?;
        transcript.append(Event::Performed(Operation::TestSignatureVerified {
            key_id: key.id,
        }))?;
    }

    transcript.append(reset(hsm)?)?;
    transcript.append(Event::CeremonyEnded)?;

    Ok(Outcome {
        state: State {
            transcript_head: transcript.head(),
            ..state.clone()
        },
        transcript: transcript.entries().to_vec(),
    })
}

fn parse(generation: u32, input: ShareInput) -> Result<KeyShare, ShareError> {
    match input {
        ShareInput::Disc(json) => KeyShare::from_json(&json),
        ShareInput::Paper { index, lines } => {
            let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
            KeyShare::parse(generation, index, &lines)
        }
    }
}
