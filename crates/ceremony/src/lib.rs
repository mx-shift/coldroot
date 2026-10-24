//! The ceremonies coldroot runs.
//!
//! A ceremony is a fixed sequence of steps over three things: the hash-chained
//! transcript, the custodians' shares, and an HSM that is empty when the
//! ceremony starts and empty again when it ends. The operator and witnesses
//! take part through a [`Console`], which the TUI implements and tests script;
//! the device is reached through an [`Hsm`], which `coldroot-hsm` implements
//! for the YubiHSM 2 and tests implement in software.
//!
//! Each ceremony reads a [`State`] from the previous state disc (except
//! `init`, which creates the first one) and produces an [`Outcome`]: the new
//! state and the transcript, both of which the caller burns to the next disc.

pub mod drill;
pub mod hsm;
pub mod init;

use coldroot_core::{
    shares::{KeyShare, ShareError, Verifier},
    transcript::{Entry, Event, Genesis, Hash, ParticipantId, TranscriptError},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use coldroot_core::transcript::Participant;
pub use hsm::{Hsm, HsmError, KeyId};

/// How the operator and witnesses take part in a ceremony.
pub trait Console {
    /// Show the people present something they need to know. Not recorded.
    fn notice(&mut self, text: &str);

    /// Ask for confirmation of `prompt`; returns who confirmed.
    fn confirm(&mut self, prompt: &str) -> Result<ParticipantId, Aborted>;

    /// Hand a newly made share to its custodian (print the lines, burn the
    /// share disc); returns who confirmed they have it.
    fn issue_share(&mut self, share: &KeyShare) -> Result<ParticipantId, Aborted>;

    /// Collect one share for `generation` from whoever presents it.
    fn collect_share(&mut self, generation: u32) -> Result<(ParticipantId, ShareInput), Aborted>;
}

/// A share as a custodian presents it.
pub enum ShareInput {
    /// The JSON record from a share disc.
    Disc(String),
    /// Transcribed lines from the paper copy of share `index`.
    Paper { index: u8, lines: Vec<String> },
}

/// The people present stopped the ceremony.
#[derive(Debug, thiserror::Error)]
#[error("ceremony aborted")]
pub struct Aborted;

#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    #[error(transparent)]
    Aborted(#[from] Aborted),
    #[error("transcript: {0}")]
    Transcript(#[from] TranscriptError),
    #[error("shares: {0}")]
    Share(#[from] ShareError),
    #[error("HSM: {0}")]
    Hsm(#[from] HsmError),
    #[error("wrapped blob for key {key_id} restored key {restored} instead")]
    WrongKeyRestored { key_id: KeyId, restored: KeyId },
    #[error("restored key {key_id} has a different public key than recorded")]
    PublicKeyMismatch { key_id: KeyId },
    #[error("restored key {key_id} produced a signature that does not verify")]
    BadSignature { key_id: KeyId },
    #[error("state has no keys")]
    NoKeys,
}

/// A root key as kept on the state disc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredKey {
    pub id: KeyId,
    pub label: String,
    /// SEC1 uncompressed P-256 point.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    /// The key wrapped under the custodians' wrap key: nonce then ciphertext,
    /// as the YubiHSM exports it.
    #[serde(with = "hex::serde")]
    pub blob: Vec<u8>,
}

/// Everything a state disc carries besides the transcript.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub genesis: Genesis,
    pub verifier: Verifier,
    pub keys: Vec<StoredKey>,
    /// Final hash of the transcript that produced this state, which the next
    /// ceremony's transcript chains from.
    #[serde(with = "hex::serde")]
    pub transcript_head: Hash,
}

/// What a ceremony produces for the next state disc.
#[derive(Debug)]
pub struct Outcome {
    pub state: State,
    pub transcript: Vec<Entry>,
}

fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

fn verifier_committed(verifier: &Verifier) -> Event {
    Event::VerifierCommitted {
        generation: verifier.generation,
        sha256: sha256(&serde_json::to_vec(verifier).expect("verifier serializes")),
    }
}

fn reset(hsm: &mut dyn Hsm) -> Result<Event, CeremonyError> {
    hsm.reset()?;
    Ok(Event::Performed(
        coldroot_core::transcript::Operation::ResetHsm,
    ))
}
