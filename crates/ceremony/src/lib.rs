//! The ceremonies coldroot runs.
//!
//! A ceremony is a fixed sequence of steps over three things: the hash-chained
//! transcript, the custodians' shares, and an HSM that is empty when the
//! ceremony starts and empty again when it ends. The operator and witnesses
//! take part through a [`Console`], which the TUI implements; tests script it.
//!
//! Each ceremony reads a [`State`] from the previous state disc (except
//! `init`, which creates the first one) and produces an [`Outcome`]: the new
//! state and the transcript, both of which the caller burns to the next disc.

pub mod drill;
pub mod init;

use coldroot_core::{
    shares::{KeyShare, ShareError, Verifier},
    transcript::{Entry, Event, Genesis, Hash, ParticipantId, TranscriptError},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use yubihsm::{Client, object};

pub use coldroot_core::transcript::Participant;

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
    Hsm(#[from] coldroot_hsm::Error),
    #[error("wrapped key blob for key {key_id} is malformed")]
    MalformedBlob { key_id: u16 },
    #[error("restored key {key_id} has a different public key than recorded")]
    PublicKeyMismatch { key_id: u16 },
    #[error("restored key {key_id} produced a signature that does not verify")]
    BadSignature { key_id: u16 },
    #[error("state has no keys")]
    NoKeys,
}

/// A root key as kept on the state disc.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredKey {
    pub id: u16,
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

/// Public key of `key_id` as an uncompressed SEC1 point, which is the HSM's
/// raw `x || y` with the 0x04 prefix the HSM leaves off.
fn public_key(client: &Client, key_id: u16) -> Result<Vec<u8>, CeremonyError> {
    let raw = client.get_public_key(key_id)?.into_vec();
    let mut sec1 = Vec::with_capacity(raw.len() + 1);
    sec1.push(0x04);
    sec1.extend_from_slice(&raw);
    Ok(sec1)
}

fn reset(client: &Client) -> Result<Event, CeremonyError> {
    client.reset_device()?;
    Ok(Event::Performed(
        coldroot_core::transcript::Operation::ResetHsm,
    ))
}

fn wrapped(key: &StoredKey) -> Result<coldroot_hsm::Wrapped, CeremonyError> {
    let message = yubihsm::wrap::Message::from_vec(key.blob.clone())
        .map_err(|_| CeremonyError::MalformedBlob { key_id: key.id })?;
    Ok(coldroot_hsm::Wrapped {
        object_type: object::Type::AsymmetricKey,
        object_id: key.id,
        message,
    })
}
