//! Hash-chained ceremony transcript.
//!
//! Every action taken during a ceremony is appended as an [`Entry`]. Each
//! entry commits to the hash of the entry before it, and the first entry
//! commits to the final hash of the previous ceremony's transcript (read from
//! the input state disc). Tampering with, removing, or reordering any entry
//! breaks the chain, which [`verify`] detects.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// Hash used as the predecessor of the very first ceremony.
pub const GENESIS: Hash = [0u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    CeremonyStarted {
        ceremony: String,
        operator_clock: String,
    },
    MediaRead {
        label: String,
        #[serde(with = "hex::serde")]
        sha256: Hash,
    },
    WitnessConfirmed {
        step: String,
        prompt: String,
    },
    ShareAccepted {
        custodian: u8,
    },
    Action {
        step: String,
        detail: String,
    },
    MediaWritten {
        label: String,
        #[serde(with = "hex::serde")]
        sha256: Hash,
    },
    ExceptionStarted {
        reason: String,
    },
    ExceptionCommand {
        command: String,
    },
    ExceptionEnded,
    CeremonyEnded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    #[serde(with = "hex::serde")]
    pub prev: Hash,
    pub event: Event,
}

impl Entry {
    pub fn hash(&self) -> Hash {
        // serde_json emits struct fields in declaration order, so this is a
        // stable encoding for our own types.
        let bytes = serde_json::to_vec(self).expect("entry serializes");
        Sha256::digest(&bytes).into()
    }
}

#[derive(Debug)]
pub struct Transcript {
    entries: Vec<Entry>,
    head: Hash,
}

impl Transcript {
    /// Start a transcript chained to the previous ceremony's final hash.
    pub fn new(previous: Hash) -> Self {
        Self {
            entries: Vec::new(),
            head: previous,
        }
    }

    pub fn append(&mut self, event: Event) -> &Entry {
        let entry = Entry {
            seq: self.entries.len() as u64,
            prev: self.head,
            event,
        };
        self.head = entry.hash();
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    pub fn head(&self) -> Hash {
        self.head
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn in_exception(&self) -> bool {
        let mut open = false;
        for e in &self.entries {
            match e.event {
                Event::ExceptionStarted { .. } => open = true,
                Event::ExceptionEnded => open = false,
                _ => {}
            }
        }
        open
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    BadSequence { index: usize },
    BrokenChain { seq: u64 },
}

/// Check that `entries` form an unbroken chain starting at `previous`,
/// returning the final hash.
pub fn verify(previous: Hash, entries: &[Entry]) -> Result<Hash, VerifyError> {
    let mut head = previous;
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(VerifyError::BadSequence { index: i });
        }
        if e.prev != head {
            return Err(VerifyError::BrokenChain { seq: e.seq });
        }
        head = e.hash();
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Transcript {
        let mut t = Transcript::new(GENESIS);
        t.append(Event::CeremonyStarted {
            ceremony: "init".into(),
            operator_clock: "2026-10-24T07:00:00Z".into(),
        });
        t.append(Event::ShareAccepted { custodian: 1 });
        t.append(Event::Action {
            step: "generate".into(),
            detail: "root-a".into(),
        });
        t.append(Event::CeremonyEnded);
        t
    }

    #[test]
    fn chain_verifies() {
        let t = sample();
        assert_eq!(verify(GENESIS, t.entries()), Ok(t.head()));
    }

    #[test]
    fn tamper_is_detected() {
        let t = sample();
        let mut entries = t.entries().to_vec();
        entries[1].event = Event::ShareAccepted { custodian: 2 };
        assert_eq!(
            verify(GENESIS, &entries),
            Err(VerifyError::BrokenChain { seq: 2 })
        );
    }

    #[test]
    fn removal_is_detected() {
        let t = sample();
        let mut entries = t.entries().to_vec();
        entries.remove(1);
        assert_eq!(
            verify(GENESIS, &entries),
            Err(VerifyError::BadSequence { index: 1 })
        );
    }

    #[test]
    fn chains_across_ceremonies() {
        let first = sample();
        let mut second = Transcript::new(first.head());
        second.append(Event::CeremonyEnded);
        assert!(verify(first.head(), second.entries()).is_ok());
        assert!(verify(GENESIS, second.entries()).is_err());
    }

    #[test]
    fn tracks_exception_mode() {
        let mut t = Transcript::new(GENESIS);
        t.append(Event::ExceptionStarted {
            reason: "re-sign expired CRL".into(),
        });
        assert!(t.in_exception());
        t.append(Event::ExceptionEnded);
        assert!(!t.in_exception());
    }
}
