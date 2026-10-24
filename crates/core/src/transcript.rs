//! Hash-chained ceremony transcript.
//!
//! Every action taken during a ceremony is appended as an [`Entry`]. Each
//! entry commits to the hash of the entry before it. The first entry commits
//! to an [`Anchor`]: for the very first ceremony that is the hash of a
//! [`Genesis`] record, and for every later ceremony it is the final hash of the
//! previous ceremony's transcript (read from the input state disc). Tampering
//! with, removing, or reordering any entry breaks the chain, and malformed
//! sequences (such as nested exceptions) are refused, both when appending and
//! when verifying a transcript read back from disc.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// Domain separator for the genesis anchor hash.
const GENESIS_DOMAIN: &[u8] = b"coldroot genesis v1\0";

/// What the first ceremony chains from. It ties the transcript to evidence
/// that exists outside it: a fresh random nonce printed and kept with the
/// ceremony records, and optionally a public value that could not have been
/// known in advance (a randomness beacon round, a newspaper headline), which
/// shows the ceremony happened no earlier than that value was published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    pub organization: String,
    pub created: Timestamp,
    #[serde(with = "hex::serde")]
    pub nonce: [u8; 32],
    pub public_anchor: Option<String>,
}

impl Genesis {
    pub fn hash(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(GENESIS_DOMAIN);
        h.update(serde_json::to_vec(self).expect("genesis serializes"));
        h.finalize().into()
    }
}

/// The predecessor a transcript chains from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchor {
    Genesis(Genesis),
    Previous(Hash),
}

impl Anchor {
    pub fn hash(&self) -> Hash {
        match self {
            Anchor::Genesis(g) => g.hash(),
            Anchor::Previous(h) => *h,
        }
    }
}

/// Someone present at the ceremony.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    CeremonyStarted {
        participants: Vec<Participant>,
    },
    ExceptionStarted {
        reason: String,
    },
    /// A command run in exception mode: its argument vector and exit status.
    ExceptionCommand {
        argv: Vec<String>,
        exit_status: i32,
    },
    ExceptionEnded,
    CeremonyEnded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    #[serde(with = "hex::serde")]
    pub prev: Hash,
    /// Ceremony machine clock, which is set by hand before the ceremony.
    pub time: Timestamp,
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

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TranscriptError {
    #[error("entry {index} has sequence number {seq}")]
    BadSequence { index: usize, seq: u64 },
    #[error("entry {seq} does not chain to its predecessor")]
    BrokenChain { seq: u64 },
    #[error("entry {seq} is out of order: {reason}")]
    Malformed { seq: u64, reason: &'static str },
    #[error("entry {seq} is earlier than the entry before it")]
    TimeWentBackwards { seq: u64 },
}

/// Where the transcript is in its life cycle; enforces the event grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    NotStarted,
    Running,
    Exception,
    Ended,
}

#[derive(Debug)]
struct Grammar {
    phase: Phase,
    last_time: Option<Timestamp>,
}

impl Grammar {
    fn new() -> Self {
        Self {
            phase: Phase::NotStarted,
            last_time: None,
        }
    }

    /// Check `event` at `time` is allowed next, and advance.
    fn step(&mut self, seq: u64, time: Timestamp, event: &Event) -> Result<(), TranscriptError> {
        use Phase::*;
        let malformed = |reason| Err(TranscriptError::Malformed { seq, reason });

        if self.last_time.is_some_and(|t| time < t) {
            return Err(TranscriptError::TimeWentBackwards { seq });
        }
        let next = match (self.phase, event) {
            (NotStarted, Event::CeremonyStarted { participants }) => {
                if participants.is_empty() {
                    return malformed("a ceremony needs at least one participant");
                }
                Running
            }
            (NotStarted, _) => return malformed("first event must be ceremony_started"),
            (_, Event::CeremonyStarted { .. }) => return malformed("ceremony already started"),
            (Ended, _) => return malformed("ceremony already ended"),

            (Running, Event::ExceptionStarted { .. }) => Exception,
            (Exception, Event::ExceptionStarted { .. }) => {
                return malformed("exceptions cannot be nested");
            }
            (Exception, Event::ExceptionEnded) => Running,
            (Running, Event::ExceptionEnded) => return malformed("no exception to end"),
            (Exception, Event::ExceptionCommand { .. }) => Exception,
            (Running, Event::ExceptionCommand { .. }) => {
                return malformed("commands are only allowed in exception mode");
            }
            (Exception, Event::CeremonyEnded) => {
                return malformed("exception must end before the ceremony");
            }
            (Running, Event::CeremonyEnded) => Ended,
        };
        self.phase = next;
        self.last_time = Some(time);
        Ok(())
    }
}

#[derive(Debug)]
pub struct Transcript {
    entries: Vec<Entry>,
    head: Hash,
    grammar: Grammar,
}

impl Transcript {
    pub fn new(anchor: &Anchor) -> Self {
        Self {
            entries: Vec::new(),
            head: anchor.hash(),
            grammar: Grammar::new(),
        }
    }

    /// Append `event` stamped with the current system time.
    pub fn append(&mut self, event: Event) -> Result<&Entry, TranscriptError> {
        self.append_at(Timestamp::now(), event)
    }

    pub fn append_at(&mut self, time: Timestamp, event: Event) -> Result<&Entry, TranscriptError> {
        let seq = self.entries.len() as u64;
        self.grammar.step(seq, time, &event)?;
        let entry = Entry {
            seq,
            prev: self.head,
            time,
            event,
        };
        self.head = entry.hash();
        self.entries.push(entry);
        Ok(self.entries.last().unwrap())
    }

    pub fn head(&self) -> Hash {
        self.head
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn in_exception(&self) -> bool {
        self.grammar.phase == Phase::Exception
    }

    pub fn is_ended(&self) -> bool {
        self.grammar.phase == Phase::Ended
    }
}

/// Check that `entries` form a complete, well-formed ceremony chained from
/// `anchor`, returning the final hash.
pub fn verify(anchor: &Anchor, entries: &[Entry]) -> Result<Hash, TranscriptError> {
    let mut head = anchor.hash();
    let mut grammar = Grammar::new();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            return Err(TranscriptError::BadSequence {
                index: i,
                seq: e.seq,
            });
        }
        if e.prev != head {
            return Err(TranscriptError::BrokenChain { seq: e.seq });
        }
        grammar.step(e.seq, e.time, &e.event)?;
        head = e.hash();
    }
    if grammar.phase != Phase::Ended {
        return Err(TranscriptError::Malformed {
            seq: entries.len() as u64,
            reason: "transcript ends before ceremony_ended",
        });
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis() -> Anchor {
        Anchor::Genesis(Genesis {
            organization: "example.org".into(),
            created: "2026-10-24T07:00:00Z".parse().unwrap(),
            nonce: [42; 32],
            public_anchor: Some("drand quicknet round 1234567".into()),
        })
    }

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_second(1_793_000_000 + secs).unwrap()
    }

    fn started() -> Event {
        Event::CeremonyStarted {
            participants: vec![
                Participant {
                    name: "Operator".into(),
                },
                Participant {
                    name: "Witness".into(),
                },
            ],
        }
    }

    fn sample(anchor: &Anchor) -> Transcript {
        let mut tr = Transcript::new(anchor);
        tr.append_at(t(0), started()).unwrap();
        tr.append_at(
            t(1),
            Event::ExceptionStarted {
                reason: "re-sign expired CRL".into(),
            },
        )
        .unwrap();
        tr.append_at(
            t(2),
            Event::ExceptionCommand {
                argv: vec!["coldroot".into(), "crl".into()],
                exit_status: 0,
            },
        )
        .unwrap();
        tr.append_at(t(3), Event::ExceptionEnded).unwrap();
        tr.append_at(t(4), Event::CeremonyEnded).unwrap();
        tr
    }

    #[test]
    fn chain_verifies() {
        let a = genesis();
        let tr = sample(&a);
        assert_eq!(verify(&a, tr.entries()), Ok(tr.head()));
    }

    #[test]
    fn genesis_details_change_the_anchor() {
        let Anchor::Genesis(mut g) = genesis() else {
            unreachable!()
        };
        let before = g.hash();
        g.nonce[0] ^= 1;
        assert_ne!(before, g.hash());
    }

    #[test]
    fn tamper_is_detected() {
        let a = genesis();
        let mut entries = sample(&a).entries().to_vec();
        entries[2].event = Event::ExceptionCommand {
            argv: vec!["coldroot".into(), "sign".into()],
            exit_status: 0,
        };
        assert_eq!(
            verify(&a, &entries),
            Err(TranscriptError::BrokenChain { seq: 3 })
        );
    }

    #[test]
    fn removal_is_detected() {
        let a = genesis();
        let mut entries = sample(&a).entries().to_vec();
        entries.remove(1);
        assert_eq!(
            verify(&a, &entries),
            Err(TranscriptError::BadSequence { index: 1, seq: 2 })
        );
    }

    #[test]
    fn truncation_is_detected() {
        let a = genesis();
        let entries = sample(&a).entries().to_vec();
        assert!(matches!(
            verify(&a, &entries[..4]),
            Err(TranscriptError::Malformed { seq: 4, .. })
        ));
    }

    #[test]
    fn chains_across_ceremonies() {
        let a = genesis();
        let first = sample(&a);
        let next = Anchor::Previous(first.head());
        let second = sample(&next);
        assert!(verify(&next, second.entries()).is_ok());
        assert!(verify(&a, second.entries()).is_err());
    }

    #[test]
    fn nested_exception_is_refused() {
        let mut tr = Transcript::new(&genesis());
        tr.append_at(t(0), started()).unwrap();
        tr.append_at(
            t(1),
            Event::ExceptionStarted {
                reason: "re-sign CRL".into(),
            },
        )
        .unwrap();
        assert!(tr.in_exception());
        assert!(matches!(
            tr.append_at(
                t(2),
                Event::ExceptionStarted {
                    reason: "again".into()
                }
            ),
            Err(TranscriptError::Malformed { seq: 2, .. })
        ));
        tr.append_at(t(2), Event::ExceptionEnded).unwrap();
        assert!(!tr.in_exception());
    }

    #[test]
    fn nested_exception_on_disc_is_refused() {
        // Build a chain that bypasses append's checks, as a forged disc would.
        let a = genesis();
        let events = [
            started(),
            Event::ExceptionStarted {
                reason: "one".into(),
            },
            Event::ExceptionStarted {
                reason: "two".into(),
            },
        ];
        let mut head = a.hash();
        let entries: Vec<Entry> = events
            .into_iter()
            .enumerate()
            .map(|(i, event)| {
                let e = Entry {
                    seq: i as u64,
                    prev: head,
                    time: t(i as i64),
                    event,
                };
                head = e.hash();
                e
            })
            .collect();
        assert!(matches!(
            verify(&a, &entries),
            Err(TranscriptError::Malformed { seq: 2, .. })
        ));
    }

    #[test]
    fn commands_outside_exception_are_refused() {
        let mut tr = Transcript::new(&genesis());
        tr.append_at(t(0), started()).unwrap();
        let cmd = Event::ExceptionCommand {
            argv: vec!["coldroot".into()],
            exit_status: 0,
        };
        assert!(tr.append_at(t(1), cmd).is_err());
    }

    #[test]
    fn time_cannot_go_backwards() {
        let mut tr = Transcript::new(&genesis());
        tr.append_at(t(5), started()).unwrap();
        assert_eq!(
            tr.append_at(t(4), Event::CeremonyEnded).unwrap_err(),
            TranscriptError::TimeWentBackwards { seq: 1 }
        );
    }

    #[test]
    fn events_must_start_with_ceremony_started() {
        let mut tr = Transcript::new(&genesis());
        assert!(tr.append_at(t(0), Event::CeremonyEnded).is_err());
    }

    #[test]
    fn timestamps_serialize_as_utc() {
        let tr = sample(&genesis());
        let json = serde_json::to_string(&tr.entries()[0]).unwrap();
        assert!(json.contains("\"time\":\"2026-"), "{json}");
        assert!(json.contains("Z\""), "{json}");
    }
}
