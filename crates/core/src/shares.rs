//! Quorum shares of the wrap key.
//!
//! The wrap key is a nonzero P-256 scalar split with Pedersen verifiable
//! secret sharing. The verifier (commitments to the sharing polynomials) is
//! stored on the state disc, which is copied and kept for decades.
//!
//! What this does and does not give you:
//!
//! - The verifier reveals nothing about the key, even to an attacker with
//!   unbounded computing power (hiding is unconditional). The same disc also
//!   carries the keys wrapped under AES-256 with this key, so the disc as a
//!   whole is as strong as AES-256, not information-theoretic. Pedersen only
//!   makes sure the verifier is not a weaker link than those blobs.
//! - Checking a share against the verifier assumes the discrete log problem
//!   is hard on P-256 (binding is computational). An attacker who can solve
//!   it could forge a share that passes the check; the HSM would then fail to
//!   unwrap the keys, so the attack is a denial of service, not a key leak.
//!
//! Shares and verifiers carry a generation number, which a reshare ceremony
//! increments, so a share from a superseded set is reported as such rather
//! than as a mysterious verification failure.
//!
//! Each share is an index, a secret value and a blinding value. Custodians
//! transcribe it as eight lines of hex, each ending in a check byte, so a typo
//! is reported against the line it is on before the Pedersen check runs.
//!
//! Everything here is done directly on P-256 scalars and points rather than
//! through a secret-sharing library, so that the Feldman commitment `g^s`,
//! which would reveal the key to a discrete-log attacker, is never computed,
//! and so that every secret-bearing temporary can be zeroized.

use std::fmt::Write as _;

use p256::{
    EncodedPoint, ProjectivePoint, Scalar,
    elliptic_curve::{
        Field, PrimeField,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;

/// Bytes per transcribed line, excluding its check byte.
const LINE_LEN: usize = 8;
/// Lines per share: the value and blinder, 64 bytes in all.
pub const SHARE_LINES: usize = 2 * KEY_LEN / LINE_LEN;
const _: () = assert!(SHARE_LINES <= u8::MAX as usize);

const LINE_CHECK_DOMAIN: &[u8] = b"coldroot share line v1\0";

/// The second Pedersen generator `h`, as a compressed SEC1 point.
///
/// It was derived once with RFC 9380 hash-to-curve (suite
/// `P256_XMD:SHA-256_SSWU_RO_`) from the message
/// `coldroot pedersen blinder generator` and the domain separation tag
/// `coldroot-v1-P256_XMD:SHA-256_SSWU_RO_`, so nobody knows its discrete
/// log relative to the standard generator. The value is fixed here, rather
/// than recomputed, so that a change in some library's hash-to-curve code can
/// never make existing state discs unverifiable. A test re-derives it.
pub const BLINDER_GENERATOR: [u8; 33] = [
    0x02, 0xba, 0x93, 0xfd, 0xe2, 0xd3, 0x48, 0x25, 0xac, 0xe8, 0xa9, 0x8f, 0xf3, 0x8f, 0xdc, 0x08,
    0x75, 0x4c, 0x20, 0x14, 0x55, 0x75, 0x31, 0x70, 0x81, 0x69, 0x10, 0x2a, 0x18, 0x7d, 0x94, 0x41,
    0xcb,
];

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    #[error("threshold {threshold} must be at least 2 and no more than {limit} shares")]
    BadParameters { threshold: u8, limit: u8 },
    #[error("share index must be between 1 and 255")]
    BadIndex,
    #[error("expected {SHARE_LINES} lines, got {0}")]
    WrongLineCount(usize),
    #[error("line {line}: not 16 hex digits followed by a 2-digit check")]
    MalformedLine { line: usize },
    #[error("line {line}: this is line {found} of the share, check the order")]
    MislabeledLine { line: usize, found: usize },
    #[error("line {line}: check digits do not match, look for a typo on this line")]
    LineCheckFailed { line: usize },
    #[error("verifier is malformed")]
    MalformedVerifier,
    #[error("share disc record is malformed")]
    MalformedRecord,
    #[error("share {0} is not a valid share")]
    Malformed(u8),
    #[error("share {0} does not match the verifier")]
    Unverified(u8),
    #[error("share is from generation {share}, the current generation is {current}")]
    WrongGeneration { share: u32, current: u32 },
    #[error("share {0} was entered twice")]
    Duplicate(u8),
    #[error("need {needed} shares, have {have}")]
    NotEnough { needed: usize, have: usize },
}

fn blinder_generator() -> ProjectivePoint {
    let encoded = EncodedPoint::from_bytes(BLINDER_GENERATOR).expect("constant is SEC1");
    ProjectivePoint::from_encoded_point(&encoded).expect("constant is on the curve")
}

fn scalar(bytes: &[u8; KEY_LEN]) -> Option<Scalar> {
    Scalar::from_repr((*bytes).into()).into()
}

fn nonzero_scalar(bytes: &[u8; KEY_LEN]) -> Option<Scalar> {
    scalar(bytes).filter(|s| !bool::from(s.is_zero()))
}

fn index_scalar(index: u8) -> Scalar {
    Scalar::from(u64::from(index))
}

/// Evaluate the polynomial with the given coefficients (lowest first) at `x`.
fn eval(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |acc, c| acc * x + c)
}

/// Pedersen commitment `g^a · h^b`.
fn commit(a: &Scalar, b: &Scalar) -> ProjectivePoint {
    ProjectivePoint::GENERATOR * a + blinder_generator() * b
}

/// The result of splitting a key: the custodian shares and their verifier.
pub type Split = (Vec<KeyShare>, Verifier);

/// The AES-256 wrap key, held only in RAM during a ceremony.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WrapKey([u8; KEY_LEN]);

impl WrapKey {
    /// Accept `bytes` if they encode a nonzero scalar below the curve order.
    /// Callers sample until this succeeds; rejection is ~2^-32 likely. This
    /// means the wrap key is generated on the ceremony machine and imported
    /// into the HSM, never generated by the HSM.
    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Option<Self> {
        let key = nonzero_scalar(&bytes).map(|_| Self(bytes));
        bytes.zeroize();
        key
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Split into `limit` shares, any `threshold` of which reconstruct the key.
    pub fn split<R: RngCore + CryptoRng>(
        &self,
        generation: u32,
        threshold: u8,
        limit: u8,
        rng: &mut R,
    ) -> Result<Split, ShareError> {
        Ok(self
            .split_with_blinder(generation, threshold, limit, rng)?
            .0)
    }

    /// `split`, also returning the blinder `b_0` of the key's commitment, so
    /// tests can open it.
    fn split_with_blinder<R: RngCore + CryptoRng>(
        &self,
        generation: u32,
        threshold: u8,
        limit: u8,
        rng: &mut R,
    ) -> Result<(Split, Zeroizing<Scalar>), ShareError> {
        Verifier::check_parameters(threshold, limit)?;
        let degree = usize::from(threshold);

        // Secret polynomial a(x) with a(0) = key, blinder polynomial b(x)
        // with b(0) random; shares are (i, a(i), b(i)).
        let mut a = Zeroizing::new(Vec::with_capacity(degree));
        let mut b = Zeroizing::new(Vec::with_capacity(degree));
        a.push(scalar(&self.0).expect("wrap key is a valid scalar"));
        b.push(Scalar::random(&mut *rng));
        for _ in 1..degree {
            a.push(Scalar::random(&mut *rng));
            b.push(Scalar::random(&mut *rng));
        }

        let verifier = Verifier {
            generation,
            threshold,
            limit,
            commitments: a
                .iter()
                .zip(b.iter())
                .map(|(a, b)| Commitment(commit(a, b)))
                .collect(),
        };
        let shares = (1..=limit)
            .map(|index| {
                let x = index_scalar(index);
                let mut value = Zeroizing::new(eval(&a, &x));
                let mut blinder = Zeroizing::new(eval(&b, &x));
                let share = KeyShare {
                    generation,
                    index,
                    value: value.to_repr().into(),
                    blinder: blinder.to_repr().into(),
                };
                value.zeroize();
                blinder.zeroize();
                share
            })
            .collect::<Vec<_>>();
        // Self-check. A share with a zero value or blinder (probability about
        // 2^-255 each) would fail here; the caller then splits again.
        for s in &shares {
            verifier.check(s)?;
        }
        let blinder = Zeroizing::new(b[0]);
        Ok(((shares, verifier), blinder))
    }
}

/// One custodian's share.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct KeyShare {
    generation: u32,
    index: u8,
    value: [u8; KEY_LEN],
    blinder: [u8; KEY_LEN],
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KeyShare(gen {}, #{}, <redacted>)",
            self.generation, self.index
        )
    }
}

fn line_check(generation: u32, index: u8, line: u8, bytes: &[u8]) -> u8 {
    let mut h = Sha256::new();
    h.update(LINE_CHECK_DOMAIN);
    h.update(generation.to_be_bytes());
    h.update([index, line]);
    h.update(bytes);
    h.finalize()[0]
}

/// Split "3: ..." or "3. ..." or "3) ..." into its line number and the rest.
fn split_line_label(text: &str) -> (Option<usize>, &str) {
    let text = text.trim();
    let digits = text.len() - text.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    let rest = &text[digits..];
    if digits == 0 || !rest.starts_with([':', '.', ')']) {
        return (None, text);
    }
    (text[..digits].parse().ok(), &rest[1..])
}

impl KeyShare {
    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn index(&self) -> u8 {
        self.index
    }

    fn body(&self) -> Zeroizing<[u8; 2 * KEY_LEN]> {
        let mut body = Zeroizing::new([0u8; 2 * KEY_LEN]);
        body[..KEY_LEN].copy_from_slice(&self.value);
        body[KEY_LEN..].copy_from_slice(&self.blinder);
        body
    }

    /// The share as custodians transcribe it: numbered lines of four 4-digit
    /// hex groups, each followed by a check byte bound to the generation,
    /// share index and line number. The sheet's heading, which names the
    /// generation and index, is the caller's to print.
    pub fn to_lines(&self) -> Zeroizing<Vec<Zeroizing<String>>> {
        let body = self.body();
        Zeroizing::new(
            body.chunks(LINE_LEN)
                .enumerate()
                .map(|(i, chunk)| {
                    let line = i + 1;
                    let mut out = Zeroizing::new(String::with_capacity(32));
                    write!(out, "{line}:").unwrap();
                    for group in chunk.chunks(2) {
                        write!(out, " {:02x}{:02x}", group[0], group[1]).unwrap();
                    }
                    write!(
                        out,
                        "  {:02x}",
                        line_check(self.generation, self.index, line as u8, chunk)
                    )
                    .unwrap();
                    out
                })
                .collect(),
        )
    }

    /// Parse transcribed lines for share `index` of `generation`. Leading
    /// line numbers and whitespace are optional. Errors name the first line
    /// with a problem.
    pub fn parse(generation: u32, index: u8, lines: &[&str]) -> Result<Self, ShareError> {
        if index == 0 {
            return Err(ShareError::BadIndex);
        }
        if lines.len() != SHARE_LINES {
            return Err(ShareError::WrongLineCount(lines.len()));
        }
        let mut body = Zeroizing::new([0u8; 2 * KEY_LEN]);
        for (i, text) in lines.iter().enumerate() {
            let line = i + 1;
            let (label, text) = split_line_label(text);
            if let Some(found) = label
                && found != line
            {
                return Err(ShareError::MislabeledLine { line, found });
            }
            let digits: Zeroizing<String> =
                Zeroizing::new(text.chars().filter(|c| !c.is_whitespace()).collect());
            let mut raw = Zeroizing::new([0u8; LINE_LEN + 1]);
            hex::decode_to_slice(digits.as_bytes(), &mut raw[..])
                .map_err(|_| ShareError::MalformedLine { line })?;
            let (bytes, check) = raw.split_at(LINE_LEN);
            if line_check(generation, index, line as u8, bytes) != check[0] {
                return Err(ShareError::LineCheckFailed { line });
            }
            body[i * LINE_LEN..line * LINE_LEN].copy_from_slice(bytes);
        }
        let mut share = Self {
            generation,
            index,
            value: [0; KEY_LEN],
            blinder: [0; KEY_LEN],
        };
        share.value.copy_from_slice(&body[..KEY_LEN]);
        share.blinder.copy_from_slice(&body[KEY_LEN..]);
        Ok(share)
    }

    /// The share as written to a custodian's share disc.
    pub fn to_json(&self) -> Zeroizing<String> {
        let record = ShareRecord {
            generation: self.generation,
            index: self.index,
            value: self.value,
            blinder: self.blinder,
        };
        Zeroizing::new(serde_json::to_string(&record).expect("record serializes"))
    }

    /// Read a share from a share disc.
    pub fn from_json(json: &str) -> Result<Self, ShareError> {
        let record: Zeroizing<ShareRecord> =
            Zeroizing::new(serde_json::from_str(json).map_err(|_| ShareError::MalformedRecord)?);
        if record.index == 0 {
            return Err(ShareError::BadIndex);
        }
        Ok(Self {
            generation: record.generation,
            index: record.index,
            value: record.value,
            blinder: record.blinder,
        })
    }

    fn scalars(&self) -> Result<(Zeroizing<Scalar>, Zeroizing<Scalar>), ShareError> {
        let malformed = || ShareError::Malformed(self.index);
        let value = nonzero_scalar(&self.value).ok_or_else(malformed)?;
        let blinder = nonzero_scalar(&self.blinder).ok_or_else(malformed)?;
        Ok((Zeroizing::new(value), Zeroizing::new(blinder)))
    }
}

/// On-disc form of a share.
#[derive(Serialize, Deserialize, Zeroize)]
struct ShareRecord {
    generation: u32,
    index: u8,
    #[serde(with = "hex::serde")]
    value: [u8; KEY_LEN],
    #[serde(with = "hex::serde")]
    blinder: [u8; KEY_LEN],
}

/// A curve point serialized as compressed SEC1 hex.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Commitment(ProjectivePoint);

impl Serialize for Commitment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0.to_encoded_point(true)))
    }
}

impl<'de> Deserialize<'de> for Commitment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode(text).map_err(serde::de::Error::custom)?;
        let encoded = EncodedPoint::from_bytes(bytes).map_err(serde::de::Error::custom)?;
        Option::from(ProjectivePoint::from_encoded_point(&encoded))
            .map(Commitment)
            .ok_or_else(|| serde::de::Error::custom("not a point on P-256"))
    }
}

/// Public Pedersen commitments, stored on the state disc.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verifier {
    pub generation: u32,
    pub threshold: u8,
    pub limit: u8,
    /// One commitment `g^a_k · h^b_k` per polynomial coefficient, lowest
    /// first. The first commits to the key itself.
    commitments: Vec<Commitment>,
}

impl Verifier {
    fn check_parameters(threshold: u8, limit: u8) -> Result<(), ShareError> {
        if threshold < 2 || threshold > limit {
            return Err(ShareError::BadParameters { threshold, limit });
        }
        Ok(())
    }

    /// Reject a verifier whose parameters a disc editor could have changed.
    fn check_well_formed(&self) -> Result<(), ShareError> {
        Self::check_parameters(self.threshold, self.limit)
            .map_err(|_| ShareError::MalformedVerifier)?;
        if self.commitments.len() != usize::from(self.threshold) {
            return Err(ShareError::MalformedVerifier);
        }
        Ok(())
    }

    /// Check `share` opens to the commitments: `g^v · h^b == Π C_k^(i^k)`.
    pub fn check(&self, share: &KeyShare) -> Result<(), ShareError> {
        self.check_well_formed()?;
        if share.generation != self.generation {
            return Err(ShareError::WrongGeneration {
                share: share.generation,
                current: self.generation,
            });
        }
        let index = share.index();
        if index == 0 || index > self.limit {
            return Err(ShareError::Unverified(index));
        }
        let (value, blinder) = share.scalars()?;
        let x = index_scalar(index);
        let expected = self
            .commitments
            .iter()
            .rev()
            .fold(ProjectivePoint::IDENTITY, |acc, c| acc * x + c.0);
        if commit(&value, &blinder) == expected {
            Ok(())
        } else {
            Err(ShareError::Unverified(index))
        }
    }

    /// Reconstruct the wrap key from verified shares.
    pub fn combine(&self, shares: &[KeyShare]) -> Result<WrapKey, ShareError> {
        self.check_well_formed()?;
        if shares.len() < usize::from(self.threshold) {
            return Err(ShareError::NotEnough {
                needed: usize::from(self.threshold),
                have: shares.len(),
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut points = Zeroizing::new(Vec::with_capacity(shares.len()));
        for s in shares {
            self.check(s)?;
            if !seen.insert(s.index()) {
                return Err(ShareError::Duplicate(s.index()));
            }
            points.push((index_scalar(s.index()), *s.scalars()?.0));
        }
        // Lagrange interpolation at x = 0.
        let mut secret = Zeroizing::new(Scalar::ZERO);
        for (i, (x_i, y_i)) in points.iter().enumerate() {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for (j, (x_j, _)) in points.iter().enumerate() {
                if i != j {
                    num *= x_j;
                    den *= x_j - x_i;
                }
            }
            let coefficient = num * den.invert().expect("distinct indices");
            *secret += y_i * &coefficient;
        }
        let mut bytes: [u8; KEY_LEN] = secret.to_repr().into();
        let key = WrapKey::from_bytes(bytes);
        bytes.zeroize();
        key.ok_or(ShareError::Unverified(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        NistP256,
        elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest},
    };
    use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
    use rand_core::OsRng;

    fn key() -> WrapKey {
        loop {
            let mut b = [0u8; KEY_LEN];
            OsRng.fill_bytes(&mut b);
            if let Some(k) = WrapKey::from_bytes(b) {
                return k;
            }
        }
    }

    /// A key and shares from a fixed seed, for tests whose outcome would
    /// otherwise depend on a 1-in-256 check byte collision, and for the
    /// known-answer test.
    fn fixed_split() -> (WrapKey, Vec<KeyShare>, Verifier) {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let k = loop {
            let mut b = [0u8; KEY_LEN];
            rng.fill_bytes(&mut b);
            if let Some(k) = WrapKey::from_bytes(b) {
                break k;
            }
        };
        let (shares, verifier) = k.split(1, 3, 5, &mut rng).unwrap();
        (k, shares, verifier)
    }

    fn lines(share: &KeyShare) -> Vec<String> {
        share.to_lines().iter().map(|l| l.to_string()).collect()
    }

    fn parse(index: u8, lines: &[String]) -> Result<KeyShare, ShareError> {
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        KeyShare::parse(1, index, &refs)
    }

    #[test]
    fn blinder_generator_matches_its_derivation() {
        let derived = NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
            &[b"coldroot pedersen blinder generator"],
            &[b"coldroot-v1-P256_XMD:SHA-256_SSWU_RO_"],
        )
        .unwrap();
        assert_eq!(derived, blinder_generator());
        assert_ne!(blinder_generator(), ProjectivePoint::GENERATOR);
    }

    #[test]
    fn line_check_known_answer() {
        assert_eq!(line_check(1, 1, 1, &[0; 8]), 0x8b);
        assert_eq!(line_check(1, 2, 1, &[0; 8]), 0xd3);
        assert_eq!(line_check(1, 1, 2, &[0; 8]), 0xcf);
        assert_eq!(line_check(2, 1, 1, &[0; 8]), 0x24);
    }

    /// Byte-for-byte vectors from a fixed seed. If this test fails after a
    /// dependency or code change, shares and verifiers on existing state
    /// discs are affected; the change needs a format version, not a new
    /// vector.
    #[test]
    fn known_answer_vectors() {
        let (k, shares, verifier) = fixed_split();
        assert_eq!(
            hex::encode(k.as_bytes()),
            "9a3744504560639ec670b7a17d492b273e077b0a96bef58ba7760779e544546e"
        );
        assert_eq!(
            lines(&shares[0]),
            [
                "1: 1912 bb74 50af 456b  29",
                "2: 9244 0c8c 897a 5704  fe",
                "3: e107 953e ca37 3526  16",
                "4: 6bd7 6a1a 2880 f651  1e",
                "5: 74f5 a2c7 46a5 5ede  41",
                "6: 1aed 14bb 3237 da97  ea",
                "7: 3e74 3aaf 5386 2a57  01",
                "8: 488c dd70 44a0 9a65  64",
            ]
        );
        assert_eq!(
            serde_json::to_string(&verifier).unwrap(),
            concat!(
                r#"{"generation":1,"threshold":3,"limit":5,"commitments":["#,
                r#""030975df5aca9434b9f57001547453124c851c29c709e4b7b12a038076d0f5127d","#,
                r#""036d48625e7953ae7aead91003d5be50f97594100225ceb2793ae8bdb3956b7cf4","#,
                r#""021a53b26de5b37dad0c53a8f9d4e3e5f076c45c7fd9cbc8b7f68df67df85ddf27"]}"#
            )
        );
    }

    #[test]
    fn any_threshold_subset_reconstructs() {
        let k = key();
        let (shares, verifier) = k.split(1, 3, 5, &mut OsRng).unwrap();
        for subset in [[0, 1, 2], [0, 2, 4], [2, 3, 4], [4, 1, 3]] {
            let picked: Vec<_> = subset.iter().map(|&i| shares[i].clone()).collect();
            assert_eq!(verifier.combine(&picked).unwrap().as_bytes(), k.as_bytes());
        }
        // More than the threshold also works.
        assert_eq!(verifier.combine(&shares).unwrap().as_bytes(), k.as_bytes());
    }

    #[test]
    fn edge_parameters_work() {
        let k = key();
        let (shares, verifier) = k.split(1, 2, 2, &mut OsRng).unwrap();
        assert_eq!(verifier.combine(&shares).unwrap().as_bytes(), k.as_bytes());
        let (shares, verifier) = k.split(1, 3, 255, &mut OsRng).unwrap();
        assert_eq!(shares.last().unwrap().index(), 255);
        let picked = vec![shares[0].clone(), shares[127].clone(), shares[254].clone()];
        assert_eq!(verifier.combine(&picked).unwrap().as_bytes(), k.as_bytes());
    }

    #[test]
    fn bad_parameters_are_refused() {
        let k = key();
        assert!(k.split(1, 1, 5, &mut OsRng).is_err());
        assert!(k.split(1, 6, 5, &mut OsRng).is_err());
    }

    #[test]
    fn below_threshold_is_refused() {
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        assert_eq!(
            verifier.combine(&shares[..2]).err(),
            Some(ShareError::NotEnough { needed: 3, have: 2 })
        );
    }

    #[test]
    fn key_commitment_opens_with_its_blinder() {
        let k = key();
        let ((_, verifier), blinder) = k.split_with_blinder(1, 3, 5, &mut OsRng).unwrap();
        let s = scalar(k.as_bytes()).unwrap();
        assert_eq!(verifier.commitments[0].0, commit(&s, &blinder));
        // And the blinder is doing its job: no commitment equals g^s.
        let g_s = ProjectivePoint::GENERATOR * s;
        assert!(verifier.commitments.iter().all(|c| c.0 != g_s));
    }

    #[test]
    fn splits_of_the_same_key_differ() {
        let k = key();
        let (shares_a, verifier_a) = k.split(1, 3, 5, &mut OsRng).unwrap();
        let (shares_b, verifier_b) = k.split(1, 3, 5, &mut OsRng).unwrap();
        assert_ne!(verifier_a.commitments, verifier_b.commitments);
        assert_ne!(shares_a[0], shares_b[0]);
        // Shares from one split don't verify against the other.
        assert_eq!(
            verifier_a.check(&shares_b[0]),
            Err(ShareError::Unverified(1))
        );
    }

    #[test]
    fn lines_round_trip() {
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let typed = lines(&shares[3]);
        assert_eq!(typed.len(), SHARE_LINES);
        let parsed = parse(4, &typed).unwrap();
        assert_eq!(parsed, shares[3]);
        verifier.check(&parsed).unwrap();
    }

    #[test]
    fn line_labels_and_spacing_are_optional() {
        let (shares, _) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let bare: Vec<String> = lines(&shares[0])
            .iter()
            .map(|l| l.split_once(": ").unwrap().1.replace(' ', ""))
            .collect();
        assert_eq!(parse(1, &bare).unwrap(), shares[0]);
        let dotted: Vec<String> = lines(&shares[0])
            .iter()
            .map(|l| l.replacen(':', ".", 1))
            .collect();
        assert_eq!(parse(1, &dotted).unwrap(), shares[0]);
    }

    #[test]
    fn disc_record_round_trips() {
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let json = shares[2].to_json();
        assert!(json.contains(r#""generation":1"#) && json.contains(r#""index":3"#));
        let back = KeyShare::from_json(&json).unwrap();
        assert_eq!(back, shares[2]);
        verifier.check(&back).unwrap();
        assert_eq!(
            KeyShare::from_json("{}").err(),
            Some(ShareError::MalformedRecord)
        );
    }

    #[test]
    fn typo_is_reported_on_its_line() {
        let (_, shares, _) = fixed_split();
        let typed = lines(&shares[1]);
        // Try every other digit in one position of line 6. A single check
        // byte misses 1 in 256 typos, so allow at most one of the fifteen to
        // slip through; every detected one must name line 6.
        let pos = "6: ".len();
        let original = typed[5].as_bytes()[pos];
        let mut missed = 0;
        for digit in b"0123456789abcdef".iter().filter(|&&d| d != original) {
            let mut attempt = typed.clone();
            attempt[5].replace_range(pos..pos + 1, std::str::from_utf8(&[*digit]).unwrap());
            match parse(2, &attempt) {
                Err(ShareError::LineCheckFailed { line: 6 }) => {}
                Ok(_) => missed += 1,
                other => panic!("unexpected result {other:?}"),
            }
        }
        assert!(missed <= 1, "{missed} typos went undetected");
    }

    #[test]
    fn swapped_lines_are_caught() {
        let (_, shares, _) = fixed_split();
        let mut typed = lines(&shares[0]);
        typed.swap(2, 3);
        // With labels, the label mismatch is reported.
        assert_eq!(
            parse(1, &typed).err(),
            Some(ShareError::MislabeledLine { line: 3, found: 4 })
        );
        // Without labels, the check byte catches it.
        let bare: Vec<String> = typed
            .iter()
            .map(|l| l.split_once(": ").unwrap().1.to_string())
            .collect();
        assert_eq!(
            parse(1, &bare).err(),
            Some(ShareError::LineCheckFailed { line: 3 })
        );
    }

    #[test]
    fn wrong_index_is_caught() {
        let (_, shares, _) = fixed_split();
        assert_eq!(
            parse(3, &lines(&shares[1])).err(),
            Some(ShareError::LineCheckFailed { line: 1 })
        );
    }

    #[test]
    fn malformed_input_is_refused() {
        let (_, shares, _) = fixed_split();
        let typed = lines(&shares[0]);
        assert_eq!(parse(0, &typed).err(), Some(ShareError::BadIndex));
        assert_eq!(
            parse(1, &typed[..7]).err(),
            Some(ShareError::WrongLineCount(7))
        );
        let mut bad = typed.clone();
        bad[4].push('0');
        assert_eq!(
            parse(1, &bad).err(),
            Some(ShareError::MalformedLine { line: 5 })
        );
    }

    #[test]
    fn share_with_valid_line_checks_but_wrong_value_is_unverified() {
        // Someone who recomputes the line checks still can't pass the verifier.
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let mut forged = shares[2].clone();
        forged.value[KEY_LEN - 1] ^= 1;
        assert_eq!(verifier.check(&forged), Err(ShareError::Unverified(3)));
    }

    #[test]
    fn zero_share_values_are_refused() {
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let mut zero = shares[0].clone();
        zero.value = [0; KEY_LEN];
        assert_eq!(verifier.check(&zero), Err(ShareError::Malformed(1)));
    }

    #[test]
    fn wrong_generation_is_reported() {
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let mut old = shares[0].clone();
        old.generation = 0;
        assert_eq!(
            verifier.check(&old),
            Err(ShareError::WrongGeneration {
                share: 0,
                current: 1
            })
        );
        // The paper form also differs: lines from generation 1 don't parse as
        // generation 2.
        assert_eq!(
            KeyShare::parse(
                2,
                1,
                &lines(&shares[0])
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            )
            .err(),
            Some(ShareError::LineCheckFailed { line: 1 })
        );
    }

    #[test]
    fn index_outside_limit_is_refused() {
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let mut share = shares[0].clone();
        share.index = 6;
        assert_eq!(verifier.check(&share), Err(ShareError::Unverified(6)));
    }

    #[test]
    fn duplicate_share_is_refused() {
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let picked = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert_eq!(
            verifier.combine(&picked).err(),
            Some(ShareError::Duplicate(1))
        );
    }

    #[test]
    fn verifier_round_trips_through_json() {
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let json = serde_json::to_string(&verifier).unwrap();
        let back: Verifier = serde_json::from_str(&json).unwrap();
        back.check(&shares[4]).unwrap();
    }

    #[test]
    fn tampered_verifier_parameters_are_refused() {
        let (shares, verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        let mut json: serde_json::Value = serde_json::to_value(&verifier).unwrap();

        json["threshold"] = 1.into();
        let tampered: Verifier = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            tampered.check(&shares[0]),
            Err(ShareError::MalformedVerifier)
        );
        assert_eq!(
            tampered.combine(&shares[..1]).err(),
            Some(ShareError::MalformedVerifier)
        );

        json["threshold"] = 3.into();
        json["limit"] = 2.into();
        let tampered: Verifier = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            tampered.check(&shares[0]),
            Err(ShareError::MalformedVerifier)
        );

        json["limit"] = 5.into();
        json["commitments"].as_array_mut().unwrap().pop();
        let tampered: Verifier = serde_json::from_value(json).unwrap();
        assert_eq!(
            tampered.check(&shares[0]),
            Err(ShareError::MalformedVerifier)
        );
    }

    #[test]
    fn tampered_commitment_is_detected() {
        let (shares, mut verifier) = key().split(1, 3, 5, &mut OsRng).unwrap();
        verifier.commitments[0] = Commitment(ProjectivePoint::GENERATOR * Scalar::from(7u64));
        assert_eq!(verifier.check(&shares[0]), Err(ShareError::Unverified(1)));
    }

    #[test]
    fn invalid_point_in_json_is_refused() {
        let json = r#"{"generation":1,"threshold":2,"limit":2,"commitments":["02ff","0200000000000000000000000000000000000000000000000000000000000000000000"]}"#;
        assert!(serde_json::from_str::<Verifier>(json).is_err());
    }
}
