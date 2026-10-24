//! Quorum shares of the wrap key.
//!
//! The wrap key is a nonzero P-256 scalar split with Pedersen verifiable
//! secret sharing. The verifier (commitments to the sharing polynomials) is
//! stored on the state disc. It lets anyone check a single share without
//! learning anything about the key, even with unbounded computing power,
//! which matters because state discs are copied and kept for decades.
//!
//! Each share is an index, a secret value and a blinding value. Custodians
//! transcribe it as eight lines of hex, each ending in a check byte, so a typo
//! is reported against the line it is on before the Pedersen check runs.

use p256::{
    NistP256, NonZeroScalar, ProjectivePoint, Scalar,
    elliptic_curve::{
        PrimeField,
        hash2curve::{ExpandMsgXmd, GroupDigest},
    },
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vsss_rs::{
    DefaultShare, IdentifierPrimeField, PedersenResult, PedersenVerifierSet, ReadableShareSet,
    Share as _, ShareVerifierGroup, pedersen,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;

/// Bytes per transcribed line, excluding its check byte.
const LINE_LEN: usize = 8;
/// Lines per share: the value and blinder, 64 bytes in all.
pub const SHARE_LINES: usize = 2 * KEY_LEN / LINE_LEN;

const LINE_CHECK_DOMAIN: &[u8] = b"coldroot share line v1";
const BLINDER_GENERATOR_MSG: &[u8] = b"coldroot pedersen blinder generator";
const BLINDER_GENERATOR_DST: &[u8] = b"coldroot-v1-P256_XMD:SHA-256_SSWU_RO_";

type RawShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
type RawVerifier = ShareVerifierGroup<ProjectivePoint>;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    #[error("threshold {threshold} must be at least 2 and no more than {limit} shares")]
    BadParameters { threshold: usize, limit: usize },
    #[error("share index must be between 1 and 255")]
    BadIndex,
    #[error("expected {SHARE_LINES} lines, got {0}")]
    WrongLineCount(usize),
    #[error("line {line}: not 16 hex digits followed by a 2-digit check")]
    MalformedLine { line: usize },
    #[error("line {line}: check digits do not match, look for a typo on this line")]
    LineCheckFailed { line: usize },
    #[error("share {0} is not a valid share")]
    Malformed(u8),
    #[error("share {0} does not match the verifier")]
    Unverified(u8),
    #[error("share {0} was entered twice")]
    Duplicate(u8),
    #[error("need {needed} shares, have {have}")]
    NotEnough { needed: usize, have: usize },
    #[error("verifier was not made with coldroot's generators")]
    ForeignVerifier,
    #[error("secret sharing failed: {0}")]
    Vsss(String),
}

/// Second Pedersen generator, derived by hash-to-curve so that nobody knows
/// its discrete log relative to the standard generator.
fn blinder_generator() -> ProjectivePoint {
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(
        &[BLINDER_GENERATOR_MSG],
        &[BLINDER_GENERATOR_DST],
    )
    .expect("hash-to-curve with fixed inputs")
}

fn scalar(bytes: &[u8; KEY_LEN]) -> Option<Scalar> {
    Scalar::from_repr((*bytes).into()).into()
}

/// The AES-256 wrap key, held only in RAM during a ceremony.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WrapKey([u8; KEY_LEN]);

impl WrapKey {
    /// Accept `bytes` if they encode a nonzero scalar below the curve order.
    /// Callers sample until this succeeds; rejection is ~2^-32 likely.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Option<Self> {
        let scalar = Option::<NonZeroScalar>::from(NonZeroScalar::from_repr(bytes.into()))?;
        Some(Self(scalar.to_repr().into()))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Split into `limit` shares, any `threshold` of which reconstruct the key.
    pub fn split<R: RngCore + CryptoRng>(
        &self,
        threshold: usize,
        limit: usize,
        rng: &mut R,
    ) -> Result<(Vec<KeyShare>, Verifier), ShareError> {
        if threshold < 2 || threshold > limit || limit > u8::MAX as usize {
            return Err(ShareError::BadParameters { threshold, limit });
        }
        let secret = IdentifierPrimeField(scalar(&self.0).unwrap());
        let result = pedersen::split_secret::<RawShare, RawVerifier>(
            threshold,
            limit,
            &secret,
            None,
            Some(ProjectivePoint::GENERATOR.into()),
            Some(blinder_generator().into()),
            rng,
        )
        .map_err(|e| ShareError::Vsss(e.to_string()))?;

        let verifier = Verifier {
            threshold,
            limit,
            commitments: result.pedersen_verifier_set().clone(),
        };
        let shares = result
            .secret_shares()
            .iter()
            .zip(result.blinder_shares().iter())
            .map(|(s, b)| KeyShare::from_raw(s, b))
            .collect::<Vec<_>>();
        for s in &shares {
            verifier.check(s)?;
        }
        Ok((shares, verifier))
    }
}

/// One custodian's share.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct KeyShare {
    index: u8,
    value: [u8; KEY_LEN],
    blinder: [u8; KEY_LEN],
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyShare({}, <redacted>)", self.index)
    }
}

fn line_check(index: u8, line: usize, bytes: &[u8]) -> u8 {
    let mut h = Sha256::new();
    h.update(LINE_CHECK_DOMAIN);
    h.update([index, line as u8]);
    h.update(bytes);
    h.finalize()[0]
}

impl KeyShare {
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
    /// hex groups, each followed by a check byte bound to the share index and
    /// line number.
    pub fn to_lines(&self) -> Zeroizing<Vec<String>> {
        let body = self.body();
        Zeroizing::new(
            body.chunks(LINE_LEN)
                .enumerate()
                .map(|(i, chunk)| {
                    let line = i + 1;
                    let hex = hex::encode(chunk);
                    let groups: Vec<&str> = (0..4).map(|g| &hex[g * 4..g * 4 + 4]).collect();
                    let check = line_check(self.index, line, chunk);
                    format!("{line}: {}  {check:02x}", groups.join(" "))
                })
                .collect(),
        )
    }

    /// Parse transcribed lines for share `index`. Leading line numbers and
    /// whitespace are optional. Errors name the first line with a problem.
    pub fn parse(index: u8, lines: &[&str]) -> Result<Self, ShareError> {
        if index == 0 {
            return Err(ShareError::BadIndex);
        }
        if lines.len() != SHARE_LINES {
            return Err(ShareError::WrongLineCount(lines.len()));
        }
        let mut body = Zeroizing::new([0u8; 2 * KEY_LEN]);
        for (i, text) in lines.iter().enumerate() {
            let line = i + 1;
            let text = text
                .trim()
                .strip_prefix(&format!("{line}:"))
                .unwrap_or(text);
            let digits: Zeroizing<String> =
                Zeroizing::new(text.chars().filter(|c| !c.is_whitespace()).collect());
            let mut raw = Zeroizing::new([0u8; LINE_LEN + 1]);
            hex::decode_to_slice(digits.as_bytes(), &mut raw[..])
                .map_err(|_| ShareError::MalformedLine { line })?;
            let (bytes, check) = raw.split_at(LINE_LEN);
            if line_check(index, line, bytes) != check[0] {
                return Err(ShareError::LineCheckFailed { line });
            }
            body[i * LINE_LEN..line * LINE_LEN].copy_from_slice(bytes);
        }
        let mut share = Self {
            index,
            value: [0; KEY_LEN],
            blinder: [0; KEY_LEN],
        };
        share.value.copy_from_slice(&body[..KEY_LEN]);
        share.blinder.copy_from_slice(&body[KEY_LEN..]);
        Ok(share)
    }

    fn from_raw(secret: &RawShare, blinder: &RawShare) -> Self {
        let id = secret.identifier.0.to_repr();
        Self {
            index: id[KEY_LEN - 1],
            value: secret.value.0.to_repr().into(),
            blinder: blinder.value.0.to_repr().into(),
        }
    }

    fn to_raw(&self) -> Result<(RawShare, RawShare), ShareError> {
        let malformed = || ShareError::Malformed(self.index);
        let mut id = [0u8; KEY_LEN];
        id[KEY_LEN - 1] = self.index;
        let id = IdentifierPrimeField(scalar(&id).ok_or_else(malformed)?);
        let value = IdentifierPrimeField(scalar(&self.value).ok_or_else(malformed)?);
        let blinder = IdentifierPrimeField(scalar(&self.blinder).ok_or_else(malformed)?);
        Ok((
            RawShare::with_identifier_and_value(id, value),
            RawShare::with_identifier_and_value(id, blinder),
        ))
    }
}

/// Public Pedersen commitments, stored on the state disc.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verifier {
    pub threshold: usize,
    pub limit: usize,
    /// The secret generator, the blinder generator, then one commitment per
    /// polynomial coefficient.
    commitments: Vec<RawVerifier>,
}

impl Verifier {
    pub fn check(&self, share: &KeyShare) -> Result<(), ShareError> {
        let set = &self.commitments;
        if self.commitments.len() != self.threshold + 2
            || PedersenVerifierSet::<RawShare, RawVerifier>::secret_generator(set).0
                != ProjectivePoint::GENERATOR
            || PedersenVerifierSet::<RawShare, RawVerifier>::blinder_generator(set).0
                != blinder_generator()
        {
            return Err(ShareError::ForeignVerifier);
        }
        let index = share.index();
        if index == 0 || index as usize > self.limit {
            return Err(ShareError::Unverified(index));
        }
        let (secret, blinder) = share.to_raw()?;
        set.verify_share_and_blinder(&secret, &blinder)
            .map_err(|_| ShareError::Unverified(index))
    }

    /// Reconstruct the wrap key from verified shares.
    pub fn combine(&self, shares: &[KeyShare]) -> Result<WrapKey, ShareError> {
        if shares.len() < self.threshold {
            return Err(ShareError::NotEnough {
                needed: self.threshold,
                have: shares.len(),
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut raw = Vec::with_capacity(shares.len());
        for s in shares {
            self.check(s)?;
            if !seen.insert(s.index()) {
                return Err(ShareError::Duplicate(s.index()));
            }
            raw.push(s.to_raw()?.0);
        }
        let secret = raw.combine().map_err(|e| ShareError::Vsss(e.to_string()))?;
        let bytes: [u8; KEY_LEN] = secret.0.to_repr().into();
        WrapKey::from_bytes(bytes).ok_or(ShareError::Vsss("reconstructed zero key".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// Shares from a fixed seed, for tests whose outcome would otherwise
    /// depend on a 1-in-256 check byte collision.
    fn fixed_split() -> Vec<KeyShare> {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let k = loop {
            let mut b = [0u8; KEY_LEN];
            rng.fill_bytes(&mut b);
            if let Some(k) = WrapKey::from_bytes(b) {
                break k;
            }
        };
        k.split(3, 5, &mut rng).unwrap().0
    }

    fn lines(share: &KeyShare) -> Vec<String> {
        share.to_lines().to_vec()
    }

    fn parse(index: u8, lines: &[String]) -> Result<KeyShare, ShareError> {
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        KeyShare::parse(index, &refs)
    }

    #[test]
    fn any_threshold_subset_reconstructs() {
        let k = key();
        let (shares, verifier) = k.split(3, 5, &mut OsRng).unwrap();
        for subset in [[0, 1, 2], [0, 2, 4], [2, 3, 4], [4, 1, 3]] {
            let picked: Vec<_> = subset.iter().map(|&i| shares[i].clone()).collect();
            assert_eq!(verifier.combine(&picked).unwrap().as_bytes(), k.as_bytes());
        }
    }

    #[test]
    fn below_threshold_is_refused() {
        let (shares, verifier) = key().split(3, 5, &mut OsRng).unwrap();
        assert_eq!(
            verifier.combine(&shares[..2]).err(),
            Some(ShareError::NotEnough { needed: 3, have: 2 })
        );
    }

    #[test]
    fn verifier_does_not_contain_the_feldman_commitment() {
        // The Feldman commitment g^s would reveal the key to anyone who can
        // take discrete logs; only blinded commitments may be stored.
        let k = key();
        let (_, verifier) = k.split(3, 5, &mut OsRng).unwrap();
        let g_s = ProjectivePoint::GENERATOR * scalar(k.as_bytes()).unwrap();
        assert!(verifier.commitments.iter().all(|c| c.0 != g_s));
    }

    #[test]
    fn lines_round_trip() {
        let (shares, verifier) = key().split(3, 5, &mut OsRng).unwrap();
        let typed = lines(&shares[3]);
        assert_eq!(typed.len(), SHARE_LINES);
        let parsed = parse(4, &typed).unwrap();
        assert_eq!(parsed, shares[3]);
        verifier.check(&parsed).unwrap();
    }

    #[test]
    fn line_numbers_and_spacing_are_optional() {
        let (shares, _) = key().split(3, 5, &mut OsRng).unwrap();
        let bare: Vec<String> = lines(&shares[0])
            .iter()
            .map(|l| l.split_once(": ").unwrap().1.replace(' ', ""))
            .collect();
        assert_eq!(parse(1, &bare).unwrap(), shares[0]);
    }

    #[test]
    fn typo_is_reported_on_its_line() {
        let shares = fixed_split();
        let mut typed = lines(&shares[1]);
        // Change one digit in the first group of line 6.
        let pos = "6: ".len();
        let c = typed[5].as_bytes()[pos];
        let replacement = if c == b'0' { "1" } else { "0" };
        typed[5].replace_range(pos..pos + 1, replacement);
        assert_eq!(
            parse(2, &typed).err(),
            Some(ShareError::LineCheckFailed { line: 6 })
        );
    }

    #[test]
    fn swapped_lines_are_caught() {
        let shares = fixed_split();
        let mut typed = lines(&shares[0]);
        typed.swap(2, 3);
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
        let shares = fixed_split();
        assert_eq!(
            parse(3, &lines(&shares[1])).err(),
            Some(ShareError::LineCheckFailed { line: 1 })
        );
    }

    #[test]
    fn share_with_valid_line_checks_but_wrong_value_is_unverified() {
        // Someone who recomputes the line checks still can't pass the verifier.
        let (shares, verifier) = key().split(3, 5, &mut OsRng).unwrap();
        let mut forged = shares[2].clone();
        forged.value[KEY_LEN - 1] ^= 1;
        assert_eq!(verifier.check(&forged), Err(ShareError::Unverified(3)));
    }

    #[test]
    fn duplicate_share_is_refused() {
        let (shares, verifier) = key().split(3, 5, &mut OsRng).unwrap();
        let picked = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert_eq!(
            verifier.combine(&picked).err(),
            Some(ShareError::Duplicate(1))
        );
    }

    #[test]
    fn verifier_round_trips_through_json() {
        let (shares, verifier) = key().split(3, 5, &mut OsRng).unwrap();
        let json = serde_json::to_string(&verifier).unwrap();
        let back: Verifier = serde_json::from_str(&json).unwrap();
        back.check(&shares[4]).unwrap();
    }

    #[test]
    fn verifier_with_other_generators_is_refused() {
        let (shares, mut verifier) = key().split(3, 5, &mut OsRng).unwrap();
        verifier.commitments[1] = (ProjectivePoint::GENERATOR * Scalar::from(7u64)).into();
        assert_eq!(verifier.check(&shares[0]), Err(ShareError::ForeignVerifier));
    }
}
