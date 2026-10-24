//! Quorum shares of the wrap key.
//!
//! The wrap key is a nonzero P-256 scalar so it can be split with Feldman
//! verifiable secret sharing: alongside the shares we publish a verifier
//! (commitments to the sharing polynomial) on the state disc. Anyone can check
//! a single share against the verifier without learning the key, which catches
//! transcription errors at the moment a custodian types their share in.

use p256::{NonZeroScalar, ProjectivePoint, Scalar, elliptic_curve::PrimeField};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use vsss_rs::{
    DefaultShare, FeldmanVerifierSet, IdentifierPrimeField, ReadableShareSet, Share as _,
    ShareVerifierGroup, feldman,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;

type RawShare = DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
type RawVerifier = ShareVerifierGroup<ProjectivePoint>;

#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    #[error("threshold {threshold} must be at least 2 and no more than {limit} shares")]
    BadParameters { threshold: usize, limit: usize },
    #[error("share is not valid hex of the expected length")]
    Malformed,
    #[error("share {0} does not match the verifier")]
    Unverified(u8),
    #[error("share {0} was entered twice")]
    Duplicate(u8),
    #[error("need {needed} shares, have {have}")]
    NotEnough { needed: usize, have: usize },
    #[error("secret sharing failed: {0}")]
    Vsss(String),
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

    fn scalar(&self) -> Scalar {
        Scalar::from_repr(self.0.into()).unwrap()
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
        let secret = IdentifierPrimeField(self.scalar());
        let (shares, verifier) =
            feldman::split_secret::<RawShare, RawVerifier>(threshold, limit, &secret, None, rng)
                .map_err(|e| ShareError::Vsss(e.to_string()))?;
        let verifier = Verifier {
            threshold,
            limit,
            commitments: verifier,
        };
        let shares = shares.iter().map(KeyShare::from_raw).collect::<Vec<_>>();
        for s in &shares {
            verifier.check(s)?;
        }
        Ok((shares, verifier))
    }
}

/// One custodian's share: a one-byte index followed by a 32-byte value.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct KeyShare([u8; KEY_LEN + 1]);

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyShare({}, <redacted>)", self.index())
    }
}

impl KeyShare {
    pub fn index(&self) -> u8 {
        self.0[0]
    }

    /// Hex in groups of four characters, as printed for a custodian.
    pub fn to_display(&self) -> Zeroizing<String> {
        let hex = Zeroizing::new(hex::encode(self.0));
        let groups: Vec<&str> = hex
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        Zeroizing::new(groups.join(" "))
    }

    /// Parse what a custodian typed; whitespace is ignored.
    pub fn parse(input: &str) -> Result<Self, ShareError> {
        let compact: Zeroizing<String> =
            Zeroizing::new(input.chars().filter(|c| !c.is_whitespace()).collect());
        let mut bytes = [0u8; KEY_LEN + 1];
        hex::decode_to_slice(compact.as_bytes(), &mut bytes).map_err(|_| ShareError::Malformed)?;
        if bytes[0] == 0 {
            return Err(ShareError::Malformed);
        }
        Ok(Self(bytes))
    }

    fn from_raw(raw: &RawShare) -> Self {
        let mut bytes = [0u8; KEY_LEN + 1];
        let id = raw.identifier.0.to_repr();
        bytes[0] = id[KEY_LEN - 1];
        bytes[1..].copy_from_slice(&raw.value.0.to_repr());
        Self(bytes)
    }

    fn to_raw(&self) -> Result<RawShare, ShareError> {
        let mut id = [0u8; KEY_LEN];
        id[KEY_LEN - 1] = self.0[0];
        let id =
            Option::<Scalar>::from(Scalar::from_repr(id.into())).ok_or(ShareError::Malformed)?;
        let value: [u8; KEY_LEN] = self.0[1..].try_into().unwrap();
        let value =
            Option::<Scalar>::from(Scalar::from_repr(value.into())).ok_or(ShareError::Malformed)?;
        Ok(RawShare::with_identifier_and_value(
            IdentifierPrimeField(id),
            IdentifierPrimeField(value),
        ))
    }
}

/// Public Feldman commitments, stored on the state disc.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verifier {
    pub threshold: usize,
    pub limit: usize,
    commitments: Vec<RawVerifier>,
}

impl Verifier {
    pub fn check(&self, share: &KeyShare) -> Result<(), ShareError> {
        let index = share.index();
        if index as usize > self.limit {
            return Err(ShareError::Unverified(index));
        }
        let raw = share.to_raw()?;
        self.commitments
            .verify_share(&raw)
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
            raw.push(s.to_raw()?);
        }
        let secret = raw.combine().map_err(|e| ShareError::Vsss(e.to_string()))?;
        let bytes: [u8; KEY_LEN] = secret.0.to_repr().into();
        WrapKey::from_bytes(bytes).ok_or(ShareError::Vsss("reconstructed zero key".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(matches!(
            verifier.combine(&shares[..2]),
            Err(ShareError::NotEnough { needed: 3, have: 2 })
        ));
    }

    #[test]
    fn display_round_trips() {
        let (shares, verifier) = key().split(3, 5, &mut OsRng).unwrap();
        let typed = shares[3].to_display();
        let parsed = KeyShare::parse(&typed).unwrap();
        assert_eq!(parsed, shares[3]);
        verifier.check(&parsed).unwrap();
    }

    #[test]
    fn typo_is_caught_by_verifier() {
        let (shares, verifier) = key().split(3, 5, &mut OsRng).unwrap();
        let mut typed = shares[1].to_display().to_string();
        // flip one hex digit in the value
        let pos = typed.len() - 1;
        let c = if typed.as_bytes()[pos] == b'0' {
            "1"
        } else {
            "0"
        };
        typed.replace_range(pos.., c);
        let parsed = KeyShare::parse(&typed).unwrap();
        assert!(matches!(
            verifier.check(&parsed),
            Err(ShareError::Unverified(2))
        ));
    }

    #[test]
    fn duplicate_share_is_refused() {
        let (shares, verifier) = key().split(3, 5, &mut OsRng).unwrap();
        let picked = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
        assert!(matches!(
            verifier.combine(&picked),
            Err(ShareError::Duplicate(1))
        ));
    }

    #[test]
    fn verifier_round_trips_through_json() {
        let (shares, verifier) = key().split(3, 5, &mut OsRng).unwrap();
        let json = serde_json::to_string(&verifier).unwrap();
        let back: Verifier = serde_json::from_str(&json).unwrap();
        back.check(&shares[4]).unwrap();
    }
}
