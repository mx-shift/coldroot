//! The YubiHSM 2 behind coldroot's [`Hsm`] interface.
//!
//! The device holds no keys at rest. A ceremony reconstructs the wrap key from
//! a quorum of custodian shares, installs it, imports the wrapped key blobs
//! from the state disc, does its work, exports fresh blobs, and resets the
//! device. This crate is the only place that knows how the YubiHSM does each
//! of those steps.

use coldroot_ceremony::{Hsm, HsmError, KeyId, hsm::WRAP_KEY_LEN};
use yubihsm::{Capability, Client, Connector, Credentials, Domain, asymmetric, object, wrap};

/// Object ID of the wrap key while it is installed during a ceremony.
pub const WRAP_KEY_ID: object::Id = 1;

/// A YubiHSM 2 reached over USB (or the mock, in tests).
pub struct YubiHsm {
    client: Client,
}

impl YubiHsm {
    /// Open a session with the device's default authentication key. The
    /// device is expected to be factory-fresh, and is reset at the end of the
    /// ceremony, so there is nothing else to authenticate as.
    pub fn open(connector: Connector) -> Result<Self, HsmError> {
        let client = Client::open(connector, Credentials::default(), true)?;
        Ok(Self { client })
    }
}

impl Hsm for YubiHsm {
    fn install_wrap_key(&mut self, key: &[u8; WRAP_KEY_LEN]) -> Result<(), HsmError> {
        // Limited to moving keys in and out under wrap; it can never sign.
        self.client.put_wrap_key(
            WRAP_KEY_ID,
            object::Label::from("coldroot-wrap"),
            Domain::all(),
            Capability::EXPORT_WRAPPED | Capability::IMPORT_WRAPPED,
            Capability::all(),
            wrap::Algorithm::Aes256Ccm,
            key.to_vec(),
        )?;
        Ok(())
    }

    fn generate_signing_key(&mut self, id: KeyId, label: &str) -> Result<(), HsmError> {
        self.client.generate_asymmetric_key(
            id,
            object::Label::from(label),
            Domain::DOM1,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )?;
        Ok(())
    }

    fn public_key(&mut self, id: KeyId) -> Result<Vec<u8>, HsmError> {
        // The device returns raw `x || y`; SEC1 wants the 0x04 prefix.
        let raw = self.client.get_public_key(id)?.into_vec();
        let mut sec1 = Vec::with_capacity(raw.len() + 1);
        sec1.push(0x04);
        sec1.extend_from_slice(&raw);
        Ok(sec1)
    }

    fn export_wrapped(&mut self, id: KeyId) -> Result<Vec<u8>, HsmError> {
        let message = self
            .client
            .export_wrapped(WRAP_KEY_ID, object::Type::AsymmetricKey, id)?;
        Ok(message.into_vec())
    }

    fn import_wrapped(&mut self, blob: &[u8]) -> Result<KeyId, HsmError> {
        let message = wrap::Message::from_vec(blob.to_vec())?;
        let handle = self.client.import_wrapped(WRAP_KEY_ID, message)?;
        Ok(handle.object_id)
    }

    fn sign_prehash(&mut self, id: KeyId, digest: &[u8; 32]) -> Result<Vec<u8>, HsmError> {
        Ok(self.client.sign_ecdsa_prehash_raw(id, *digest)?)
    }

    fn reset(&mut self) -> Result<(), HsmError> {
        self.client.reset_device()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_KEY_ID: KeyId = 0x100;

    // MockHsm exports the *public* half of Ed25519 keys under wrap (see
    // mockhsm/object/payload.rs `to_bytes`), so Ed25519 can't round-trip
    // through the mock. The ceremonies use P-256 throughout, which the mock
    // wraps correctly, as does real hardware.
    fn fresh_hsm() -> YubiHsm {
        YubiHsm::open(Connector::mockhsm()).unwrap()
    }

    /// The core claim of the design: keys generated on one HSM survive that
    /// HSM being wiped, and a different HSM can use them given only the wrap
    /// key and the blobs.
    #[test]
    fn keys_move_between_empty_hsms() {
        let wrap_key = [7u8; WRAP_KEY_LEN];

        let mut first = fresh_hsm();
        first.install_wrap_key(&wrap_key).unwrap();
        first.generate_signing_key(ROOT_KEY_ID, "root").unwrap();
        let public = first.public_key(ROOT_KEY_ID).unwrap();
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04);
        let blob = first.export_wrapped(ROOT_KEY_ID).unwrap();
        first.reset().unwrap();
        assert!(first.public_key(ROOT_KEY_ID).is_err());

        let mut second = fresh_hsm();
        second.install_wrap_key(&wrap_key).unwrap();
        assert_eq!(second.import_wrapped(&blob).unwrap(), ROOT_KEY_ID);
        assert_eq!(second.public_key(ROOT_KEY_ID).unwrap(), public);
        second.sign_prehash(ROOT_KEY_ID, &[0u8; 32]).unwrap();
    }

    #[test]
    fn wrong_wrap_key_cannot_restore() {
        let mut first = fresh_hsm();
        first.install_wrap_key(&[7u8; WRAP_KEY_LEN]).unwrap();
        first.generate_signing_key(ROOT_KEY_ID, "root").unwrap();
        let blob = first.export_wrapped(ROOT_KEY_ID).unwrap();

        let mut second = fresh_hsm();
        second.install_wrap_key(&[8u8; WRAP_KEY_LEN]).unwrap();
        assert!(second.import_wrapped(&blob).is_err());
    }
}
