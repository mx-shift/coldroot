//! HSM operations for the empty-between-ceremonies model.
//!
//! The HSM holds no keys at rest. A ceremony reconstructs the wrap key from a
//! quorum of custodian shares, installs it, imports the wrapped key blobs from
//! the state disc, does its work, exports fresh blobs, and resets the device.

use yubihsm::{Capability, Client, Domain, object, wrap};

pub use yubihsm::client::Error;

/// Object ID of the wrap key while it is installed during a ceremony.
pub const WRAP_KEY_ID: object::Id = 1;

/// Length of an AES-256-CCM wrap key in bytes.
pub const WRAP_KEY_LEN: usize = 32;

/// A key blob as stored on the state disc.
#[derive(Clone, Debug)]
pub struct Wrapped {
    pub object_type: object::Type,
    pub object_id: object::Id,
    pub message: wrap::Message,
}

/// Install the reconstructed wrap key. The capabilities are limited to moving
/// keys in and out under wrap; it can never be used to sign anything itself.
pub fn install_wrap_key(client: &Client, key: &[u8; WRAP_KEY_LEN]) -> Result<(), Error> {
    client.put_wrap_key(
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

/// Export the listed asymmetric keys under the installed wrap key.
pub fn backup(client: &Client, key_ids: &[object::Id]) -> Result<Vec<Wrapped>, Error> {
    key_ids
        .iter()
        .map(|&id| {
            let message = client.export_wrapped(WRAP_KEY_ID, object::Type::AsymmetricKey, id)?;
            Ok(Wrapped {
                object_type: object::Type::AsymmetricKey,
                object_id: id,
                message,
            })
        })
        .collect()
}

/// Import key blobs from the state disc under the installed wrap key.
pub fn restore(client: &Client, blobs: &[Wrapped]) -> Result<(), Error> {
    for blob in blobs {
        client.import_wrapped(WRAP_KEY_ID, blob.message.clone())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use yubihsm::{Connector, Credentials, asymmetric};

    const ROOT_KEY_ID: object::Id = 0x100;

    // MockHsm exports the *public* half of Ed25519 keys under wrap (see
    // mockhsm/object/payload.rs `to_bytes`), so Ed25519 can't round-trip
    // through the mock. Use P-256 here until that's fixed upstream; real
    // YubiHSM 2 hardware wraps Ed25519 keys correctly.
    const ALG: asymmetric::Algorithm = asymmetric::Algorithm::EcP256;
    const SIGN: Capability = Capability::SIGN_ECDSA;

    fn fresh_hsm() -> Client {
        Client::open(Connector::mockhsm(), Credentials::default(), true).unwrap()
    }

    /// The core claim of the design: keys generated on one HSM survive that
    /// HSM being wiped, and a different HSM can use them given only the wrap
    /// key and the blobs.
    #[test]
    fn keys_move_between_empty_hsms() {
        let wrap_key = [7u8; WRAP_KEY_LEN];

        let first = fresh_hsm();
        install_wrap_key(&first, &wrap_key).unwrap();
        first
            .generate_asymmetric_key(
                ROOT_KEY_ID,
                object::Label::from("root"),
                Domain::DOM1,
                SIGN | Capability::EXPORTABLE_UNDER_WRAP,
                ALG,
            )
            .unwrap();
        let public = first.get_public_key(ROOT_KEY_ID).unwrap();
        let blobs = backup(&first, &[ROOT_KEY_ID]).unwrap();
        drop(first);

        let second = fresh_hsm();
        install_wrap_key(&second, &wrap_key).unwrap();
        restore(&second, &blobs).unwrap();
        assert_eq!(second.get_public_key(ROOT_KEY_ID).unwrap(), public);
        second
            .sign_ecdsa_prehash_raw(ROOT_KEY_ID, [0u8; 32])
            .unwrap();
    }

    #[test]
    fn wrong_wrap_key_cannot_restore() {
        let first = fresh_hsm();
        install_wrap_key(&first, &[7u8; WRAP_KEY_LEN]).unwrap();
        first
            .generate_asymmetric_key(
                ROOT_KEY_ID,
                object::Label::from("root"),
                Domain::DOM1,
                SIGN | Capability::EXPORTABLE_UNDER_WRAP,
                ALG,
            )
            .unwrap();
        let blobs = backup(&first, &[ROOT_KEY_ID]).unwrap();

        let second = fresh_hsm();
        install_wrap_key(&second, &[8u8; WRAP_KEY_LEN]).unwrap();
        assert!(restore(&second, &blobs).is_err());
    }
}
