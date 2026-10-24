//! What a ceremony needs from an HSM, and nothing more.
//!
//! The ceremonies never see a vendor client. They talk to an [`Hsm`], which
//! `coldroot-hsm` implements for the YubiHSM 2 and tests implement in
//! software. Everything crosses this boundary as plain bytes: SEC1 public
//! keys, DER signatures and opaque wrapped blobs that only the same model of
//! HSM with the same wrap key can open.

/// Object ID of a key inside the HSM. The same ID is used on every HSM the
/// key is ever restored into, so the state disc can name keys by it.
pub type KeyId = u16;

/// Length of the AES-256 wrap key in bytes.
pub const WRAP_KEY_LEN: usize = 32;

/// An error from the device or its driver, reported as the vendor's own type.
pub type HsmError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// An HSM that starts a ceremony empty and is wiped at the end of it.
pub trait Hsm {
    /// Install the custodians' wrap key. It must only be able to move keys
    /// in and out under wrap, never to sign.
    fn install_wrap_key(&mut self, key: &[u8; WRAP_KEY_LEN]) -> Result<(), HsmError>;

    /// Generate a P-256 signing key that can leave the device only under wrap.
    fn generate_signing_key(&mut self, id: KeyId, label: &str) -> Result<(), HsmError>;

    /// The key's public half as an uncompressed SEC1 point (`04 || x || y`).
    fn public_key(&mut self, id: KeyId) -> Result<Vec<u8>, HsmError>;

    /// Export `id` under the installed wrap key as an opaque blob.
    fn export_wrapped(&mut self, id: KeyId) -> Result<Vec<u8>, HsmError>;

    /// Import a blob made by [`Hsm::export_wrapped`]; returns the ID of the
    /// key it held, which the ceremony checks against the state disc.
    fn import_wrapped(&mut self, blob: &[u8]) -> Result<KeyId, HsmError>;

    /// ECDSA over an already-hashed message, as a DER signature.
    fn sign_prehash(&mut self, id: KeyId, digest: &[u8; 32]) -> Result<Vec<u8>, HsmError>;

    /// Wipe the device, including the wrap key.
    fn reset(&mut self) -> Result<(), HsmError>;
}
