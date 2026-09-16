//! Hashing and signatures through Windows CNG (`bcrypt.dll`).
//!
//! - [`sha256`] hashes a byte slice.
//! - [`EcdsaP256PublicKey`] verifies ECDSA P-256 signatures.
//! - [`EcdsaP256PrivateKey`] generates keys and signs digests.
//!
//! Signatures are 64 raw bytes, `r || s` (IEEE P1363), as CNG produces them.
//! Keys keep only their bytes and import a CNG handle per call, so they are
//! `Send + Sync` and need no cleanup.
//!
//! # Example
//!
//! ```no_run
//! use windows_erg::crypto::{EcdsaP256PrivateKey, sha256};
//!
//! let key = EcdsaP256PrivateKey::generate()?;
//! let digest = sha256(b"manifest")?;
//! let signature = key.sign(&digest)?;
//! assert!(key.public_key().verify(&digest, &signature)?);
//! # Ok::<(), windows_erg::Error>(())
//! ```

use windows::Win32::Foundation::{NTSTATUS, STATUS_INVALID_SIGNATURE};
use windows::Win32::Security::Cryptography::{
    BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDSA_P256_ALG_HANDLE, BCRYPT_ECDSA_PRIVATE_P256_MAGIC, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
    BCRYPT_FLAGS, BCRYPT_KEY_HANDLE, BCRYPT_SHA256_ALG_HANDLE, BCryptDestroyKey, BCryptExportKey,
    BCryptFinalizeKeyPair, BCryptGenerateKeyPair, BCryptHash, BCryptImportKeyPair, BCryptSignHash,
    BCryptVerifySignature,
};
use windows::core::PCWSTR;

use crate::error::{Error, InvalidParameterError, Result, WindowsApiError};

/// Length of a SHA-256 digest.
pub const SHA256_LEN: usize = 32;
/// Length of a P-256 public key: `X || Y`.
pub const P256_PUBLIC_KEY_LEN: usize = 64;
/// Length of a P-256 signature: `r || s`.
pub const P256_SIGNATURE_LEN: usize = 64;
/// Length of a serialised P-256 private key ([`EcdsaP256PrivateKey::to_blob`]).
pub const P256_PRIVATE_BLOB_LEN: usize = HEADER_LEN + 3 * COORD_LEN;

const COORD_LEN: usize = 32;
const HEADER_LEN: usize = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();
const P256_BITS: u32 = 256;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> Result<[u8; SHA256_LEN]> {
    let mut digest = [0u8; SHA256_LEN];
    // SAFETY: the pseudo-handle needs no setup; both buffers are valid slices.
    let status = unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, data, &mut digest) };
    check(status, "BCryptHash")?;
    Ok(digest)
}

/// An ECDSA P-256 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EcdsaP256PublicKey {
    xy: [u8; P256_PUBLIC_KEY_LEN],
}

impl EcdsaP256PublicKey {
    /// Key from its uncompressed coordinates, `X || Y` (32 bytes each,
    /// big-endian). The point is validated on first use.
    pub fn from_xy(xy: &[u8; P256_PUBLIC_KEY_LEN]) -> Self {
        Self { xy: *xy }
    }

    /// The coordinates, `X || Y`.
    pub fn to_xy(&self) -> [u8; P256_PUBLIC_KEY_LEN] {
        self.xy
    }

    /// `Ok(false)` when `signature` does not match `digest`; `Err` when the
    /// key itself is invalid or CNG fails.
    pub fn verify(
        &self,
        digest: &[u8; SHA256_LEN],
        signature: &[u8; P256_SIGNATURE_LEN],
    ) -> Result<bool> {
        let blob = key_blob(BCRYPT_ECDSA_PUBLIC_P256_MAGIC, &[&self.xy]);
        let key = KeyHandle::import(BCRYPT_ECCPUBLIC_BLOB, &blob)?;
        // SAFETY: `key` is a live key handle; no padding info for ECDSA.
        let status =
            unsafe { BCryptVerifySignature(key.0, None, digest, signature, BCRYPT_FLAGS(0)) };
        if status == STATUS_INVALID_SIGNATURE {
            return Ok(false);
        }
        check(status, "BCryptVerifySignature")?;
        Ok(true)
    }
}

impl std::fmt::Debug for EcdsaP256PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaP256PublicKey").finish_non_exhaustive()
    }
}

/// An ECDSA P-256 private key.
#[derive(Clone)]
pub struct EcdsaP256PrivateKey {
    blob: [u8; P256_PRIVATE_BLOB_LEN],
}

impl EcdsaP256PrivateKey {
    /// A new random key.
    pub fn generate() -> Result<Self> {
        let key = KeyHandle::generate()?;
        let mut blob = [0u8; P256_PRIVATE_BLOB_LEN];
        let mut written = 0u32;
        // SAFETY: `key` is a finalised key pair and `blob` is large enough for
        // a P-256 private blob.
        let status = unsafe {
            BCryptExportKey(
                key.0,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPRIVATE_BLOB,
                Some(&mut blob),
                &mut written,
                0,
            )
        };
        check(status, "BCryptExportKey")?;
        Self::from_blob(&blob[..written as usize])
    }

    /// Key from a blob written by [`to_blob`](Self::to_blob) (a CNG
    /// `BCRYPT_ECCPRIVATE_BLOB`). The key is validated here.
    pub fn from_blob(blob: &[u8]) -> Result<Self> {
        let blob: [u8; P256_PRIVATE_BLOB_LEN] = blob
            .try_into()
            .map_err(|_| invalid("blob", "not a P-256 private key blob"))?;
        let header = key_blob(BCRYPT_ECDSA_PRIVATE_P256_MAGIC, &[]);
        if blob[..HEADER_LEN] != header[..] {
            return Err(invalid("blob", "not a P-256 private key blob"));
        }
        KeyHandle::import(BCRYPT_ECCPRIVATE_BLOB, &blob)?;
        Ok(Self { blob })
    }

    /// Serialised key, for storage outside source control.
    pub fn to_blob(&self) -> [u8; P256_PRIVATE_BLOB_LEN] {
        self.blob
    }

    /// The matching public key.
    pub fn public_key(&self) -> EcdsaP256PublicKey {
        let mut xy = [0u8; P256_PUBLIC_KEY_LEN];
        xy.copy_from_slice(&self.blob[HEADER_LEN..HEADER_LEN + P256_PUBLIC_KEY_LEN]);
        EcdsaP256PublicKey { xy }
    }

    /// Sign a SHA-256 digest.
    pub fn sign(&self, digest: &[u8; SHA256_LEN]) -> Result<[u8; P256_SIGNATURE_LEN]> {
        let key = KeyHandle::import(BCRYPT_ECCPRIVATE_BLOB, &self.blob)?;
        let mut signature = [0u8; P256_SIGNATURE_LEN];
        let mut written = 0u32;
        // SAFETY: `key` is a live private key; the output fits a P-256 signature.
        let status = unsafe {
            BCryptSignHash(
                key.0,
                None,
                digest,
                Some(&mut signature),
                &mut written,
                BCRYPT_FLAGS(0),
            )
        };
        check(status, "BCryptSignHash")?;
        if written as usize != P256_SIGNATURE_LEN {
            return Err(invalid("signature", "unexpected P-256 signature length"));
        }
        Ok(signature)
    }
}

impl std::fmt::Debug for EcdsaP256PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaP256PrivateKey")
            .finish_non_exhaustive()
    }
}

/// CNG key handle, destroyed on drop.
struct KeyHandle(BCRYPT_KEY_HANDLE);

impl KeyHandle {
    fn import(blob_type: PCWSTR, blob: &[u8]) -> Result<Self> {
        let mut handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: the pseudo-handle needs no setup; `blob` is a complete blob
        // of `blob_type`, and CNG copies it.
        let status = unsafe {
            BCryptImportKeyPair(
                BCRYPT_ECDSA_P256_ALG_HANDLE,
                BCRYPT_KEY_HANDLE::default(),
                blob_type,
                &mut handle,
                blob,
                0,
            )
        };
        check(status, "BCryptImportKeyPair")?;
        Ok(Self(handle))
    }

    fn generate() -> Result<Self> {
        let mut handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: the pseudo-handle needs no setup.
        let status = unsafe {
            BCryptGenerateKeyPair(BCRYPT_ECDSA_P256_ALG_HANDLE, &mut handle, P256_BITS, 0)
        };
        check(status, "BCryptGenerateKeyPair")?;
        let key = Self(handle);
        // SAFETY: `key` holds an unfinalised key pair.
        check(
            unsafe { BCryptFinalizeKeyPair(key.0, 0) },
            "BCryptFinalizeKeyPair",
        )?;
        Ok(key)
    }
}

impl Drop for KeyHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from CNG and is destroyed exactly once.
        let _ = unsafe { BCryptDestroyKey(self.0) };
    }
}

/// `BCRYPT_ECCKEY_BLOB` header followed by `parts`.
fn key_blob(magic: u32, parts: &[&[u8]]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(HEADER_LEN + parts.iter().map(|p| p.len()).sum::<usize>());
    blob.extend_from_slice(&magic.to_le_bytes());
    blob.extend_from_slice(&(COORD_LEN as u32).to_le_bytes());
    for part in parts {
        blob.extend_from_slice(part);
    }
    blob
}

fn check(status: NTSTATUS, api: &'static str) -> Result<()> {
    status
        .ok()
        .map_err(|e| Error::WindowsApi(WindowsApiError::with_context(e, api)))
}

fn invalid(parameter: &'static str, reason: &'static str) -> Error {
    Error::InvalidParameter(InvalidParameterError::new(parameter, reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            hex(&sha256(b"").unwrap()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc").unwrap()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn signatures_verify_only_for_the_signed_digest_and_key() {
        let key = EcdsaP256PrivateKey::generate().unwrap();
        let public = key.public_key();
        let digest = sha256(b"manifest").unwrap();
        let signature = key.sign(&digest).unwrap();

        assert!(public.verify(&digest, &signature).unwrap());

        let other_digest = sha256(b"manifest!").unwrap();
        assert!(!public.verify(&other_digest, &signature).unwrap());

        let mut bad_signature = signature;
        bad_signature[10] ^= 1;
        assert!(!public.verify(&digest, &bad_signature).unwrap());

        let other_key = EcdsaP256PrivateKey::generate().unwrap().public_key();
        assert!(!other_key.verify(&digest, &signature).unwrap());
    }

    #[test]
    fn private_key_round_trips_through_its_blob() {
        let key = EcdsaP256PrivateKey::generate().unwrap();
        let restored = EcdsaP256PrivateKey::from_blob(&key.to_blob()).unwrap();
        assert_eq!(restored.public_key(), key.public_key());

        let digest = sha256(b"x").unwrap();
        let signature = restored.sign(&digest).unwrap();
        assert!(key.public_key().verify(&digest, &signature).unwrap());
        assert_eq!(
            EcdsaP256PublicKey::from_xy(&key.public_key().to_xy()),
            key.public_key()
        );
    }

    #[test]
    fn malformed_keys_are_rejected() {
        assert!(EcdsaP256PrivateKey::from_blob(&[0u8; 10]).is_err());
        assert!(EcdsaP256PrivateKey::from_blob(&[0u8; P256_PRIVATE_BLOB_LEN]).is_err());

        let not_on_curve = EcdsaP256PublicKey::from_xy(&[1u8; P256_PUBLIC_KEY_LEN]);
        let digest = sha256(b"x").unwrap();
        assert!(not_on_curve.verify(&digest, &[0u8; 64]).is_err());
    }
}
