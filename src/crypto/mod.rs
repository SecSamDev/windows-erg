//! Hashing and signatures through Windows CNG (`bcrypt.dll`).
//!
//! - [`sha256`] hashes a byte slice.
//! - [`EcdsaP256PublicKey`] verifies ECDSA P-256 signatures.
//! - [`EcdsaP256PrivateKey`] generates keys and signs digests.
//! - [`hmac_sha256`] authenticates a byte slice with a secret key.
//! - [`AesGcmKey`] seals and opens data with AES-256-GCM.
//! - [`random_bytes`] fills a buffer from the system RNG.
//! - [`dpapi`] protects small secrets (such as a data key) with DPAPI.
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

pub mod dpapi;

use windows::Win32::Foundation::{NTSTATUS, STATUS_AUTH_TAG_MISMATCH, STATUS_INVALID_SIGNATURE};
use windows::Win32::Security::Cryptography::{
    BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPRIVATE_BLOB,
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALG_HANDLE, BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC, BCRYPT_FLAGS, BCRYPT_HMAC_SHA256_ALG_HANDLE, BCRYPT_KEY_HANDLE,
    BCRYPT_MD5_ALG_HANDLE, BCRYPT_SHA1_ALG_HANDLE, BCRYPT_SHA256_ALG_HANDLE,
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptDecrypt, BCryptDestroyKey, BCryptEncrypt,
    BCryptExportKey, BCryptFinalizeKeyPair, BCryptGenRandom, BCryptGenerateKeyPair,
    BCryptGenerateSymmetricKey, BCryptHash, BCryptImportKeyPair, BCryptSignHash,
    BCryptVerifySignature,
};
use windows::core::PCWSTR;

use crate::error::{Error, InvalidParameterError, Result, WindowsApiError};

/// Length of a SHA-256 digest.
pub const SHA256_LEN: usize = 32;
/// Length of a SHA-1 digest.
pub const SHA1_LEN: usize = 20;
/// Length of an MD5 digest.
pub const MD5_LEN: usize = 16;
/// Length of a P-256 public key: `X || Y`.
pub const P256_PUBLIC_KEY_LEN: usize = 64;
/// Length of a P-256 signature: `r || s`.
pub const P256_SIGNATURE_LEN: usize = 64;
/// Length of an AES-256 key.
pub const AES256_KEY_LEN: usize = 32;
/// Length of an AES-GCM nonce.
pub const GCM_NONCE_LEN: usize = 12;
/// Length of an AES-GCM authentication tag.
pub const GCM_TAG_LEN: usize = 16;
/// Length of an HMAC-SHA256 output.
pub const HMAC_SHA256_LEN: usize = 32;
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

/// SHA-1 of `data`. Not for anything security-sensitive — only for matching
/// legacy hash databases that still key on it.
pub fn sha1(data: &[u8]) -> Result<[u8; SHA1_LEN]> {
    let mut digest = [0u8; SHA1_LEN];
    // SAFETY: the pseudo-handle needs no setup; both buffers are valid slices.
    let status = unsafe { BCryptHash(BCRYPT_SHA1_ALG_HANDLE, None, data, &mut digest) };
    check(status, "BCryptHash")?;
    Ok(digest)
}

/// MD5 of `data`. Not for anything security-sensitive — only for computing
/// values like `imphash` that are conventionally MD5.
pub fn md5(data: &[u8]) -> Result<[u8; MD5_LEN]> {
    let mut digest = [0u8; MD5_LEN];
    // SAFETY: the pseudo-handle needs no setup; both buffers are valid slices.
    let status = unsafe { BCryptHash(BCRYPT_MD5_ALG_HANDLE, None, data, &mut digest) };
    check(status, "BCryptHash")?;
    Ok(digest)
}

/// Fill `buffer` from the system-preferred RNG.
pub fn random_bytes(buffer: &mut [u8]) -> Result<()> {
    // SAFETY: BCRYPT_USE_SYSTEM_PREFERRED_RNG requires a null algorithm
    // handle; `buffer` is a valid slice.
    let status = unsafe { BCryptGenRandom(None, buffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    check(status, "BCryptGenRandom")
}

/// HMAC-SHA256 of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SHA256_LEN]> {
    let mut mac = [0u8; HMAC_SHA256_LEN];
    // SAFETY: the pseudo-handle needs no setup; all buffers are valid slices.
    let status = unsafe { BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE, Some(key), data, &mut mac) };
    check(status, "BCryptHash")?;
    Ok(mac)
}

/// An AES-256-GCM key.
///
/// Keeps only its bytes and creates a CNG key per call, like the ECDSA keys.
/// The caller owns nonce uniqueness: never seal twice with the same key and
/// nonce.
#[derive(Clone)]
pub struct AesGcmKey {
    key: [u8; AES256_KEY_LEN],
}

impl AesGcmKey {
    /// Key from its raw bytes.
    pub fn from_bytes(key: &[u8; AES256_KEY_LEN]) -> Self {
        Self { key: *key }
    }

    /// Encrypt `plaintext` and authenticate it together with `aad`.
    /// Returns `ciphertext || tag`, [`GCM_TAG_LEN`] bytes longer than the
    /// input. An empty `plaintext` gives a tag over `aad` alone.
    pub fn seal(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let key = KeyHandle::aes_gcm(&self.key)?;
        let mut sealed = vec![0u8; plaintext.len() + GCM_TAG_LEN];
        let (output, tag) = sealed.split_at_mut(plaintext.len());
        let info = cipher_info(nonce, aad, tag);
        let mut written = 0u32;
        // SAFETY: `key` is a live AES-GCM key; `info` points at `nonce`,
        // `aad` and `tag`, which outlive the call; CNG only reads the nonce
        // and aad and writes the tag; `output` is as long as `plaintext`.
        let status = unsafe {
            BCryptEncrypt(
                key.0,
                Some(plaintext),
                Some(std::ptr::from_ref(&info).cast()),
                None,
                Some(output),
                &mut written,
                BCRYPT_FLAGS(0),
            )
        };
        check(status, "BCryptEncrypt")?;
        Ok(sealed)
    }

    /// Check and decrypt `ciphertext || tag` produced by [`seal`](Self::seal)
    /// with the same nonce and `aad`. `Ok(None)` when it does not
    /// authenticate (wrong key, nonce or aad, or modified data).
    pub fn open(
        &self,
        nonce: &[u8; GCM_NONCE_LEN],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let Some(split) = sealed.len().checked_sub(GCM_TAG_LEN) else {
            return Ok(None);
        };
        let (ciphertext, tag) = sealed.split_at(split);
        let mut tag: [u8; GCM_TAG_LEN] = tag
            .try_into()
            .map_err(|_| invalid("sealed", "shorter than a GCM tag"))?;
        let key = KeyHandle::aes_gcm(&self.key)?;
        let mut plaintext = vec![0u8; ciphertext.len()];
        let info = cipher_info(nonce, aad, &mut tag);
        let mut written = 0u32;
        // SAFETY: as in `seal`; on decrypt CNG only reads the tag.
        let status = unsafe {
            BCryptDecrypt(
                key.0,
                Some(ciphertext),
                Some(std::ptr::from_ref(&info).cast()),
                None,
                Some(&mut plaintext),
                &mut written,
                BCRYPT_FLAGS(0),
            )
        };
        if status == STATUS_AUTH_TAG_MISMATCH {
            return Ok(None);
        }
        check(status, "BCryptDecrypt")?;
        Ok(Some(plaintext))
    }
}

impl std::fmt::Debug for AesGcmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmKey").finish_non_exhaustive()
    }
}

/// GCM parameters pointing into the caller's buffers. The nonce and aad are
/// input only; their pointers are `*mut` because of the C struct.
fn cipher_info(
    nonce: &[u8; GCM_NONCE_LEN],
    aad: &[u8],
    tag: &mut [u8],
) -> BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        cbSize: std::mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
        dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
        pbNonce: nonce.as_ptr().cast_mut(),
        cbNonce: GCM_NONCE_LEN as u32,
        pbAuthData: if aad.is_empty() {
            std::ptr::null_mut()
        } else {
            aad.as_ptr().cast_mut()
        },
        cbAuthData: aad.len() as u32,
        pbTag: tag.as_mut_ptr(),
        cbTag: tag.len() as u32,
        ..Default::default()
    }
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
                None,
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
                None,
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

impl KeyHandle {
    fn aes_gcm(secret: &[u8; AES256_KEY_LEN]) -> Result<Self> {
        let mut handle = BCRYPT_KEY_HANDLE::default();
        // SAFETY: the pseudo-handle needs no setup and lets CNG allocate the
        // key object itself; CNG copies `secret`.
        let status = unsafe {
            BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &mut handle, None, secret, 0)
        };
        check(status, "BCryptGenerateSymmetricKey")?;
        Ok(Self(handle))
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
    fn sha1_matches_known_vectors() {
        assert_eq!(
            hex(&sha1(b"").unwrap()),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex(&sha1(b"abc").unwrap()),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn md5_matches_known_vectors() {
        assert_eq!(hex(&md5(b"").unwrap()), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex(&md5(b"abc").unwrap()),
            "900150983cd24fb0d6963f7d28e17f72"
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

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_case_2() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?").unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn random_bytes_fill_the_buffer() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random_bytes(&mut a).unwrap();
        random_bytes(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn aes_gcm_matches_the_gcm_spec_test_case_15() {
        // McGrew & Viega, "The Galois/Counter Mode of Operation", test case
        // 15: AES-256, 96-bit IV, no aad.
        let key: [u8; 32] =
            unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
                .try_into()
                .unwrap();
        let nonce: [u8; 12] = unhex("cafebabefacedbaddecaf888").try_into().unwrap();
        let plaintext = unhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let sealed = AesGcmKey::from_bytes(&key)
            .seal(&nonce, &[], &plaintext)
            .unwrap();
        assert_eq!(
            sealed,
            unhex(
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
                 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad
                 b094dac5d93471bdec1a502270e3cc6c"
            )
        );
    }

    #[test]
    fn aes_gcm_round_trips_and_rejects_tampering() {
        let mut raw = [0u8; 32];
        random_bytes(&mut raw).unwrap();
        let key = AesGcmKey::from_bytes(&raw);
        let nonce = [7u8; GCM_NONCE_LEN];
        let sealed = key.seal(&nonce, b"header", b"detection").unwrap();
        assert_eq!(sealed.len(), b"detection".len() + GCM_TAG_LEN);
        assert_eq!(
            key.open(&nonce, b"header", &sealed).unwrap().as_deref(),
            Some(&b"detection"[..])
        );

        let mut flipped = sealed.clone();
        flipped[0] ^= 1;
        assert_eq!(key.open(&nonce, b"header", &flipped).unwrap(), None);
        assert_eq!(key.open(&nonce, b"other", &sealed).unwrap(), None);
        assert_eq!(key.open(&[8u8; 12], b"header", &sealed).unwrap(), None);
        assert_eq!(key.open(&nonce, b"header", &sealed[..4]).unwrap(), None);

        // Empty plaintext: an authenticate-only tag over the aad.
        let tag = key.seal(&nonce, b"policy", &[]).unwrap();
        assert_eq!(tag.len(), GCM_TAG_LEN);
        assert_eq!(key.open(&nonce, b"policy", &tag).unwrap(), Some(Vec::new()));
        assert_eq!(key.open(&nonce, b"policY", &tag).unwrap(), None);
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
