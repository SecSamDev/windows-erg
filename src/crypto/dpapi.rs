//! DPAPI (`CryptProtectData`): protect small secrets with a key Windows
//! manages for the calling account.
//!
//! [`Scope::CurrentUser`] ties the data to the calling account: a service
//! running as LocalSystem gets a blob only LocalSystem can open.
//! [`Scope::LocalMachine`] lets any account on the machine open it, so it
//! only guards against copying the blob to another machine.
//!
//! `entropy` is a caller-chosen value that must match on
//! [`unprotect`]; use it to keep blobs from different purposes apart.
//!
//! # Example
//!
//! ```no_run
//! use windows_erg::crypto::dpapi::{self, Scope};
//!
//! let blob = dpapi::protect(b"data key", b"my-app vault", Scope::CurrentUser)?;
//! let key = dpapi::unprotect(&blob, b"my-app vault")?;
//! assert_eq!(key, b"data key");
//! # Ok::<(), windows_erg::Error>(())
//! ```

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};
use windows::core::PCWSTR;

use crate::error::{Error, Result, WindowsApiError};

/// Whose key protects the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Only the calling account can unprotect.
    CurrentUser,
    /// Any account on this machine can unprotect.
    LocalMachine,
}

/// Protect `data`. The result is opaque and only meaningful to [`unprotect`]
/// on this machine (and, for [`Scope::CurrentUser`], for this account).
pub fn protect(data: &[u8], entropy: &[u8], scope: Scope) -> Result<Vec<u8>> {
    let input = blob(data)?;
    let entropy = blob(entropy)?;
    let flags = match scope {
        Scope::CurrentUser => CRYPTPROTECT_UI_FORBIDDEN,
        Scope::LocalMachine => CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` and `entropy` point at live slices that DPAPI only
    // reads; `output` receives a LocalAlloc'd buffer, freed by `take`.
    unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            Some(&entropy),
            None,
            None,
            flags,
            &mut output,
        )
    }
    .map_err(|e| Error::WindowsApi(WindowsApiError::with_context(e, "CryptProtectData")))?;
    Ok(take(output))
}

/// Recover data protected by [`protect`] with the same `entropy`. Fails when
/// the blob was modified, the entropy differs, or the caller's account (for
/// [`Scope::CurrentUser`]) is not the one that protected it.
pub fn unprotect(protected: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    let input = blob(protected)?;
    let entropy = blob(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: as in `protect`.
    unsafe {
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    }
    .map_err(|e| Error::WindowsApi(WindowsApiError::with_context(e, "CryptUnprotectData")))?;
    Ok(take(output))
}

/// A read-only view of `data` as a DPAPI blob.
fn blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB> {
    let len = u32::try_from(data.len()).map_err(|_| {
        Error::InvalidParameter(crate::error::InvalidParameterError::new(
            "data",
            "larger than 4 GiB",
        ))
    })?;
    Ok(CRYPT_INTEGER_BLOB {
        cbData: len,
        pbData: data.as_ptr().cast_mut(),
    })
}

/// Copy a DPAPI output blob and free it.
fn take(output: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if output.pbData.is_null() {
        return Vec::new();
    }
    // SAFETY: on success DPAPI sets `pbData` to a LocalAlloc'd buffer of
    // `cbData` bytes; it is copied once and freed exactly once.
    unsafe {
        let data = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData.cast())));
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_in_both_scopes() {
        for scope in [Scope::CurrentUser, Scope::LocalMachine] {
            let blob = protect(b"secret key", b"purpose", scope).unwrap();
            assert!(!blob.windows(10).any(|w| w == b"secret key"));
            assert_eq!(unprotect(&blob, b"purpose").unwrap(), b"secret key");
        }
    }

    #[test]
    fn wrong_entropy_or_modified_blob_fails() {
        let blob = protect(b"secret key", b"purpose", Scope::CurrentUser).unwrap();
        assert!(unprotect(&blob, b"other purpose").is_err());

        let mut modified = blob.clone();
        let last = modified.len() - 1;
        modified[last] ^= 1;
        assert!(unprotect(&modified, b"purpose").is_err());
    }

    #[test]
    fn empty_data_round_trips() {
        let blob = protect(&[], &[], Scope::CurrentUser).unwrap();
        assert_eq!(unprotect(&blob, &[]).unwrap(), Vec::<u8>::new());
    }
}
