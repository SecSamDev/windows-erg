//! Security descriptor backend adapters.

pub(crate) mod file;
pub(crate) mod registry;

use crate::Result;
use crate::error::{Error, SecurityError, SecurityUnsupportedError, WindowsApiError};
use crate::utils::{pwstr_to_string_len, to_utf16_nul};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR,
};
use windows::core::{PCWSTR, PWSTR};

/// Security descriptor allocated with `LocalAlloc`, freed on drop.
pub(super) struct LocalDescriptor(pub(super) PSECURITY_DESCRIPTOR);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by a Win32 API with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

/// The descriptor `sddl` describes, and a pointer to its DACL, valid while
/// the descriptor lives. `path` and `operation` only label errors.
pub(super) fn dacl_from_sddl(
    path: &str,
    operation: &'static str,
    sddl: &str,
) -> Result<(LocalDescriptor, *mut ACL)> {
    let sddl_wide = to_utf16_nul(sddl);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl_wide` is NUL-terminated; the result is freed by `LocalDescriptor`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|e| {
        Error::WindowsApi(WindowsApiError::with_context(
            e,
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ))
    })?;
    let descriptor = LocalDescriptor(descriptor);

    let mut dacl_present = false.into();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted = false.into();
    // SAFETY: `descriptor` is a valid self-relative descriptor.
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    }
    .map_err(|e| {
        Error::WindowsApi(WindowsApiError::with_context(
            e,
            "GetSecurityDescriptorDacl",
        ))
    })?;
    if !dacl_present.as_bool() || dacl.is_null() {
        return Err(Error::Security(SecurityError::Unsupported(
            SecurityUnsupportedError::with_reason(path.to_string(), operation, "SDDL has no DACL"),
        )));
    }
    Ok((descriptor, dacl))
}

/// The DACL of `descriptor` as SDDL (`D:` part only), including the `P` flag
/// when the DACL is protected.
pub(super) fn dacl_to_sddl_string(descriptor: &LocalDescriptor) -> Result<String> {
    let mut sddl = PWSTR::null();
    let mut sddl_len = 0u32;
    // SAFETY: `descriptor` is valid; the string is freed below.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            Some(&mut sddl_len),
        )
    }
    .map_err(|e| {
        Error::WindowsApi(WindowsApiError::with_context(
            e,
            "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        ))
    })?;
    let text = pwstr_to_string_len(sddl, sddl_len as usize);
    // SAFETY: allocated by the conversion above and not used again.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sddl.0.cast())));
    }
    Ok(text.trim_end_matches('\0').to_string())
}
