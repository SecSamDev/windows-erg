//! Single-instance guard for desktop applications.

use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::PCWSTR;

use crate::error::{Error, InvalidParameterError, Result};
use crate::utils::{OwnedHandle, to_utf16_nul};

use super::window::{op_error, validate_name};

/// Holds a named mutex in the session's `Local\` namespace for as long as it
/// lives, so a second copy of the application can tell it is not the first.
#[derive(Debug)]
pub struct SingleInstance {
    _mutex: OwnedHandle,
}

impl SingleInstance {
    /// Claim `name` for this session. Returns `None` when another process
    /// in the same session already holds it.
    pub fn acquire(name: &str) -> Result<Option<Self>> {
        validate_name("instance_name", name)?;
        if name.contains('\\') {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "instance_name",
                "value cannot contain a backslash",
            )));
        }
        let wide = to_utf16_nul(&format!("Local\\{name}"));
        // SAFETY: `wide` is NUL-terminated; default security attributes.
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(wide.as_ptr())) }
            .map_err(|e| op_error("CreateMutexW", name.to_string(), e.code().0))?;
        // SAFETY: reads the last error CreateMutexW set on success.
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let mutex = OwnedHandle::new(handle);
        if existed {
            return Ok(None);
        }
        Ok(Some(Self { _mutex: mutex }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_in_the_session_is_refused() {
        let name = format!("windows-erg-test-{}", std::process::id());
        let first = SingleInstance::acquire(&name).expect("acquire");
        assert!(first.is_some());
        assert!(SingleInstance::acquire(&name).expect("acquire").is_none());
        drop(first);
        assert!(SingleInstance::acquire(&name).expect("acquire").is_some());
    }

    #[test]
    fn names_are_validated() {
        assert!(SingleInstance::acquire("").is_err());
        assert!(SingleInstance::acquire("Global\\x").is_err());
    }
}
