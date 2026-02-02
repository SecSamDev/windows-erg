//! Registry key builder for advanced opening options.

use super::types::{Access, Hive, Wow64View};
use super::key::RegistryKey;
use crate::{Error, Result};
use windows::core::HSTRING;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::System::Registry::*;

/// Builder for opening registry keys with specific options.
pub struct RegistryKeyBuilder {
    hive: Option<Hive>,
    path: Option<String>,
    access: Access,
    wow64: Option<Wow64View>,
}

impl RegistryKeyBuilder {
    /// Create a new registry key builder.
    pub fn new() -> Self {
        RegistryKeyBuilder {
            hive: None,
            path: None,
            access: Access::Read,
            wow64: None,
        }
    }

    /// Set the registry hive.
    pub fn hive(mut self, hive: Hive) -> Self {
        self.hive = Some(hive);
        self
    }

    /// Set the registry key path.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set read-only access (default).
    pub fn read(mut self) -> Self {
        self.access = Access::Read;
        self
    }

    /// Set write access.
    pub fn write(mut self) -> Self {
        self.access = Access::ReadWrite;
        self
    }

    /// Set read-write access.
    pub fn read_write(mut self) -> Self {
        self.access = Access::ReadWrite;
        self
    }

    /// Access the 32-bit registry view on 64-bit Windows.
    pub fn wow64_32(mut self) -> Self {
        self.wow64 = Some(Wow64View::Key32);
        self
    }

    /// Access the 64-bit registry view (default on 64-bit Windows).
    pub fn wow64_64(mut self) -> Self {
        self.wow64 = Some(Wow64View::Key64);
        self
    }

    /// Open the registry key with the specified options.
    pub fn open(self) -> Result<RegistryKey> {
        let hive = self.hive.ok_or_else(|| {
            Error::InvalidParameter(crate::error::InvalidParameterError::new(
                "hive",
                "Registry hive must be specified"
            ))
        })?;
        let path = self.path.ok_or_else(|| {
            Error::InvalidParameter(crate::error::InvalidParameterError::new(
                "path",
                "Registry path must be specified"
            ))
        })?;

        let mut sam_flags = self.access.to_sam_flags();
        if let Some(wow64) = self.wow64 {
            sam_flags |= wow64.to_sam_flags();
        }

        let subkey_wide = HSTRING::from(&path);
        let mut handle = HKEY::default();

        unsafe {
            let result = RegOpenKeyExW(
                hive.as_hkey(),
                &subkey_wide,
                0,
                REG_SAM_FLAGS(sam_flags),
                &mut handle,
            );

            if result.is_err() {
                if result == ERROR_FILE_NOT_FOUND {
                    return Err(Error::Registry(crate::error::RegistryError::KeyNotFound(
                        crate::error::RegistryKeyNotFoundError::new(path)
                    )));
                }
                return Err(Error::WindowsApi(crate::error::WindowsApiError::with_context(
                    result.into(),
                    "RegOpenKeyExW"
                )));
            }
        }

        Ok(RegistryKey::from_handle(handle, true))
    }
}

impl Default for RegistryKeyBuilder {
    fn default() -> Self {
        Self::new()
    }
}
