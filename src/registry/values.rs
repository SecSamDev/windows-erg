//! Registry value trait and type implementations.

use super::key::RegistryKey;
use crate::{Error, Result};
use windows::core::HSTRING;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::System::Registry::*;

/// Trait for types that can be read from and written to the registry.
pub trait RegistryValue: Sized {
    /// Read this value type from a registry key.
    fn read_from_key(key: &RegistryKey, name: &str) -> Result<Self>;

    /// Write this value type to a registry key.
    fn write_to_key(self, key: &RegistryKey, name: &str) -> Result<()>;
}

impl RegistryValue for String {
    fn read_from_key(key: &RegistryKey, name: &str) -> Result<Self> {
        let name_wide = HSTRING::from(name);
        let mut buf = vec![0u16; 1024];
        let mut len = (buf.len() * 2) as u32;
        let mut typ = REG_NONE;

        unsafe {
            let result = RegQueryValueExW(
                key.handle,
                &name_wide,
                None,
                Some(&mut typ),
                Some(buf.as_mut_ptr() as *mut u8),
                Some(&mut len),
            );

            if result.is_err() {
                if result == ERROR_FILE_NOT_FOUND {
                    return Err(Error::Registry(crate::error::RegistryError::ValueNotFound(
                        crate::error::RegistryValueNotFoundError::new(name.to_string())
                    )));
                }
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }

            if typ != REG_SZ && typ != REG_EXPAND_SZ {
                return Err(Error::Registry(crate::error::RegistryError::InvalidType(
                    crate::error::RegistryInvalidTypeError::with_name(
                        "String (REG_SZ or REG_EXPAND_SZ)",
                        format!("REG type {}", typ.0),
                        name.to_string()
                    )
                )));
            }

            let str_len = (len as usize / 2).saturating_sub(1);
            buf.truncate(str_len);
            Ok(String::from_utf16_lossy(&buf))
        }
    }

    fn write_to_key(self, key: &RegistryKey, name: &str) -> Result<()> {
        let name_wide = HSTRING::from(name);
        let value_wide = HSTRING::from(&self);
        let bytes = value_wide.as_wide();

        unsafe {
            let result = RegSetValueExW(
                key.handle,
                &name_wide,
                0,
                REG_SZ,
                Some(std::slice::from_raw_parts(
                    bytes.as_ptr() as *const u8,
                    (bytes.len() + 1) * 2,
                )),
            );
            
            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }
        }

        Ok(())
    }
}

// Implement for &str by converting to String
impl RegistryValue for &str {
    fn read_from_key(_key: &RegistryKey, _name: &str) -> Result<Self> {
        // Cannot return a borrowed string from registry data
        // This method should never be called since we can't read into &str
        unreachable!("Cannot read registry value into &str; use String instead")
    }

    fn write_to_key(self, key: &RegistryKey, name: &str) -> Result<()> {
        // Convert to String and use its implementation
        self.to_string().write_to_key(key, name)
    }
}

impl RegistryValue for u32 {
    fn read_from_key(key: &RegistryKey, name: &str) -> Result<Self> {
        let name_wide = HSTRING::from(name);
        let mut value = 0u32;
        let mut len = std::mem::size_of::<u32>() as u32;
        let mut typ = REG_NONE;

        unsafe {
            let result = RegQueryValueExW(
                key.handle,
                &name_wide,
                None,
                Some(&mut typ),
                Some(&mut value as *mut u32 as *mut u8),
                Some(&mut len),
            );

            if result.is_err() {
                if result == ERROR_FILE_NOT_FOUND {
                    return Err(Error::Registry(crate::error::RegistryError::ValueNotFound(
                        crate::error::RegistryValueNotFoundError::new(name.to_string())
                    )));
                }
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }

            if typ != REG_DWORD {
                return Err(Error::Registry(crate::error::RegistryError::InvalidType(
                    crate::error::RegistryInvalidTypeError::with_name(
                        "u32 (REG_DWORD)",
                        format!("REG type {}", typ.0),
                        name.to_string()
                    )
                )));
            }

            Ok(value)
        }
    }

    fn write_to_key(self, key: &RegistryKey, name: &str) -> Result<()> {
        let name_wide = HSTRING::from(name);

        unsafe {
            let result = RegSetValueExW(
                key.handle,
                &name_wide,
                0,
                REG_DWORD,
                Some(std::slice::from_raw_parts(
                    &self as *const u32 as *const u8,
                    std::mem::size_of::<u32>(),
                )),
            );
            
            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }
        }

        Ok(())
    }
}

impl RegistryValue for u64 {
    fn read_from_key(key: &RegistryKey, name: &str) -> Result<Self> {
        let name_wide = HSTRING::from(name);
        let mut value = 0u64;
        let mut len = std::mem::size_of::<u64>() as u32;
        let mut typ = REG_NONE;

        unsafe {
            let result = RegQueryValueExW(
                key.handle,
                &name_wide,
                None,
                Some(&mut typ),
                Some(&mut value as *mut u64 as *mut u8),
                Some(&mut len),
            );

            if result.is_err() {
                if result == ERROR_FILE_NOT_FOUND {
                    return Err(Error::Registry(crate::error::RegistryError::ValueNotFound(
                        crate::error::RegistryValueNotFoundError::new(name.to_string())
                    )));
                }
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }

            if typ != REG_QWORD {
                return Err(Error::Registry(crate::error::RegistryError::InvalidType(
                    crate::error::RegistryInvalidTypeError::with_name(
                        "u64 (REG_QWORD)",
                        format!("REG type {}", typ.0),
                        name.to_string()
                    )
                )));
            }

            Ok(value)
        }
    }

    fn write_to_key(self, key: &RegistryKey, name: &str) -> Result<()> {
        let name_wide = HSTRING::from(name);

        unsafe {
            let result = RegSetValueExW(
                key.handle,
                &name_wide,
                0,
                REG_QWORD,
                Some(std::slice::from_raw_parts(
                    &self as *const u64 as *const u8,
                    std::mem::size_of::<u64>(),
                )),
            );
            
            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }
        }

        Ok(())
    }
}

impl RegistryValue for bool {
    fn read_from_key(key: &RegistryKey, name: &str) -> Result<Self> {
        let value = u32::read_from_key(key, name)?;
        Ok(value != 0)
    }

    fn write_to_key(self, key: &RegistryKey, name: &str) -> Result<()> {
        let value = if self { 1u32 } else { 0u32 };
        value.write_to_key(key, name)
    }
}

impl RegistryValue for Vec<u8> {
    fn read_from_key(key: &RegistryKey, name: &str) -> Result<Self> {
        let name_wide = HSTRING::from(name);
        let mut buf = vec![0u8; 4096];
        let mut len = buf.len() as u32;
        let mut typ = REG_NONE;

        unsafe {
            let result = RegQueryValueExW(
                key.handle,
                &name_wide,
                None,
                Some(&mut typ),
                Some(buf.as_mut_ptr()),
                Some(&mut len),
            );

            if result.is_err() {
                if result == ERROR_FILE_NOT_FOUND {
                    return Err(Error::Registry(crate::error::RegistryError::ValueNotFound(
                        crate::error::RegistryValueNotFoundError::new(name.to_string())
                    )));
                }
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }

            if typ != REG_BINARY {
                return Err(Error::Registry(crate::error::RegistryError::InvalidType(
                    crate::error::RegistryInvalidTypeError::with_name(
                        "Vec<u8> (REG_BINARY)",
                        format!("REG type {}", typ.0),
                        name.to_string()
                    )
                )));
            }

            buf.truncate(len as usize);
            Ok(buf)
        }
    }

    fn write_to_key(self, key: &RegistryKey, name: &str) -> Result<()> {
        let name_wide = HSTRING::from(name);

        unsafe {
            let result = RegSetValueExW(
                key.handle,
                &name_wide,
                0,
                REG_BINARY,
                Some(&self),
            );
            
            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }
        }

        Ok(())
    }
}

impl RegistryValue for Vec<String> {
    fn read_from_key(key: &RegistryKey, name: &str) -> Result<Self> {
        let name_wide = HSTRING::from(name);
        let mut buf = vec![0u16; 4096];
        let mut len = (buf.len() * 2) as u32;
        let mut typ = REG_NONE;

        unsafe {
            let result = RegQueryValueExW(
                key.handle,
                &name_wide,
                None,
                Some(&mut typ),
                Some(buf.as_mut_ptr() as *mut u8),
                Some(&mut len),
            );

            if result.is_err() {
                if result == ERROR_FILE_NOT_FOUND {
                    return Err(Error::Registry(crate::error::RegistryError::ValueNotFound(
                        crate::error::RegistryValueNotFoundError::new(name.to_string())
                    )));
                }
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }

            if typ != REG_MULTI_SZ {
                return Err(Error::Registry(crate::error::RegistryError::InvalidType(
                    crate::error::RegistryInvalidTypeError::with_name(
                        "Vec<String> (REG_MULTI_SZ)",
                        format!("REG type {}", typ.0),
                        name.to_string()
                    )
                )));
            }

            // Parse multi-string (double-null terminated strings)
            let mut strings = Vec::new();
            let mut start = 0;
            
            for i in 0..(len as usize / 2) {
                if buf[i] == 0 {
                    if i > start {
                        let s = String::from_utf16_lossy(&buf[start..i]);
                        strings.push(s);
                    }
                    start = i + 1;
                    
                    // Double null terminator
                    if i + 1 < buf.len() && buf[i + 1] == 0 {
                        break;
                    }
                }
            }

            Ok(strings)
        }
    }

    fn write_to_key(self, key: &RegistryKey, name: &str) -> Result<()> {
        let name_wide = HSTRING::from(name);

        // Build multi-string buffer
        let mut buffer = Vec::new();
        for s in self {
            let wide = HSTRING::from(&s);
            buffer.extend_from_slice(wide.as_wide());
            buffer.push(0); // Null terminator
        }
        buffer.push(0); // Final null terminator

        unsafe {
            let result = RegSetValueExW(
                key.handle,
                &name_wide,
                0,
                REG_MULTI_SZ,
                Some(std::slice::from_raw_parts(
                    buffer.as_ptr() as *const u8,
                    buffer.len() * 2,
                )),
            );
            
            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }
        }

        Ok(())
    }
}
