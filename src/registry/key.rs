//! Registry key handle and core operations.

use super::builder::RegistryKeyBuilder;
use super::types::Hive;
use super::values::RegistryValue;
use crate::{Error, Result};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS};
use windows::Win32::System::Registry::*;

/// A Windows Registry key with automatic handle management.
pub struct RegistryKey {
    pub(crate) handle: HKEY,
    close_on_drop: bool,
}

impl RegistryKey {
    /// Create from an existing handle (internal use).
    pub(crate) fn from_handle(handle: HKEY, close_on_drop: bool) -> Self {
        RegistryKey { handle, close_on_drop }
    }

    /// Create a builder for opening a registry key with specific options.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use windows_erg::registry::{Hive, RegistryKey};
    ///
    /// let key = RegistryKey::builder()
    ///     .hive(Hive::LocalMachine)
    ///     .path(r"SOFTWARE\Microsoft")
    ///     .read()
    ///     .open()?;
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn builder() -> RegistryKeyBuilder {
        RegistryKeyBuilder::new()
    }

    /// Open an existing registry key with read-only access.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use windows_erg::registry::{Hive, RegistryKey};
    ///
    /// let key = RegistryKey::open(
    ///     Hive::LocalMachine,
    ///     r"SOFTWARE\Microsoft\Windows\CurrentVersion"
    /// )?;
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn open(hive: Hive, subkey: &str) -> Result<Self> {
        let subkey_wide = HSTRING::from(subkey);
        let mut handle = HKEY::default();

        unsafe {
            let result = RegOpenKeyExW(
                hive.as_hkey(),
                &subkey_wide,
                0,
                KEY_READ,
                &mut handle,
            );

            if result.is_err() {
                if result == ERROR_FILE_NOT_FOUND {
                    return Err(Error::Registry(crate::error::RegistryError::KeyNotFound(
                        crate::error::RegistryKeyNotFoundError::new(subkey.to_string())
                    )));
                }
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }
        }

        Ok(RegistryKey {
            handle,
            close_on_drop: true,
        })
    }

    /// Create a new registry key or open it if it already exists.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use windows_erg::registry::{Hive, RegistryKey};
    ///
    /// let key = RegistryKey::create(Hive::CurrentUser, r"Software\MyApp")?;
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn create(hive: Hive, subkey: &str) -> Result<Self> {
        let subkey_wide = HSTRING::from(subkey);
        let mut handle = HKEY::default();
        let mut disposition = REG_CREATED_NEW_KEY;

        unsafe {
            let result = RegCreateKeyExW(
                hive.as_hkey(),
                &subkey_wide,
                0,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_READ | KEY_WRITE,
                None,
                &mut handle,
                Some(&mut disposition),
            );

            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::with_context(
                    result.into(),
                    "RegCreateKeyExW"
                )));
            }
        }

        Ok(RegistryKey {
            handle,
            close_on_drop: true,
        })
    }

    /// Get a typed value from the registry key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use windows_erg::registry::{Hive, RegistryKey};
    /// # let key = RegistryKey::open(Hive::LocalMachine, r"SOFTWARE\Microsoft")?;
    /// let value: String = key.get_value("SomeString")?;
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn get_value<T: RegistryValue>(&self, name: &str) -> Result<T> {
        T::read_from_key(self, name)
    }

    /// Set a typed value in the registry key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use windows_erg::registry::{Hive, RegistryKey};
    /// # let key = RegistryKey::create(Hive::CurrentUser, r"Software\MyApp")?;
    /// key.set_value("Version", "1.0.0")?;
    /// key.set_value("Count", 42u32)?;
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn set_value<T: RegistryValue>(&self, name: &str, value: T) -> Result<()> {
        value.write_to_key(self, name)
    }

    /// Delete a value from the registry key.
    pub fn delete_value(&self, name: &str) -> Result<()> {
        let name_wide = HSTRING::from(name);
        unsafe {
            let result = RegDeleteValueW(self.handle, &name_wide);
            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }
        }
        Ok(())
    }

    /// Check if a value exists in the registry key.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use windows_erg::registry::{Hive, RegistryKey};
    /// # let key = RegistryKey::open(Hive::CurrentUser, r"Software\MyApp")?;
    /// if key.value_exists("Version")? {
    ///     println!("Version exists");
    /// }
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn value_exists(&self, name: &str) -> Result<bool> {
        let name_wide = HSTRING::from(name);
        let mut typ = REG_NONE;

        unsafe {
            let result = RegQueryValueExW(
                self.handle,
                &name_wide,
                None,
                Some(&mut typ),
                None,
                None,
            );

            if result == ERROR_FILE_NOT_FOUND {
                return Ok(false);
            }

            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }

            Ok(true)
        }
    }

    /// Try to get a value, returning None if it doesn't exist.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use windows_erg::registry::{Hive, RegistryKey};
    /// # let key = RegistryKey::open(Hive::CurrentUser, r"Software\MyApp")?;
    /// if let Some(version) = key.try_get_value::<String>("Version") {
    ///     println!("Version: {}", version);
    /// }
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn try_get_value<T: RegistryValue>(&self, name: &str) -> Option<T> {
        T::read_from_key(self, name).ok()
    }

    /// Get a value with a default if it doesn't exist.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use windows_erg::registry::{Hive, RegistryKey};
    /// # let key = RegistryKey::open(Hive::CurrentUser, r"Software\MyApp")?;
    /// let count = key.get_value_or("Count", 0u32);
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn get_value_or<T: RegistryValue>(&self, name: &str, default: T) -> T {
        self.try_get_value(name).unwrap_or(default)
    }

    /// Delete a registry key.
    ///
    /// Note: The key must not have any subkeys. Use `delete_tree()` to delete
    /// a key and all its subkeys.
    pub fn delete_key(hive: Hive, subkey: &str) -> Result<()> {
        let subkey_wide = HSTRING::from(subkey);
        unsafe {
            let result = RegDeleteKeyW(hive.as_hkey(), &subkey_wide);
            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }
        }
        Ok(())
    }

    /// Delete a registry key and all its subkeys recursively.
    pub fn delete_tree(hive: Hive, subkey: &str) -> Result<()> {
        let subkey_wide = HSTRING::from(subkey);
        unsafe {
            let result = RegDeleteTreeW(hive.as_hkey(), &subkey_wide);
            if result.is_err() {
                return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
            }
        }
        Ok(())
    }

    /// Enumerate all subkeys of this key.
    pub fn subkeys(&self) -> Result<Vec<String>> {
        let mut subkeys = Vec::new();
        let mut index = 0u32;

        loop {
            let mut name_buf = vec![0u16; 256];
            let mut name_len = name_buf.len() as u32;

            unsafe {
                let result = RegEnumKeyExW(
                    self.handle,
                    index,
                    windows::core::PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    windows::core::PWSTR::null(),
                    None,
                    None,
                );

                if result == ERROR_NO_MORE_ITEMS {
                    break;
                }

                if result.is_err() {
                    return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
                }

                name_buf.truncate(name_len as usize);
                subkeys.push(String::from_utf16_lossy(&name_buf));
            }

            index += 1;
        }

        Ok(subkeys)
    }

    /// Enumerate all value names in this key.
    pub fn value_names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let mut index = 0u32;

        loop {
            let mut name_buf = vec![0u16; 256];
            let mut name_len = name_buf.len() as u32;

            unsafe {
                let result = RegEnumValueW(
                    self.handle,
                    index,
                    windows::core::PWSTR(name_buf.as_mut_ptr()),
                    &mut name_len,
                    None,
                    None,
                    None,
                    None,
                );

                if result == ERROR_NO_MORE_ITEMS {
                    break;
                }

                if result.is_err() {
                    return Err(Error::WindowsApi(crate::error::WindowsApiError::new(result.into())));
                }

                name_buf.truncate(name_len as usize);
                names.push(String::from_utf16_lossy(&name_buf));
            }

            index += 1;
        }

        Ok(names)
    }
}

impl Drop for RegistryKey {
    fn drop(&mut self) {
        if self.close_on_drop {
            unsafe {
                let _ = RegCloseKey(self.handle);
            }
        }
    }
}
