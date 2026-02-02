//! Windows Registry operations.
//!
//! This module provides ergonomic access to the Windows Registry with automatic
//! handle management and type-safe value operations.
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```no_run
//! use windows_erg::registry::{Hive, RegistryKey};
//!
//! // Open a key
//! let key = RegistryKey::open(
//!     Hive::LocalMachine,
//!     r"SOFTWARE\Microsoft\Windows\CurrentVersion"
//! )?;
//!
//! // Read a string value
//! let program_files: String = key.get_value("ProgramFilesDir")?;
//!
//! // Create a new key and write values
//! let key = RegistryKey::create(Hive::CurrentUser, r"Software\MyApp")?;
//! key.set_value("Version", "1.0.0")?;
//! key.set_value("Count", 42u32)?;
//!
//! // Enumerate subkeys
//! for subkey in key.subkeys()? {
//!     println!("Subkey: {}", subkey);
//! }
//! # Ok::<(), windows_erg::Error>(())
//! ```
//!
//! ## Convenience Functions
//!
//! ```no_run
//! use windows_erg::registry::{self, Hive};
//!
//! // Quick read/write without opening a key
//! let version = registry::read_string(
//!     Hive::LocalMachine,
//!     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
//!     "ProductName"
//! )?;
//!
//! registry::write_u32(Hive::CurrentUser, r"Software\MyApp", "Count", 42)?;
//! # Ok::<(), windows_erg::Error>(())
//! ```
//!
//! ## Advanced Key Opening
//!
//! ```no_run
//! use windows_erg::registry::{Hive, RegistryKey};
//!
//! // Open with WOW64 view and specific access
//! let key = RegistryKey::builder()
//!     .hive(Hive::LocalMachine)
//!     .path(r"SOFTWARE\MyApp")
//!     .write()
//!     .wow64_32()
//!     .open()?;
//! # Ok::<(), windows_erg::Error>(())
//! ```

mod builder;
mod key;
mod types;
mod values;

#[cfg(test)]
mod tests;

pub use builder::RegistryKeyBuilder;
pub use key::RegistryKey;
pub use types::{Access, Hive};
pub use values::RegistryValue;

use crate::Result;

// Convenience functions for quick registry operations

/// Read a string value from the registry without opening a key.
pub fn read_string(hive: Hive, path: &str, name: &str) -> Result<String> {
    let key = RegistryKey::open(hive, path)?;
    key.get_value(name)
}

/// Write a string value to the registry without opening a key.
pub fn write_string(hive: Hive, path: &str, name: &str, value: &str) -> Result<()> {
    let key = RegistryKey::create(hive, path)?;
    key.set_value(name, value.to_string())
}

/// Read a DWORD (u32) value from the registry.
pub fn read_u32(hive: Hive, path: &str, name: &str) -> Result<u32> {
    let key = RegistryKey::open(hive, path)?;
    key.get_value(name)
}

/// Write a DWORD (u32) value to the registry.
pub fn write_u32(hive: Hive, path: &str, name: &str, value: u32) -> Result<()> {
    let key = RegistryKey::create(hive, path)?;
    key.set_value(name, value)
}

/// Read a QWORD (u64) value from the registry.
pub fn read_u64(hive: Hive, path: &str, name: &str) -> Result<u64> {
    let key = RegistryKey::open(hive, path)?;
    key.get_value(name)
}

/// Write a QWORD (u64) value to the registry.
pub fn write_u64(hive: Hive, path: &str, name: &str, value: u64) -> Result<()> {
    let key = RegistryKey::create(hive, path)?;
    key.set_value(name, value)
}

/// Read a boolean value from the registry (stored as DWORD).
pub fn read_bool(hive: Hive, path: &str, name: &str) -> Result<bool> {
    let key = RegistryKey::open(hive, path)?;
    key.get_value(name)
}

/// Write a boolean value to the registry (stored as DWORD).
pub fn write_bool(hive: Hive, path: &str, name: &str, value: bool) -> Result<()> {
    let key = RegistryKey::create(hive, path)?;
    key.set_value(name, value)
}

/// Read binary data from the registry.
pub fn read_binary(hive: Hive, path: &str, name: &str) -> Result<Vec<u8>> {
    let key = RegistryKey::open(hive, path)?;
    key.get_value(name)
}

/// Write binary data to the registry.
pub fn write_binary(hive: Hive, path: &str, name: &str, value: &[u8]) -> Result<()> {
    let key = RegistryKey::create(hive, path)?;
    key.set_value(name, value.to_vec())
}

/// Read a multi-string value from the registry.
pub fn read_multi_string(hive: Hive, path: &str, name: &str) -> Result<Vec<String>> {
    let key = RegistryKey::open(hive, path)?;
    key.get_value(name)
}

/// Write a multi-string value to the registry.
pub fn write_multi_string(hive: Hive, path: &str, name: &str, value: &[String]) -> Result<()> {
    let key = RegistryKey::create(hive, path)?;
    key.set_value(name, value.to_vec())
}
