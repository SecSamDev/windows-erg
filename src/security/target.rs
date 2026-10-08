//! Security target helpers.

use crate::Result;

use super::SecurityDescriptor;
use super::backends;

/// Permission target reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionTarget {
    /// File or directory path.
    FilePath(String),
    /// Registry key path.
    RegistryPath(String),
}

impl PermissionTarget {
    /// Build a file target.
    pub fn file(path: impl Into<String>) -> Self {
        PermissionTarget::FilePath(path.into())
    }

    /// Build a registry target.
    pub fn registry(path: impl Into<String>) -> Self {
        PermissionTarget::RegistryPath(path.into())
    }

    /// Read current descriptor for target.
    pub fn read_descriptor(&self) -> Result<SecurityDescriptor> {
        match self {
            PermissionTarget::FilePath(path) => backends::file::read_descriptor(path),
            PermissionTarget::RegistryPath(path) => backends::registry::read_descriptor(path),
        }
    }

    /// Write descriptor to target.
    pub fn write_descriptor(&self, descriptor: &SecurityDescriptor) -> Result<()> {
        match self {
            PermissionTarget::FilePath(path) => backends::file::write_descriptor(path, descriptor),
            PermissionTarget::RegistryPath(path) => {
                backends::registry::write_descriptor(path, descriptor)
            }
        }
    }

    /// Replace the DACL with the one in `sddl` (for example
    /// `D:(A;OICI;FA;;;SY)` for a directory, `D:(A;CI;KA;;;SY)` for a
    /// registry key) and protect it from inheritance. Owner and group are
    /// unchanged.
    pub fn set_protected_dacl_sddl(&self, sddl: &str) -> Result<()> {
        match self {
            PermissionTarget::FilePath(path) => backends::file::set_protected_dacl(path, sddl),
            PermissionTarget::RegistryPath(path) => {
                backends::registry::set_protected_dacl(path, sddl)
            }
        }
    }

    /// The current DACL as SDDL (`D:...`), including the `P` flag when it is
    /// protected.
    pub fn dacl_sddl(&self) -> Result<String> {
        match self {
            PermissionTarget::FilePath(path) => backends::file::dacl_sddl(path),
            PermissionTarget::RegistryPath(path) => backends::registry::dacl_sddl(path),
        }
    }
}
