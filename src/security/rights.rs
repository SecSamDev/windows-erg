//! Resource-specific rights wrappers.

use super::AccessMask;

/// File access rights wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAccess {
    /// Read data/list directory.
    Read,
    /// Write data/add file.
    Write,
    /// Execute/traverse.
    Execute,
    /// Read + write + execute + standard rights.
    FullControl,
    /// Custom raw mask.
    Custom(AccessMask),
}

impl FileAccess {
    /// Convert to generic access mask.
    pub fn to_mask(self) -> AccessMask {
        match self {
            FileAccess::Read => AccessMask::from_bits(0x120089),
            FileAccess::Write => AccessMask::from_bits(0x120116),
            FileAccess::Execute => AccessMask::from_bits(0x1200A0),
            FileAccess::FullControl => AccessMask::from_bits(0x1F01FF),
            FileAccess::Custom(mask) => mask,
        }
    }
}

/// Registry key access rights wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryAccess {
    /// KEY_READ.
    Read,
    /// KEY_WRITE.
    Write,
    /// KEY_READ | KEY_WRITE.
    ReadWrite,
    /// KEY_ALL_ACCESS.
    FullControl,
    /// Custom raw mask.
    Custom(AccessMask),
}

impl RegistryAccess {
    /// Convert to generic access mask.
    pub fn to_mask(self) -> AccessMask {
        match self {
            RegistryAccess::Read => AccessMask::from_bits(0x20019),
            RegistryAccess::Write => AccessMask::from_bits(0x20006),
            RegistryAccess::ReadWrite => AccessMask::from_bits(0x2001F),
            RegistryAccess::FullControl => AccessMask::from_bits(0xF003F),
            RegistryAccess::Custom(mask) => mask,
        }
    }
}
