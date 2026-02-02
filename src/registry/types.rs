//! Registry type definitions (Hive, Access, Wow64View).

use windows::Win32::System::Registry::*;

/// Registry hive identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    /// HKEY_CLASSES_ROOT
    ClassesRoot,
    /// HKEY_CURRENT_USER
    CurrentUser,
    /// HKEY_LOCAL_MACHINE
    LocalMachine,
    /// HKEY_USERS
    Users,
    /// HKEY_CURRENT_CONFIG
    CurrentConfig,
}

impl Hive {
    pub(crate) fn as_hkey(&self) -> HKEY {
        match self {
            Hive::ClassesRoot => HKEY_CLASSES_ROOT,
            Hive::CurrentUser => HKEY_CURRENT_USER,
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
            Hive::Users => HKEY_USERS,
            Hive::CurrentConfig => HKEY_CURRENT_CONFIG,
        }
    }
}

/// Access rights for registry keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read-only access
    Read,
    /// Write-only access
    Write,
    /// Read and write access
    ReadWrite,
    /// All access rights
    AllAccess,
}

impl Access {
    pub(crate) fn to_sam_flags(self) -> u32 {
        match self {
            Access::Read => KEY_READ.0,
            Access::Write => KEY_WRITE.0,
            Access::ReadWrite => KEY_READ.0 | KEY_WRITE.0,
            Access::AllAccess => KEY_ALL_ACCESS.0,
        }
    }
}

/// WOW64 registry view options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wow64View {
    /// 32-bit registry view
    Key32,
    /// 64-bit registry view
    Key64,
}

impl Wow64View {
    pub(crate) fn to_sam_flags(self) -> u32 {
        match self {
            Wow64View::Key32 => 0x0200, // KEY_WOW64_32KEY
            Wow64View::Key64 => 0x0100, // KEY_WOW64_64KEY
        }
    }
}
