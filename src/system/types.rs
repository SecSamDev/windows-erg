//! Types for host system inventory.

use std::borrow::Cow;

/// Strongly-typed machine GUID value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MachineGuid(String);

impl MachineGuid {
    /// Create a new machine GUID wrapper.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Return GUID as string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into owned string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

/// Snapshot section identifier used for partial-result reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnapshotSection {
    /// Host identity details (hostname).
    Identity,
    /// Operating system details.
    Os,
    /// GUID values (machine/firmware).
    Guids,
    /// BIOS details.
    Bios,
    /// Logical volumes.
    LogicalDisks,
    /// Physical disks.
    PhysicalDisks,
    /// Network interfaces.
    Network,
    /// User/account inventory.
    Users,
}

/// Section-level error recorded during snapshot collection.
#[derive(Debug, Clone)]
pub struct SnapshotSectionError {
    /// Section that failed.
    pub section: SnapshotSection,
    /// Human-readable failure message.
    pub message: Cow<'static, str>,
}

/// Top-level host inventory snapshot.
#[derive(Debug, Clone)]
pub struct HostSnapshot {
    /// Host identity details.
    pub identity: HostIdentity,
    /// Operating system details.
    pub os: OsInfo,
    /// GUID values.
    pub guids: GuidInfo,
    /// BIOS/firmware details when available.
    pub bios: Option<BiosInfo>,
    /// Logical volume inventory.
    pub logical_disks: Vec<LogicalDiskInfo>,
    /// Physical disk inventory.
    pub physical_disks: Vec<PhysicalDiskInfo>,
    /// Network interface inventory.
    pub networks: Vec<NetworkInterfaceInfo>,
    /// User/account inventory.
    pub users: Vec<UserInfo>,
    /// Per-section failures captured while building this snapshot.
    pub section_errors: Vec<SnapshotSectionError>,
}

/// Host identity data.
#[derive(Debug, Clone)]
pub struct HostIdentity {
    /// NetBIOS/DNS hostname.
    pub hostname: String,
}

/// OS details.
#[derive(Debug, Clone)]
pub struct OsInfo {
    /// Marketing name when available (for example: Windows 11 Pro).
    pub product_name: Option<String>,
    /// Semantic label derived from major/minor/build mapping.
    pub release_label: Option<String>,
    /// Build number.
    pub build_number: u32,
    /// Major version.
    pub major_version: u32,
    /// Minor version.
    pub minor_version: u32,
}

/// GUID values discovered from host sources.
#[derive(Debug, Clone)]
pub struct GuidInfo {
    /// Registry machine GUID.
    pub machine_guid: Option<MachineGuid>,
    /// Firmware/system UUID when available from SMBIOS.
    pub firmware_guid: Option<String>,
}

/// BIOS summary information.
#[derive(Debug, Clone)]
pub struct BiosInfo {
    /// BIOS vendor.
    pub vendor: Option<String>,
    /// BIOS version string.
    pub version: Option<String>,
    /// BIOS release date string.
    pub release_date: Option<String>,
    /// System manufacturer from firmware descriptors.
    pub system_manufacturer: Option<String>,
    /// System product name from firmware descriptors.
    pub system_product_name: Option<String>,
}

/// Logical disk information.
#[derive(Debug, Clone)]
pub struct LogicalDiskInfo {
    /// Drive root path (for example: C:\\).
    pub root: String,
    /// Volume label when available.
    pub volume_label: Option<String>,
    /// File system type when available.
    pub file_system: Option<String>,
    /// Total size in bytes.
    pub total_bytes: u64,
    /// Free bytes available to caller.
    pub free_bytes_available: u64,
    /// Total free bytes on volume.
    pub total_free_bytes: u64,
}

/// Physical disk information.
#[derive(Debug, Clone)]
pub struct PhysicalDiskInfo {
    /// Physical disk path (for example: \\.\\PhysicalDrive0).
    pub path: String,
    /// Disk size in bytes when available.
    pub size_bytes: u64,
}

/// Network interface information.
#[derive(Debug, Clone)]
pub struct NetworkInterfaceInfo {
    /// Interface display name.
    pub name: String,
    /// MAC address in canonical form when available.
    pub mac_address: Option<String>,
    /// IPv4/IPv6 addresses.
    pub addresses: Vec<String>,
}

/// User/account information.
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Username.
    pub username: String,
    /// Optional SID string.
    pub sid: Option<String>,
    /// Data source label (for example: profile_list/current_user).
    pub source: &'static str,
}
