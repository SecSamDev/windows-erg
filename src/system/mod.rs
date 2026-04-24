//! Host system inventory (native Windows API and registry).
//!
//! This module intentionally avoids WMI and uses native APIs plus registry reads.

mod types;

use std::borrow::Cow;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_PREFIX, GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetDiskFreeSpaceExW, GetLogicalDriveStringsW, GetVolumeInformationW, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO};
use windows::Win32::System::SystemInformation::{
    FIRMWARE_TABLE_PROVIDER, GetSystemFirmwareTable, OSVERSIONINFOW,
};
use windows::core::PCWSTR;

use crate::error::{Error, Result, WindowsApiError};
use crate::registry::{self, Hive};
use crate::utils::{OwnedHandle, pwstr_to_string, to_utf16_nul};

pub use types::{
    BiosInfo, GuidInfo, HostIdentity, HostSnapshot, LogicalDiskInfo, MachineGuid,
    NetworkInterfaceInfo, OsInfo, PhysicalDiskInfo, SnapshotSection, SnapshotSectionError,
    UserInfo,
};

/// Collect a host inventory snapshot.
///
/// The snapshot is resilient by design: section failures are recorded in
/// `section_errors` and collection continues.
pub fn snapshot() -> HostSnapshot {
    let mut section_errors = Vec::new();

    let identity = match hostname() {
        Ok(hostname) => HostIdentity { hostname },
        Err(err) => {
            section_errors.push(section_error(SnapshotSection::Identity, err));
            HostIdentity {
                hostname: "unknown".to_string(),
            }
        }
    };

    let os = match os_info() {
        Ok(os) => os,
        Err(err) => {
            section_errors.push(section_error(SnapshotSection::Os, err));
            OsInfo {
                product_name: None,
                release_label: None,
                build_number: 0,
                major_version: 0,
                minor_version: 0,
            }
        }
    };

    let guids = match guid_info() {
        Ok(guids) => guids,
        Err(err) => {
            section_errors.push(section_error(SnapshotSection::Guids, err));
            GuidInfo {
                machine_guid: None,
                firmware_guid: None,
            }
        }
    };

    let bios = match bios_info() {
        Ok(bios) => bios,
        Err(err) => {
            section_errors.push(section_error(SnapshotSection::Bios, err));
            None
        }
    };

    let logical_disks = match logical_disks() {
        Ok(disks) => disks,
        Err(err) => {
            section_errors.push(section_error(SnapshotSection::LogicalDisks, err));
            Vec::new()
        }
    };

    let physical_disks = match physical_disks() {
        Ok(disks) => disks,
        Err(err) => {
            section_errors.push(section_error(SnapshotSection::PhysicalDisks, err));
            Vec::new()
        }
    };

    let networks = match network_interfaces() {
        Ok(interfaces) => interfaces,
        Err(err) => {
            section_errors.push(section_error(SnapshotSection::Network, err));
            Vec::new()
        }
    };

    let users = match users() {
        Ok(users) => users,
        Err(err) => {
            section_errors.push(section_error(SnapshotSection::Users, err));
            Vec::new()
        }
    };

    HostSnapshot {
        identity,
        os,
        guids,
        bios,
        logical_disks,
        physical_disks,
        networks,
        users,
        section_errors,
    }
}

/// Get hostname via native API with environment fallback.
pub fn hostname() -> Result<String> {
    if let Ok(value) = std::env::var("COMPUTERNAME")
        && !value.trim().is_empty() {
            return Ok(value);
        }

    let value = registry::read_string(
        Hive::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
        "ComputerName",
    )?;

    if value.trim().is_empty() {
        return Err(Error::Other(crate::error::OtherError::new(
            "hostname is empty",
        )));
    }

    Ok(value)
}

/// Read OS version and product name.
pub fn os_info() -> Result<OsInfo> {
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };

    query_real_os_version(&mut version)?;

    let product_name = resolve_product_name(
        version.dwMajorVersion,
        version.dwMinorVersion,
        version.dwBuildNumber,
    );

    let release_label = derive_release_label(version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);

    Ok(OsInfo {
        product_name,
        release_label,
        build_number: version.dwBuildNumber,
        major_version: version.dwMajorVersion,
        minor_version: version.dwMinorVersion,
    })
}

fn query_real_os_version(out_version: &mut OSVERSIONINFOW) -> Result<()> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(lpVersionInformation: *mut OSVERSIONINFOW) -> i32;
    }

    let status = unsafe { RtlGetVersion(out_version as *mut OSVERSIONINFOW) };
    if status < 0 {
        return Err(Error::Other(crate::error::OtherError::new(Cow::Owned(
            format!("RtlGetVersion failed with NTSTATUS 0x{status:08X}"),
        ))));
    }

    Ok(())
}

/// Get machine and firmware GUID information.
pub fn guid_info() -> Result<GuidInfo> {
    let machine_guid = machine_guid().ok();
    let firmware_guid = firmware_guid_from_smbios().ok().flatten();

    Ok(GuidInfo {
        machine_guid,
        firmware_guid,
    })
}

/// Read machine GUID from registry.
pub fn machine_guid() -> Result<MachineGuid> {
    let guid = registry::read_string(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Cryptography",
        "MachineGuid",
    )?;

    if guid.trim().is_empty() {
        return Err(Error::Other(crate::error::OtherError::new(
            "MachineGuid registry value is empty",
        )));
    }

    Ok(MachineGuid::new(guid))
}

/// Read BIOS info from registry-provided firmware descriptors.
pub fn bios_info() -> Result<Option<BiosInfo>> {
    let path = r"HARDWARE\DESCRIPTION\System\BIOS";

    let vendor = registry::read_string(Hive::LocalMachine, path, "BIOSVendor").ok();
    let version = registry::read_string(Hive::LocalMachine, path, "BIOSVersion").ok();
    let release_date = registry::read_string(Hive::LocalMachine, path, "BIOSReleaseDate").ok();
    let system_manufacturer =
        registry::read_string(Hive::LocalMachine, path, "SystemManufacturer").ok();
    let system_product_name =
        registry::read_string(Hive::LocalMachine, path, "SystemProductName").ok();

    if vendor.is_none()
        && version.is_none()
        && release_date.is_none()
        && system_manufacturer.is_none()
        && system_product_name.is_none()
    {
        return Ok(None);
    }

    Ok(Some(BiosInfo {
        vendor,
        version,
        release_date,
        system_manufacturer,
        system_product_name,
    }))
}

/// List logical disks.
pub fn logical_disks() -> Result<Vec<LogicalDiskInfo>> {
    let mut out_disks = Vec::with_capacity(16);
    logical_disks_with_filter(&mut out_disks, |_| true)?;
    Ok(out_disks)
}

/// Fill caller-provided logical disk buffer.
pub fn logical_disks_with_buffer(out_disks: &mut Vec<LogicalDiskInfo>) -> Result<usize> {
    logical_disks_with_filter(out_disks, |_| true)
}

/// Fill caller-provided logical disk buffer with in-enumeration filtering.
pub fn logical_disks_with_filter<F>(
    out_disks: &mut Vec<LogicalDiskInfo>,
    filter: F,
) -> Result<usize>
where
    F: Fn(&LogicalDiskInfo) -> bool,
{
    out_disks.clear();

    let mut work_buffer = vec![0u16; 512];
    let chars = unsafe { GetLogicalDriveStringsW(Some(&mut work_buffer)) } as usize;

    if chars == 0 {
        return Err(Error::WindowsApi(WindowsApiError::with_context(
            windows::core::Error::from_win32(),
            "GetLogicalDriveStringsW",
        )));
    }

    if chars > work_buffer.len() {
        work_buffer.resize(chars, 0);
        let second = unsafe { GetLogicalDriveStringsW(Some(&mut work_buffer)) } as usize;
        if second == 0 {
            return Err(Error::WindowsApi(WindowsApiError::with_context(
                windows::core::Error::from_win32(),
                "GetLogicalDriveStringsW",
            )));
        }
    }

    for root in parse_multi_sz(&work_buffer) {
        let root_wide = to_utf16_nul(&root);

        let mut free_bytes_available = 0u64;
        let mut total_bytes = 0u64;
        let mut total_free_bytes = 0u64;

        unsafe {
            GetDiskFreeSpaceExW(
                windows::core::PCWSTR(root_wide.as_ptr()),
                Some(&mut free_bytes_available),
                Some(&mut total_bytes),
                Some(&mut total_free_bytes),
            )
        }
        .map_err(|e| Error::WindowsApi(WindowsApiError::with_context(e, "GetDiskFreeSpaceExW")))?;

        let mut label = vec![0u16; 261];
        let mut fs = vec![0u16; 261];
        let mut serial = 0u32;
        let mut max_comp_len = 0u32;
        let mut flags = 0u32;

        let _ = unsafe {
            GetVolumeInformationW(
                windows::core::PCWSTR(root_wide.as_ptr()),
                Some(&mut label),
                Some(&mut serial),
                Some(&mut max_comp_len),
                Some(&mut flags),
                Some(&mut fs),
            )
        };

        let disk = LogicalDiskInfo {
            root,
            volume_label: first_nul_terminated(&label),
            file_system: first_nul_terminated(&fs),
            total_bytes,
            free_bytes_available,
            total_free_bytes,
        };

        if filter(&disk) {
            out_disks.push(disk);
        }
    }

    Ok(out_disks.len())
}

/// Enumerate physical disks.
///
/// Initial implementation uses a conservative probe and returns disks with known size
/// when available. This can be expanded to richer metadata in follow-up phases.
pub fn physical_disks() -> Result<Vec<PhysicalDiskInfo>> {
    let mut out_disks = Vec::with_capacity(8);
    physical_disks_with_filter(&mut out_disks, |_| true)?;
    Ok(out_disks)
}

/// Fill caller-provided physical disk buffer.
pub fn physical_disks_with_buffer(out_disks: &mut Vec<PhysicalDiskInfo>) -> Result<usize> {
    physical_disks_with_filter(out_disks, |_| true)
}

/// Fill caller-provided physical disk buffer with in-enumeration filtering.
pub fn physical_disks_with_filter<F>(
    out_disks: &mut Vec<PhysicalDiskInfo>,
    filter: F,
) -> Result<usize>
where
    F: Fn(&PhysicalDiskInfo) -> bool,
{
    out_disks.clear();

    for index in 0..64 {
        let path = format!(r"\\.\PhysicalDrive{}", index);
        let path_wide = to_utf16_nul(&path);

        let handle = match unsafe {
            CreateFileW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                windows::Win32::Foundation::GENERIC_READ.0,
                FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        } {
            Ok(handle) => OwnedHandle::new(handle),
            Err(_) => continue,
        };

        let mut length = GET_LENGTH_INFORMATION::default();
        let mut bytes_returned = 0u32;

        let ok = unsafe {
            DeviceIoControl(
                handle.raw(),
                IOCTL_DISK_GET_LENGTH_INFO,
                None,
                0,
                Some(std::ptr::addr_of_mut!(length) as *mut _),
                std::mem::size_of::<GET_LENGTH_INFORMATION>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        }
        .is_ok();

        if !ok {
            continue;
        }

        let disk = PhysicalDiskInfo {
            path,
            size_bytes: length.Length.max(0) as u64,
        };

        if filter(&disk) {
            out_disks.push(disk);
        }
    }

    Ok(out_disks.len())
}

/// Enumerate network interfaces.
///
/// Native adapter traversal (IpHelper) is added in a follow-up patch.
pub fn network_interfaces() -> Result<Vec<NetworkInterfaceInfo>> {
    let mut out_interfaces = Vec::with_capacity(8);
    network_interfaces_with_filter(&mut out_interfaces, |_| true)?;
    Ok(out_interfaces)
}

/// Fill caller-provided network interface buffer.
pub fn network_interfaces_with_buffer(
    out_interfaces: &mut Vec<NetworkInterfaceInfo>,
) -> Result<usize> {
    network_interfaces_with_filter(out_interfaces, |_| true)
}

/// Fill caller-provided network interface buffer with in-enumeration filtering.
pub fn network_interfaces_with_filter<F>(
    out_interfaces: &mut Vec<NetworkInterfaceInfo>,
    filter: F,
) -> Result<usize>
where
    F: Fn(&NetworkInterfaceInfo) -> bool,
{
    out_interfaces.clear();
    let mut buffer_len = 16_384u32;
    let mut work_buffer = vec![0u8; buffer_len as usize];

    let flags = GET_ADAPTERS_ADDRESSES_FLAGS(GAA_FLAG_INCLUDE_PREFIX.0);
    let mut status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            flags,
            None,
            Some(work_buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut buffer_len,
        )
    };

    // ERROR_BUFFER_OVERFLOW
    if status == 111 {
        work_buffer.resize(buffer_len as usize, 0);
        status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(work_buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buffer_len,
            )
        };
    }

    if status != 0 {
        return Err(Error::Other(crate::error::OtherError::new(Cow::Owned(
            format!("GetAdaptersAddresses failed with status {}", status),
        ))));
    }

    let mut adapter_ptr = work_buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    while !adapter_ptr.is_null() {
        let adapter = unsafe { &*adapter_ptr };

        let name = pwstr_to_string(adapter.FriendlyName)
            .or_else(|| pwstr_to_string(adapter.Description))
            .unwrap_or_else(|| "unknown".to_string());

        let mac_address = format_mac(
            &adapter.PhysicalAddress,
            adapter.PhysicalAddressLength as usize,
        );

        let addresses = collect_unicast_addresses(adapter.FirstUnicastAddress);

        let iface = NetworkInterfaceInfo {
            name,
            mac_address,
            addresses,
        };

        if filter(&iface) {
            out_interfaces.push(iface);
        }

        adapter_ptr = adapter.Next;
    }

    Ok(out_interfaces.len())
}

/// Enumerate users from profile list and current process context.
pub fn users() -> Result<Vec<UserInfo>> {
    let mut out_users = Vec::new();
    users_with_filter(&mut out_users, |_| true)?;
    Ok(out_users)
}

/// Fill caller-provided user buffer.
pub fn users_with_buffer(out_users: &mut Vec<UserInfo>) -> Result<usize> {
    users_with_filter(out_users, |_| true)
}

/// Fill caller-provided user buffer with in-enumeration filtering.
pub fn users_with_filter<F>(out_users: &mut Vec<UserInfo>, filter: F) -> Result<usize>
where
    F: Fn(&UserInfo) -> bool,
{
    out_users.clear();

    let mut dedup = HashSet::new();

    if let Ok(username) = std::env::var("USERNAME") {
        let username = username.trim().to_string();
        if !username.is_empty() {
            let user = UserInfo {
                username: username.clone(),
                sid: None,
                source: "current_user",
            };
            if dedup.insert(username) && filter(&user) {
                out_users.push(user);
            }
        }
    }

    let profile_list = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    if let Ok(key) = crate::registry::RegistryKey::open(Hive::LocalMachine, profile_list)
        && let Ok(subkeys) = key.subkeys() {
            for sid in subkeys {
                if let Ok(profile_path) = crate::registry::read_string(
                    Hive::LocalMachine,
                    &format!(r"{}\{}", profile_list, sid),
                    "ProfileImagePath",
                )
                    && let Some(username) = username_from_profile_path(&profile_path) {
                        let user = UserInfo {
                            username: username.clone(),
                            sid: Some(sid),
                            source: "profile_list",
                        };
                        if dedup.insert(username) && filter(&user) {
                            out_users.push(user);
                        }
                    }
            }
        }

    Ok(out_users.len())
}

fn section_error(section: SnapshotSection, err: Error) -> SnapshotSectionError {
    SnapshotSectionError {
        section,
        message: Cow::Owned(err.to_string()),
    }
}

fn derive_release_label(major: u32, minor: u32, build: u32) -> Option<String> {
    match (major, minor) {
        (10, 0) if build >= 22000 => Some("Windows 11".to_string()),
        (10, 0) => Some("Windows 10".to_string()),
        (6, 3) => Some("Windows 8.1".to_string()),
        (6, 2) => Some("Windows 8".to_string()),
        (6, 1) => Some("Windows 7".to_string()),
        _ => None,
    }
}

fn resolve_product_name(major: u32, minor: u32, build: u32) -> Option<String> {
    let current_version_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let registry_name =
        registry::read_string(Hive::LocalMachine, current_version_key, "ProductName").ok();
    let edition_id = registry::read_string(Hive::LocalMachine, current_version_key, "EditionID").ok();
    let installation_type =
        registry::read_string(Hive::LocalMachine, current_version_key, "InstallationType").ok();

    resolve_product_name_from_registry(
        major,
        minor,
        build,
        registry_name,
        edition_id,
        installation_type,
    )
}

fn resolve_product_name_from_registry(
    major: u32,
    minor: u32,
    build: u32,
    registry_name: Option<String>,
    edition_id: Option<String>,
    installation_type: Option<String>,
) -> Option<String> {
    let is_server = is_server_installation(installation_type.as_deref(), edition_id.as_deref());

    // Microsoft often leaves ProductName as "Windows 10 ..." on Windows 11.
    if major == 10 && minor == 0 && build >= 22000 {
        if let Some(name) = registry_name {
            if let Some(rest) = name.strip_prefix("Windows 10") {
                return Some(format!("Windows 11{}", rest));
            }
            return Some(name);
        }

        if let Some(edition_id) = edition_id {
            let edition = normalize_edition_id(&edition_id);
            let family = if is_server {
                "Windows Server"
            } else {
                "Windows 11"
            };
            let edition_suffix = if is_server {
                edition.strip_prefix("Server ").unwrap_or(&edition)
            } else {
                &edition
            };

            if edition.is_empty() {
                return Some(family.to_string());
            }

            return Some(format!("{} {}", family, edition_suffix));
        }

        return Some(if is_server {
            "Windows Server".to_string()
        } else {
            "Windows 11".to_string()
        });
    }

    registry_name
}

fn is_server_installation(installation_type: Option<&str>, edition_id: Option<&str>) -> bool {
    installation_type
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("server"))
        || edition_id
            .map(str::trim)
            .is_some_and(|value| value.starts_with("Server"))
}

fn normalize_edition_id(edition_id: &str) -> String {
    match edition_id.trim() {
        "Core" => "Home".to_string(),
        "Professional" => "Pro".to_string(),
        "EnterpriseS" => "Enterprise LTSC".to_string(),
        "ServerStandard" => "Server Standard".to_string(),
        "ServerDatacenter" => "Server Datacenter".to_string(),
        "IoTEnterprise" => "IoT Enterprise".to_string(),
        value => value.to_string(),
    }
}

fn firmware_guid_from_smbios() -> Result<Option<String>> {
    let provider = FIRMWARE_TABLE_PROVIDER(u32::from_le_bytes(*b"RSMB"));

    let required = unsafe { GetSystemFirmwareTable(provider, 0, None) } as usize;

    if required == 0 {
        return Ok(None);
    }

    let mut work_buffer = vec![0u8; required];
    let written = unsafe { GetSystemFirmwareTable(provider, 0, Some(work_buffer.as_mut_slice())) }
        as usize;

    if written == 0 {
        return Err(Error::WindowsApi(WindowsApiError::with_context(
            windows::core::Error::from_win32(),
            "GetSystemFirmwareTable",
        )));
    }

    if written > work_buffer.len() {
        return Err(Error::Other(crate::error::OtherError::new(
            "GetSystemFirmwareTable returned larger payload than buffer",
        )));
    }

    parse_firmware_uuid_from_raw_smbios(&work_buffer)
}

fn parse_firmware_uuid_from_raw_smbios(work_buffer: &[u8]) -> Result<Option<String>> {
    // Raw SMBIOS data starts with: Used20CallingMethod (1), SMBIOSMajor (1), SMBIOSMinor (1),
    // DmiRevision (1), Length (4), then SMBIOS table bytes.
    if work_buffer.len() < 8 {
        return Ok(None);
    }

    let table_len = u32::from_le_bytes([work_buffer[4], work_buffer[5], work_buffer[6], work_buffer[7]]) as usize;
    if work_buffer.len() < 8 + table_len {
        return Ok(None);
    }

    let mut cursor = 8usize;
    let end = 8 + table_len;

    while cursor + 4 <= end {
        let ty = work_buffer[cursor];
        let len = work_buffer[cursor + 1] as usize;

        if len < 4 || cursor + len > end {
            break;
        }

        if ty == 1 && len >= 0x19 {
            let uuid = &work_buffer[cursor + 8..cursor + 24];
            if let Some(formatted) = format_smbios_uuid(uuid) {
                return Ok(Some(formatted));
            }
        }

        cursor += len;
        while cursor + 1 < end {
            if work_buffer[cursor] == 0 && work_buffer[cursor + 1] == 0 {
                cursor += 2;
                break;
            }
            cursor += 1;
        }
    }

    Ok(None)
}

fn format_smbios_uuid(raw: &[u8]) -> Option<String> {
    if raw.len() != 16 {
        return None;
    }

    // SMBIOS UUID uses mixed endianness for the first 3 fields.
    let d1 = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let d2 = u16::from_le_bytes([raw[4], raw[5]]);
    let d3 = u16::from_le_bytes([raw[6], raw[7]]);

    Some(format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    ))
}

fn parse_multi_sz(work_buffer: &[u16]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;

    for i in 0..work_buffer.len() {
        if work_buffer[i] == 0 {
            if i == start {
                break;
            }
            out.push(String::from_utf16_lossy(&work_buffer[start..i]));
            start = i + 1;
        }
    }

    out
}

fn first_nul_terminated(work_buffer: &[u16]) -> Option<String> {
    let end = work_buffer.iter().position(|c| *c == 0).unwrap_or(work_buffer.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&work_buffer[..end]))
}

fn username_from_profile_path(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches(['\\', '/']);
    let username = trimmed
        .rsplit(['\\', '/'])
        .next()
        .map(str::trim)
        .unwrap_or_default();

    if username.is_empty() {
        None
    } else {
        Some(username.to_string())
    }
}

fn collect_unicast_addresses(
    mut unicast_ptr: *mut windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
) -> Vec<String> {
    let mut addresses = Vec::with_capacity(4);
    let mut dedup = HashSet::new();

    while !unicast_ptr.is_null() {
        let unicast = unsafe { &*unicast_ptr };
        if let Some(value) = sockaddr_to_ip_string(unicast.Address)
            && dedup.insert(value.clone()) {
                addresses.push(value);
            }
        unicast_ptr = unicast.Next;
    }

    addresses
}

fn sockaddr_to_ip_string(socket_address: windows::Win32::Networking::WinSock::SOCKET_ADDRESS) -> Option<String> {
    if socket_address.lpSockaddr.is_null() {
        return None;
    }

    let family = unsafe { (*socket_address.lpSockaddr).sa_family };

    if family == AF_INET {
        let v4 = unsafe { &*(socket_address.lpSockaddr as *const SOCKADDR_IN) };
        let octets = unsafe {
            let b = v4.sin_addr.S_un.S_un_b;
            [b.s_b1, b.s_b2, b.s_b3, b.s_b4]
        };
        return Some(Ipv4Addr::from(octets).to_string());
    }

    if family == AF_INET6 {
        let v6 = unsafe { &*(socket_address.lpSockaddr as *const SOCKADDR_IN6) };
        let bytes = unsafe { v6.sin6_addr.u.Byte };
        return Some(Ipv6Addr::from(bytes).to_string());
    }

    None
}

fn format_mac(bytes: &[u8], len: usize) -> Option<String> {
    if len == 0 || len > bytes.len() {
        return None;
    }

    let mut out = String::new();
    for (i, b) in bytes[..len].iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02x}"));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{
        format_smbios_uuid, parse_multi_sz, resolve_product_name_from_registry,
        username_from_profile_path,
    };

    #[test]
    fn parse_multi_sz_extracts_entries() {
        let data = [
            'C' as u16,
            ':' as u16,
            '\\' as u16,
            0,
            'D' as u16,
            ':' as u16,
            '\\' as u16,
            0,
            0,
        ];
        let drives = parse_multi_sz(&data);
        assert_eq!(drives, vec!["C:\\".to_string(), "D:\\".to_string()]);
    }

    #[test]
    fn username_from_profile_path_parses_tail_component() {
        let value = username_from_profile_path(r"C:\\Users\\alice");
        assert_eq!(value.as_deref(), Some("alice"));
    }

    #[test]
    fn format_smbios_uuid_formats_expected_shape() {
        let raw = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff,
        ];
        let value = format_smbios_uuid(&raw).expect("uuid");
        assert_eq!(value, "00112233-4455-6677-8899-aabbccddeeff");
    }

    #[test]
    fn resolve_product_name_preserves_server_sku_names() {
        let value = resolve_product_name_from_registry(
            10,
            0,
            26100,
            Some("Windows Server 2025 Standard".to_string()),
            Some("ServerStandard".to_string()),
            Some("Server".to_string()),
        );

        assert_eq!(value.as_deref(), Some("Windows Server 2025 Standard"));
    }

    #[test]
    fn resolve_product_name_synthesizes_server_family_from_server_installation() {
        let value = resolve_product_name_from_registry(
            10,
            0,
            26100,
            None,
            Some("ServerStandard".to_string()),
            Some("Server".to_string()),
        );

        assert_eq!(value.as_deref(), Some("Windows Server Standard"));
    }

    #[test]
    fn resolve_product_name_rewrites_windows_10_desktop_name_on_windows_11() {
        let value = resolve_product_name_from_registry(
            10,
            0,
            26100,
            Some("Windows 10 Pro".to_string()),
            Some("Professional".to_string()),
            Some("Client".to_string()),
        );

        assert_eq!(value.as_deref(), Some("Windows 11 Pro"));
    }
}
