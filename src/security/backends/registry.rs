//! Registry security backend.

use crate::Result;
use crate::error::{AccessDeniedError, Error, InvalidParameterError, OtherError, WindowsApiError};
use crate::security::{AccessMask, Ace, AceType, Dacl, InheritanceFlags, SecurityDescriptor, Sid};
use crate::utils::{pwstr_to_string_len, to_utf16_nul};
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_REGISTRY_KEY, SetSecurityInfo,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
    GetSecurityDescriptorGroup, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::System::Registry::{
    HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
    HKEY_USERS, REG_SAM_FLAGS, RegCloseKey, RegOpenKeyExW,
};
use windows::core::{PCWSTR, PWSTR};

const READ_CONTROL_RIGHT: u32 = 0x0002_0000;
const WRITE_DAC_RIGHT: u32 = 0x0004_0000;
const WRITE_OWNER_RIGHT: u32 = 0x0008_0000;

pub(crate) fn read_descriptor(path: &str) -> Result<SecurityDescriptor> {
    let (hive, subkey) = parse_registry_path(path)?;
    let key = open_registry_key(hive, &subkey, READ_CONTROL_RIGHT)?;

    let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
    let get_result = unsafe {
        GetSecurityInfo(
            hkey_as_handle(key.handle),
            SE_REGISTRY_KEY,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut security_descriptor),
        )
    };

    if get_result.0 != 0 {
        return map_registry_security_status(path, "GetSecurityInfo", get_result.0 as i32);
    }

    let mut sddl = PWSTR::null();
    let mut sddl_len = 0u32;

    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut sddl,
            Some(&mut sddl_len),
        )
        .map_err(|e| {
            let _ = LocalFree(HLOCAL(security_descriptor.0));
            Error::WindowsApi(WindowsApiError::with_context(
                e,
                "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            ))
        })?;
    }

    let sddl_str = pwstr_to_string_len(sddl, sddl_len as usize);

    unsafe {
        let _ = LocalFree(HLOCAL(sddl.0 as *mut core::ffi::c_void));
        let _ = LocalFree(HLOCAL(security_descriptor.0));
    }

    sddl_to_descriptor(path, &sddl_str)
}

pub(crate) fn write_descriptor(path: &str, descriptor: &SecurityDescriptor) -> Result<()> {
    let (hive, subkey) = parse_registry_path(path)?;
    let mut desired_access = READ_CONTROL_RIGHT | WRITE_DAC_RIGHT;
    if descriptor.owner().is_some() || descriptor.group().is_some() {
        desired_access |= WRITE_OWNER_RIGHT;
    }
    let key = open_registry_key(hive, &subkey, desired_access)?;

    let sddl = descriptor_to_sddl(descriptor);
    let sddl_wide = to_utf16_nul(&sddl);

    let mut security_descriptor = PSECURITY_DESCRIPTOR::default();
    let mut security_descriptor_size = 0u32;

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut security_descriptor as *mut _,
            Some(&mut security_descriptor_size),
        )
        .map_err(|e| {
            Error::WindowsApi(WindowsApiError::with_context(
                e,
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ))
        })?;
    }

    let mut dacl_present = false.into();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted = false.into();

    unsafe {
        GetSecurityDescriptorDacl(
            security_descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    }
    .map_err(|e| {
        Error::WindowsApi(WindowsApiError::with_context(
            e,
            "GetSecurityDescriptorDacl",
        ))
    })?;

    if !dacl_present.as_bool() || dacl.is_null() {
        unsafe {
            let _ = LocalFree(HLOCAL(security_descriptor.0));
        }
        return Err(Error::Other(OtherError::new(
            "generated security descriptor has no DACL",
        )));
    }

    let mut owner_sid = PSID::default();
    let mut owner_defaulted = false.into();
    unsafe {
        GetSecurityDescriptorOwner(security_descriptor, &mut owner_sid, &mut owner_defaulted)
    }
    .map_err(|e| {
        Error::WindowsApi(WindowsApiError::with_context(
            e,
            "GetSecurityDescriptorOwner",
        ))
    })?;

    let mut group_sid = PSID::default();
    let mut group_defaulted = false.into();
    unsafe {
        GetSecurityDescriptorGroup(security_descriptor, &mut group_sid, &mut group_defaulted)
    }
    .map_err(|e| {
        Error::WindowsApi(WindowsApiError::with_context(
            e,
            "GetSecurityDescriptorGroup",
        ))
    })?;

    let mut security_information = DACL_SECURITY_INFORMATION;
    let mut owner_for_set = PSID::default();
    if descriptor.owner().is_some() {
        if owner_sid.0.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(security_descriptor.0));
            }
            return Err(Error::Other(OtherError::new(
                "generated security descriptor has no owner SID",
            )));
        }
        security_information |= OWNER_SECURITY_INFORMATION;
        owner_for_set = owner_sid;
    }

    let mut group_for_set = PSID::default();
    if descriptor.group().is_some() {
        if group_sid.0.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(security_descriptor.0));
            }
            return Err(Error::Other(OtherError::new(
                "generated security descriptor has no group SID",
            )));
        }
        security_information |= GROUP_SECURITY_INFORMATION;
        group_for_set = group_sid;
    }

    let set_result = unsafe {
        SetSecurityInfo(
            hkey_as_handle(key.handle),
            SE_REGISTRY_KEY,
            security_information,
            owner_for_set,
            group_for_set,
            Some(dacl as *const ACL),
            None,
        )
    };

    unsafe {
        let _ = LocalFree(HLOCAL(security_descriptor.0));
    }

    if set_result.0 != 0 {
        return map_registry_security_status(path, "SetSecurityInfo", set_result.0 as i32);
    }

    Ok(())
}

fn parse_registry_path(path: &str) -> Result<(HKEY, String)> {
    if path.trim().is_empty() {
        return Err(Error::InvalidParameter(InvalidParameterError::new(
            "path",
            "registry path cannot be empty",
        )));
    }

    let normalized = path.replace('/', "\\");
    let upper = normalized.to_ascii_uppercase();

    let mappings: [(&str, HKEY); 10] = [
        ("HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE),
        ("HKLM", HKEY_LOCAL_MACHINE),
        ("HKEY_CURRENT_USER", HKEY_CURRENT_USER),
        ("HKCU", HKEY_CURRENT_USER),
        ("HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT),
        ("HKCR", HKEY_CLASSES_ROOT),
        ("HKEY_USERS", HKEY_USERS),
        ("HKU", HKEY_USERS),
        ("HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG),
        ("HKCC", HKEY_CURRENT_CONFIG),
    ];

    for (prefix, hive) in mappings {
        if upper == prefix {
            return Ok((hive, String::new()));
        }

        let full_prefix = format!("{}\\", prefix);
        if upper.starts_with(&full_prefix) {
            let subkey = normalized[prefix.len() + 1..].to_string();
            return Ok((hive, subkey));
        }
    }

    Err(Error::InvalidParameter(InvalidParameterError::new(
        "path",
        "registry path must start with HKLM/HKCU/HKCR/HKU/HKCC",
    )))
}

fn open_registry_key(hive: HKEY, subkey: &str, sam_desired: u32) -> Result<OpenRegistryKey> {
    let mut key = HKEY::default();
    let subkey_wide = to_utf16_nul(subkey);

    let status = unsafe {
        RegOpenKeyExW(
            hive,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            REG_SAM_FLAGS(sam_desired),
            &mut key,
        )
    };

    if status.0 != 0 {
        return map_registry_security_status(subkey, "RegOpenKeyExW", status.0 as i32);
    }

    Ok(OpenRegistryKey { handle: key })
}

fn hkey_as_handle(hkey: HKEY) -> HANDLE {
    HANDLE(hkey.0)
}

struct OpenRegistryKey {
    handle: HKEY,
}

impl Drop for OpenRegistryKey {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.handle);
        }
    }
}

fn map_registry_security_status<T>(resource: &str, operation: &str, code: i32) -> Result<T> {
    if code == 5 {
        return Err(Error::AccessDenied(AccessDeniedError::with_reason(
            resource.to_string(),
            operation.to_string(),
            "access denied",
        )));
    }

    if code == 1314 {
        return Err(Error::AccessDenied(AccessDeniedError::with_reason(
            resource.to_string(),
            operation.to_string(),
            "required privilege is not held (likely SeRestorePrivilege or SeTakeOwnershipPrivilege)",
        )));
    }

    Err(Error::Other(OtherError::new(format!(
        "Registry security operation '{}' failed on '{}' (error code: 0x{:08X})",
        operation, resource, code
    ))))
}

fn dacl_to_sddl(dacl: &Dacl) -> String {
    let mut sddl = String::from("D:");

    for ace in dacl.entries() {
        let ace_type = match ace.ace_type {
            AceType::Allow => "A",
            AceType::Deny => "D",
        };

        let mut flags = String::new();
        if ace.inheritance.object_inherit {
            flags.push_str("OI");
        }
        if ace.inheritance.container_inherit {
            flags.push_str("CI");
        }
        if ace.inheritance.inherit_only {
            flags.push_str("IO");
        }
        if ace.inheritance.no_propagate_inherit {
            flags.push_str("NP");
        }

        let sid = ace.trustee.as_str();
        let rights = format!("0x{:X}", ace.access_mask.bits());
        sddl.push_str(&format!("({};{};{};;;{})", ace_type, flags, rights, sid));
    }

    sddl
}

fn descriptor_to_sddl(descriptor: &SecurityDescriptor) -> String {
    let mut sddl = String::new();

    if let Some(owner) = descriptor.owner() {
        sddl.push_str("O:");
        sddl.push_str(owner.as_str());
    }

    if let Some(group) = descriptor.group() {
        sddl.push_str("G:");
        sddl.push_str(group.as_str());
    }

    sddl.push_str(&dacl_to_sddl(descriptor.dacl()));
    sddl
}

fn sddl_to_descriptor(path: &str, sddl: &str) -> Result<SecurityDescriptor> {
    let owner = extract_sddl_section(sddl, 'O').and_then(|v| sid_or_alias_to_sid(v).ok());
    let group = extract_sddl_section(sddl, 'G').and_then(|v| sid_or_alias_to_sid(v).ok());
    let dacl = parse_dacl_from_sddl(sddl)?;

    let mut descriptor = SecurityDescriptor::for_registry_path(path.to_string()).with_dacl(dacl);
    if let Some(owner) = owner {
        descriptor = descriptor.with_owner(owner);
    }
    if let Some(group) = group {
        descriptor = descriptor.with_group(group);
    }

    Ok(descriptor)
}

fn parse_dacl_from_sddl(sddl: &str) -> Result<Dacl> {
    let Some(dacl_section) = extract_sddl_section(sddl, 'D') else {
        return Ok(Dacl::new());
    };

    let mut entries = Vec::new();
    let mut index = 0usize;
    while let Some(start_rel) = dacl_section[index..].find('(') {
        let start = index + start_rel;
        let Some(end_rel) = dacl_section[start..].find(')') else {
            break;
        };
        let end = start + end_rel;
        let ace_body = &dacl_section[start + 1..end];
        if let Some(ace) = parse_ace(ace_body)? {
            entries.push(ace);
        }
        index = end + 1;
    }

    let mut dacl = Dacl::from_entries(entries);
    dacl.canonicalize();
    Ok(dacl)
}

fn parse_ace(ace_body: &str) -> Result<Option<Ace>> {
    let fields: Vec<&str> = ace_body.split(';').collect();
    if fields.len() < 6 {
        return Ok(None);
    }

    let ace_type = match fields[0] {
        "A" => AceType::Allow,
        "D" => AceType::Deny,
        _ => return Ok(None),
    };

    let inheritance = parse_inheritance_flags(fields[1]);
    let inherited = fields[1].contains("ID");

    let access_mask = parse_sddl_rights(fields[2])
        .ok_or_else(|| Error::Other(OtherError::new("failed to parse registry ACE access mask")))?;

    let trustee = match sid_or_alias_to_sid(fields[5]) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    Ok(Some(
        Ace::new(trustee, ace_type, access_mask)
            .with_inheritance(inheritance)
            .inherited(inherited),
    ))
}

fn parse_inheritance_flags(value: &str) -> InheritanceFlags {
    InheritanceFlags {
        object_inherit: value.contains("OI"),
        container_inherit: value.contains("CI"),
        inherit_only: value.contains("IO"),
        no_propagate_inherit: value.contains("NP"),
    }
}

fn parse_sddl_rights(value: &str) -> Option<AccessMask> {
    if let Some(hex) = value.strip_prefix("0x") {
        let bits = u32::from_str_radix(hex, 16).ok()?;
        return Some(AccessMask::from_bits(bits));
    }

    let mut mask = AccessMask::from_bits(0);
    let mut i = 0usize;
    while i + 1 < value.len() {
        let token = &value[i..i + 2];
        let token_mask = match token {
            "KA" => AccessMask::from_bits(0xF003F),
            "KR" => AccessMask::from_bits(0x20019),
            "KW" => AccessMask::from_bits(0x20006),
            "KX" => AccessMask::from_bits(0x20019),
            "SD" => AccessMask::from_bits(0x00010000),
            "RC" => AccessMask::from_bits(0x00020000),
            "WD" => AccessMask::from_bits(0x00040000),
            "WO" => AccessMask::from_bits(0x00080000),
            _ => AccessMask::from_bits(0),
        };

        if token_mask.bits() != 0 {
            mask |= token_mask;
        }
        i += 2;
    }

    if mask.bits() == 0 { None } else { Some(mask) }
}

fn sid_or_alias_to_sid(value: &str) -> Result<Sid> {
    Sid::from_sddl_trustee(value)
        .map_err(|_| Error::Other(OtherError::new("unrecognized SID alias")))
}

fn extract_sddl_section(sddl: &str, section: char) -> Option<&str> {
    let marker = format!("{}:", section);
    let start = sddl.find(&marker)? + marker.len();

    let mut end = sddl.len();
    for candidate in ['O', 'G', 'D', 'S'] {
        if candidate == section {
            continue;
        }
        let candidate_marker = format!("{}:", candidate);
        if let Some(pos) = sddl[start..].find(&candidate_marker) {
            end = end.min(start + pos);
        }
    }

    Some(sddl[start..end].trim())
}

#[cfg(test)]
mod tests {
    use super::{
        descriptor_to_sddl, map_registry_security_status, parse_dacl_from_sddl,
        parse_registry_path, sddl_to_descriptor,
    };
    use crate::security::{Dacl, SecurityDescriptor, Sid};

    #[test]
    fn parse_registry_path_supports_short_and_long_hives() {
        assert!(parse_registry_path("HKLM\\SOFTWARE").is_ok());
        assert!(parse_registry_path("HKEY_CURRENT_USER\\Software").is_ok());
        assert!(parse_registry_path("HKCU").is_ok());
        assert!(parse_registry_path("INVALID\\Path").is_err());
    }

    #[test]
    fn sddl_to_descriptor_parses_registry_descriptor() {
        let descriptor = sddl_to_descriptor("HKLM\\SOFTWARE\\Test", "O:SYG:BAD:(A;;KA;;;BA)")
            .expect("descriptor parse");
        assert!(descriptor.owner().is_some());
        assert!(descriptor.group().is_some());
        assert_eq!(descriptor.dacl().entries().len(), 1);
    }

    #[test]
    fn descriptor_to_sddl_includes_owner_and_group_when_present() {
        let owner = Sid::parse("S-1-5-18").expect("valid owner sid");
        let group = Sid::parse("S-1-5-32-544").expect("valid group sid");
        let descriptor = SecurityDescriptor::for_registry_path("HKLM\\SOFTWARE\\Test")
            .with_owner(owner)
            .with_group(group)
            .with_dacl(Dacl::new());

        let sddl = descriptor_to_sddl(&descriptor);
        assert!(sddl.contains("O:S-1-5-18"));
        assert!(sddl.contains("G:S-1-5-32-544"));
        assert!(sddl.contains("D:"));
    }

    #[test]
    fn parse_dacl_marks_inherited_entries() {
        let dacl = parse_dacl_from_sddl("D:(A;OICIID;KA;;;BA)").expect("parse dacl");
        assert_eq!(dacl.entries().len(), 1);
        assert!(dacl.entries()[0].inherited);
        assert!(dacl.entries()[0].inheritance.object_inherit);
        assert!(dacl.entries()[0].inheritance.container_inherit);
    }

    #[test]
    fn parse_dacl_skips_unknown_trustee_alias() {
        let dacl = parse_dacl_from_sddl("D:(A;;KA;;;BA)(A;;KA;;;ZZ)").expect("parse dacl");
        assert_eq!(dacl.entries().len(), 1);
    }

    #[test]
    fn map_registry_security_status_reports_privilege_not_held_as_access_denied() {
        let err = map_registry_security_status::<()>("HKCU\\Software\\x", "SetSecurityInfo", 1314)
            .expect_err("expected privilege error");

        let message = err.to_string();
        assert!(message.contains("required privilege is not held"));
    }
}
