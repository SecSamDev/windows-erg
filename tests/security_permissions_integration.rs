#![cfg(windows)]

use windows_erg::file;
use windows_erg::registry::{self, Hive, RegistryKey};
use windows_erg::security::{
    AccessMask, AceType, ApplyMode, PermissionEditor, PermissionTarget, Sid,
};
use windows_erg::{Error, error::OtherError};

#[test]
fn file_descriptor_round_trip_read_write() -> windows_erg::Result<()> {
    let path = std::env::temp_dir().join("windows_erg_security_roundtrip.txt");
    std::fs::write(&path, b"security test").map_err(|e| {
        Error::Other(OtherError::new(format!(
            "failed to create temp file: {}",
            e
        )))
    })?;

    let target = PermissionTarget::file(path.to_string_lossy().to_string());
    let descriptor = target.read_descriptor()?;
    target.write_descriptor(&descriptor)?;
    let descriptor_after_write = target.read_descriptor()?;

    assert_eq!(descriptor.owner(), descriptor_after_write.owner());
    assert_eq!(descriptor.group(), descriptor_after_write.group());

    let plan = PermissionEditor::new().build()?;
    let result = plan.execute_against_target(&target, ApplyMode::DryRunDiff)?;
    assert!(result.diff.added.is_empty());
    assert!(result.diff.removed.is_empty());

    std::fs::remove_file(path).map_err(|e| {
        Error::Other(OtherError::new(format!(
            "failed to cleanup temp file: {}",
            e
        )))
    })?;
    Ok(())
}

#[test]
fn registry_descriptor_round_trip_read_write() -> windows_erg::Result<()> {
    let key_path = format!("Software\\windows-erg-security-test-{}", std::process::id());

    let _key = RegistryKey::create(Hive::CurrentUser, &key_path)?;

    let target_path = format!("HKCU\\{}", key_path);
    let target = PermissionTarget::registry(target_path);

    let descriptor = target.read_descriptor()?;
    target.write_descriptor(&descriptor)?;
    let descriptor_after_write = target.read_descriptor()?;

    assert_eq!(descriptor.owner(), descriptor_after_write.owner());
    assert_eq!(descriptor.group(), descriptor_after_write.group());

    let plan = PermissionEditor::new().build()?;
    let result = plan.execute_against_target(&target, ApplyMode::ValidateOnly)?;
    assert!(result.diff.added.is_empty());
    assert!(result.diff.removed.is_empty());

    RegistryKey::delete_tree(Hive::CurrentUser, &key_path)?;
    Ok(())
}

#[test]
fn file_descriptor_apply_grant_and_revoke_round_trip() -> windows_erg::Result<()> {
    let path = std::env::temp_dir().join("windows_erg_security_apply_revoke.txt");
    std::fs::write(&path, b"security apply revoke").map_err(|e| {
        Error::Other(OtherError::new(format!(
            "failed to create temp file: {}",
            e
        )))
    })?;

    let target = PermissionTarget::file(path.to_string_lossy().to_string());
    let baseline = target.read_descriptor()?;

    let users = Sid::parse("S-1-5-32-545")?;
    let access = AccessMask::from_bits(0x0002_0000);

    let grant_plan = PermissionEditor::new()
        .grant(users.clone(), access)
        .build()?;
    let grant_result = grant_plan.execute_against_target(&target, ApplyMode::Apply)?;
    assert!(grant_result.updated_descriptor.is_some());
    assert!(grant_result.diff.added.iter().any(|ace| {
        ace.trustee == users && ace.access_mask == access && ace.ace_type == AceType::Allow
    }));

    let after_grant = target.read_descriptor()?;
    assert!(after_grant.dacl().entries().iter().any(|ace| {
        ace.trustee == users && ace.access_mask == access && ace.ace_type == AceType::Allow
    }));

    let revoke_plan = PermissionEditor::new()
        .revoke(users.clone(), Some(access))
        .build()?;
    let revoke_result = revoke_plan.execute_against_target(&target, ApplyMode::Apply)?;
    assert!(revoke_result.diff.removed.iter().any(|ace| {
        ace.trustee == users && ace.access_mask == access && ace.ace_type == AceType::Allow
    }));

    target.write_descriptor(&baseline)?;
    std::fs::remove_file(path).map_err(|e| {
        Error::Other(OtherError::new(format!(
            "failed to cleanup temp file: {}",
            e
        )))
    })?;

    Ok(())
}

#[test]
fn registry_descriptor_apply_grant_and_restore() -> windows_erg::Result<()> {
    let key_path = format!(
        "Software\\windows-erg-security-apply-{}",
        std::process::id()
    );
    let _key = RegistryKey::create(Hive::CurrentUser, &key_path)?;

    let target_path = format!("HKCU\\{}", key_path);
    let target = PermissionTarget::registry(target_path);
    let baseline = target.read_descriptor()?;

    let users = Sid::parse("S-1-5-32-545")?;
    let access = AccessMask::from_bits(0x0002_0000);

    let plan = PermissionEditor::new()
        .grant(users.clone(), access)
        .build()?;
    let apply_result = plan.execute_against_target(&target, ApplyMode::Apply)?;
    assert!(apply_result.updated_descriptor.is_some());

    let after_apply = target.read_descriptor()?;
    assert!(after_apply.dacl().entries().iter().any(|ace| {
        ace.trustee == users && ace.access_mask == access && ace.ace_type == AceType::Allow
    }));

    target.write_descriptor(&baseline)?;
    RegistryKey::delete_tree(Hive::CurrentUser, &key_path)?;
    Ok(())
}

#[test]
fn file_security_convenience_round_trip() -> windows_erg::Result<()> {
    let path = std::env::temp_dir().join("windows_erg_security_file_convenience.txt");
    std::fs::write(&path, b"security convenience").map_err(|e| {
        Error::Other(OtherError::new(format!(
            "failed to create temp file: {}",
            e
        )))
    })?;

    let descriptor = file::read_security_descriptor(&path)?;
    file::write_security_descriptor(&path, &descriptor)?;

    std::fs::remove_file(path).map_err(|e| {
        Error::Other(OtherError::new(format!(
            "failed to cleanup temp file: {}",
            e
        )))
    })?;

    Ok(())
}

#[test]
fn registry_security_convenience_apply_permissions_dry_run() -> windows_erg::Result<()> {
    let key_path = format!(
        "Software\\windows-erg-security-convenience-{}",
        std::process::id()
    );
    let _key = RegistryKey::create(Hive::CurrentUser, &key_path)?;

    let users = Sid::parse("S-1-5-32-545")?;
    let plan = PermissionEditor::new()
        .grant(users, AccessMask::from_bits(0x20019))
        .build()?;

    let result =
        registry::apply_permissions(Hive::CurrentUser, &key_path, &plan, ApplyMode::DryRunDiff)?;
    assert_eq!(result.diff.added.len(), 1);

    RegistryKey::delete_tree(Hive::CurrentUser, &key_path)?;
    Ok(())
}
