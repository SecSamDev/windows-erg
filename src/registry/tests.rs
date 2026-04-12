//! Registry module tests that work without administrator permissions.
//!
//! These tests use HKEY_CURRENT_USER which doesn't require elevation.
//! Each test uses a unique path to avoid interference.

use super::*;
use crate::security::{AccessMask, ApplyMode, PermissionEditor, Sid};

const TEST_BASE: &str = r"Software\windows_erg_test";

/// Helper to create a unique test path for each test
fn test_path(name: &str) -> String {
    format!("{}\\{}", TEST_BASE, name)
}

/// Helper to clean up a specific test key
fn cleanup(path: &str) {
    let _ = RegistryKey::delete_tree(Hive::CurrentUser, path);
}

#[test]
fn test_create_and_open_key() {
    let path = test_path("create_open");
    cleanup(&path);

    // Create a new key
    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();
    drop(key);

    // Open the same key
    let key = RegistryKey::open(Hive::CurrentUser, &path).unwrap();
    drop(key);

    cleanup(&path);
}

#[test]
fn test_string_value() {
    let path = test_path("string_value");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Write string
    key.set_value("TestString", "Hello, World!".to_string())
        .unwrap();

    // Read string
    let value: String = key.get_value("TestString").unwrap();
    assert_eq!(value, "Hello, World!");

    cleanup(&path);
}

#[test]
fn test_u32_value() {
    let path = test_path("u32_value");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Write u32
    key.set_value("TestU32", 42u32).unwrap();

    // Read u32
    let value: u32 = key.get_value("TestU32").unwrap();
    assert_eq!(value, 42);

    cleanup(&path);
}

#[test]
fn test_u64_value() {
    let path = test_path("u64_value");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Write u64
    key.set_value("TestU64", 0x123456789ABCDEF0u64).unwrap();

    // Read u64
    let value: u64 = key.get_value("TestU64").unwrap();
    assert_eq!(value, 0x123456789ABCDEF0u64);

    cleanup(&path);
}

#[test]
fn test_bool_value() {
    let path = test_path("bool_value");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Test true
    key.set_value("TestBoolTrue", true).unwrap();
    let value: bool = key.get_value("TestBoolTrue").unwrap();
    assert!(value);

    // Test false
    key.set_value("TestBoolFalse", false).unwrap();
    let value: bool = key.get_value("TestBoolFalse").unwrap();
    assert!(!value);

    cleanup(&path);
}

#[test]
fn test_binary_value() {
    let path = test_path("binary_value");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    let data = vec![1u8, 2, 3, 4, 5];
    key.set_value("TestBinary", data.clone()).unwrap();

    let value: Vec<u8> = key.get_value("TestBinary").unwrap();
    assert_eq!(value, data);

    cleanup(&path);
}

#[test]
fn test_multi_string_value() {
    let path = test_path("multi_string_value");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    let strings = vec![
        "First".to_string(),
        "Second".to_string(),
        "Third".to_string(),
    ];
    key.set_value("TestMultiString", strings.clone()).unwrap();

    let value: Vec<String> = key.get_value("TestMultiString").unwrap();
    assert_eq!(value, strings);

    cleanup(&path);
}

#[test]
fn test_value_exists() {
    let path = test_path("value_exists");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Non-existent value
    assert!(!key.value_exists("NonExistent").unwrap());

    // Create a value
    key.set_value("Exists", "yes".to_string()).unwrap();
    assert!(key.value_exists("Exists").unwrap());

    cleanup(&path);
}

#[test]
fn test_try_get_value() {
    let path = test_path("try_get_value");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Try to get non-existent value
    let value: Option<String> = key.try_get_value("NonExistent");
    assert!(value.is_none());

    // Set and try to get
    key.set_value("TestValue", "content".to_string()).unwrap();
    let value: Option<String> = key.try_get_value("TestValue");
    assert_eq!(value, Some("content".to_string()));

    cleanup(&path);
}

#[test]
fn test_get_value_or() {
    let path = test_path("get_value_or");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Get with default for non-existent
    let value = key.get_value_or("NonExistent", 99u32);
    assert_eq!(value, 99);

    // Get with default for existing
    key.set_value("Existing", 42u32).unwrap();
    let value = key.get_value_or("Existing", 99u32);
    assert_eq!(value, 42);

    cleanup(&path);
}

#[test]
fn test_delete_value() {
    let path = test_path("delete_value");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Create and delete value
    key.set_value("ToDelete", "data".to_string()).unwrap();
    assert!(key.value_exists("ToDelete").unwrap());

    key.delete_value("ToDelete").unwrap();
    assert!(!key.value_exists("ToDelete").unwrap());

    cleanup(&path);
}

#[test]
fn test_enumerate_subkeys() {
    let path = test_path("enumerate_subkeys");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Create subkeys
    RegistryKey::create(Hive::CurrentUser, &format!("{}\\SubKey1", path)).unwrap();
    RegistryKey::create(Hive::CurrentUser, &format!("{}\\SubKey2", path)).unwrap();
    RegistryKey::create(Hive::CurrentUser, &format!("{}\\SubKey3", path)).unwrap();

    // Enumerate
    let subkeys = key.subkeys().unwrap();
    assert_eq!(subkeys.len(), 3);
    assert!(subkeys.contains(&"SubKey1".to_string()));
    assert!(subkeys.contains(&"SubKey2".to_string()));
    assert!(subkeys.contains(&"SubKey3".to_string()));

    cleanup(&path);
}

#[test]
fn test_enumerate_value_names() {
    let path = test_path("enumerate_values");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Create values
    key.set_value("Value1", "data1".to_string()).unwrap();
    key.set_value("Value2", 42u32).unwrap();
    key.set_value("Value3", true).unwrap();

    // Enumerate
    let names = key.value_names().unwrap();
    assert_eq!(names.len(), 3);
    assert!(names.contains(&"Value1".to_string()));
    assert!(names.contains(&"Value2".to_string()));
    assert!(names.contains(&"Value3".to_string()));

    cleanup(&path);
}

#[test]
fn test_convenience_read_write_string() {
    let path = test_path("conv_string");
    cleanup(&path);

    // Write using convenience function
    write_string(Hive::CurrentUser, &path, "ConvString", "test").unwrap();

    // Read using convenience function
    let value = read_string(Hive::CurrentUser, &path, "ConvString").unwrap();
    assert_eq!(value, "test");

    cleanup(&path);
}

#[test]
fn test_convenience_read_write_u32() {
    let path = test_path("conv_u32");
    cleanup(&path);

    write_u32(Hive::CurrentUser, &path, "ConvU32", 123).unwrap();
    let value = read_u32(Hive::CurrentUser, &path, "ConvU32").unwrap();
    assert_eq!(value, 123);

    cleanup(&path);
}

#[test]
fn test_convenience_read_write_bool() {
    let path = test_path("conv_bool");
    cleanup(&path);

    write_bool(Hive::CurrentUser, &path, "ConvBool", true).unwrap();
    let value = read_bool(Hive::CurrentUser, &path, "ConvBool").unwrap();
    assert!(value);

    cleanup(&path);
}

#[test]
fn test_builder_pattern() {
    let path = test_path("builder");
    cleanup(&path);

    // Create key for test
    RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Use builder to open with specific options
    let key = RegistryKey::builder()
        .hive(Hive::CurrentUser)
        .path(&path)
        .read()
        .open()
        .unwrap();

    drop(key);

    cleanup(&path);
}

#[test]
fn test_key_not_found_error() {
    // Try to open non-existent key
    let result = RegistryKey::open(Hive::CurrentUser, r"Software\NonExistentKey12345");
    assert!(result.is_err());
}

#[test]
fn test_value_not_found_error() {
    let path = test_path("value_not_found");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();
    let result: Result<String> = key.get_value("NonExistentValue");
    assert!(result.is_err());

    cleanup(&path);
}

#[test]
fn test_type_mismatch_error() {
    let path = test_path("type_mismatch");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Write string
    key.set_value("StringValue", "text".to_string()).unwrap();

    // Try to read as u32
    let result: Result<u32> = key.get_value("StringValue");
    assert!(result.is_err());

    cleanup(&path);
}

#[test]
fn test_delete_key_and_tree() {
    let path = test_path("delete_tree");
    cleanup(&path);

    // Create nested structure
    RegistryKey::create(Hive::CurrentUser, &format!("{}\\Parent\\Child", path)).unwrap();

    // Delete tree
    RegistryKey::delete_tree(Hive::CurrentUser, &path).unwrap();

    // Verify it's gone
    let result = RegistryKey::open(Hive::CurrentUser, &path);
    assert!(result.is_err());
}

#[test]
fn test_read_system_registry() {
    // Test reading from a known system key (doesn't require admin)
    let key = RegistryKey::open(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    )
    .unwrap();

    // ProductName should always exist
    let product: String = key.get_value("ProductName").unwrap();
    assert!(!product.is_empty());
}

#[test]
fn test_multiple_operations() {
    let path = test_path("multiple_ops");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    // Mix of operations
    key.set_value("String1", "value1".to_string()).unwrap();
    key.set_value("Number1", 100u32).unwrap();
    key.set_value("Binary1", vec![1u8, 2, 3]).unwrap();

    assert_eq!(key.get_value::<String>("String1").unwrap(), "value1");
    assert_eq!(key.get_value::<u32>("Number1").unwrap(), 100);
    assert_eq!(key.get_value::<Vec<u8>>("Binary1").unwrap(), vec![1, 2, 3]);

    // Update existing
    key.set_value("Number1", 200u32).unwrap();
    assert_eq!(key.get_value::<u32>("Number1").unwrap(), 200);

    cleanup(&path);
}

#[test]
fn test_registry_key_security_descriptor_round_trip() {
    let path = test_path("security_descriptor_round_trip");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();
    let descriptor = key.security_descriptor().unwrap();
    key.set_security_descriptor(&descriptor).unwrap();

    cleanup(&path);
}

#[test]
fn test_registry_key_apply_permissions_dry_run() {
    let path = test_path("security_apply_permissions_dry_run");
    cleanup(&path);

    let key = RegistryKey::create(Hive::CurrentUser, &path).unwrap();
    let sid = Sid::parse("S-1-5-32-545").unwrap();
    let plan = PermissionEditor::new()
        .grant(sid, AccessMask::from_bits(0x20019))
        .build()
        .unwrap();

    let result = key.apply_permissions(&plan, ApplyMode::DryRunDiff).unwrap();
    assert_eq!(result.diff.added.len(), 1);

    cleanup(&path);
}

#[test]
fn test_registry_security_convenience_read_write() {
    let path = test_path("security_convenience_read_write");
    cleanup(&path);

    RegistryKey::create(Hive::CurrentUser, &path).unwrap();

    let descriptor = read_security_descriptor(Hive::CurrentUser, &path).unwrap();
    write_security_descriptor(Hive::CurrentUser, &path, &descriptor).unwrap();

    cleanup(&path);
}
