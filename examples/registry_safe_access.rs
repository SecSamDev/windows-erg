//! Safe registry access patterns.
//!
//! Demonstrates safe ways to handle potentially missing keys and values.
//!
//! Run with: cargo run --example registry_safe_access

use windows_erg::registry::{Hive, RegistryKey};

fn main() -> windows_erg::Result<()> {
    println!("=== Safe Registry Access Patterns ===\n");

    let test_path = r"Software\WindowsErg_SafeAccess";
    let key = RegistryKey::create(Hive::CurrentUser, test_path)?;

    // Set some values
    key.set_value("ExistingValue", "Hello".to_string())?;
    key.set_value("Count", 100u32)?;

    // Pattern 1: Check if value exists before reading
    println!("Pattern 1: Check existence first");
    if key.value_exists("ExistingValue")? {
        let value: String = key.get_value("ExistingValue")?;
        println!("  ✓ Value exists: {}", value);
    }

    if !key.value_exists("NonExistentValue")? {
        println!("  ✓ NonExistentValue doesn't exist (as expected)");
    }

    // Pattern 2: Use try_get_value (returns Option)
    println!("\nPattern 2: Use try_get_value (returns Option)");
    if let Some(value) = key.try_get_value::<String>("ExistingValue") {
        println!("  ✓ Got value: {}", value);
    } else {
        println!("  Value doesn't exist");
    }

    match key.try_get_value::<String>("NonExistentValue") {
        Some(v) => println!("  Got value: {}", v),
        None => println!("  ✓ NonExistentValue returned None (as expected)"),
    }

    // Pattern 3: Use get_value_or with defaults
    println!("\nPattern 3: Use get_value_or with defaults");
    let count = key.get_value_or("Count", 0u32);
    println!("  Count: {} (from registry)", count);

    let default_value = key.get_value_or("MissingValue", 999u32);
    println!("  MissingValue: {} (default used)", default_value);

    // Pattern 4: Graceful key opening
    println!("\nPattern 4: Graceful key opening");
    match RegistryKey::open(Hive::CurrentUser, r"Software\NonExistentKey12345") {
        Ok(_key) => println!("  Key exists"),
        Err(_e) => println!("  ✓ Key doesn't exist (handled gracefully)"),
    }

    // Pattern 5: Type-safe value access with error handling
    println!("\nPattern 5: Type-safe access with proper error handling");
    
    key.set_value("StringValue", "text".to_string())?;
    
    // Correct type
    match key.get_value::<String>("StringValue") {
        Ok(s) => println!("  ✓ String value: {}", s),
        Err(e) => println!("  Error: {}", e),
    }
    
    // Wrong type (will error gracefully)
    match key.get_value::<u32>("StringValue") {
        Ok(n) => println!("  Number: {}", n),
        Err(_e) => println!("  ✓ Type mismatch caught (expected u32, got string)"),
    }

    // Pattern 6: Builder pattern for safer key opening
    println!("\nPattern 6: Builder pattern with controlled access");
    match RegistryKey::builder()
        .hive(Hive::CurrentUser)
        .path(test_path)
        .read()  // Read-only access
        .open()
    {
        Ok(readonly_key) => {
            println!("  ✓ Opened with read-only access");
            if let Some(value) = readonly_key.try_get_value::<String>("ExistingValue") {
                println!("  Value: {}", value);
            }
        }
        Err(e) => println!("  Error: {}", e),
    }

    println!("\n✓ All safe access patterns demonstrated!");
    
    Ok(())
}
