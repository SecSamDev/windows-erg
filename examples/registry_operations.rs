//! Example: Registry operations
//!
//! This example demonstrates the ergonomic ways to interact with Windows Registry.
//!
//! Usage:
//!     cargo run --example registry_operations

use windows_erg::registry::{self, Hive, RegistryKey};

fn main() -> windows_erg::Result<()> {
    println!("=== Windows Registry Operations Example ===\n");
    println!("This example showcases various ergonomic ways to interact with the registry.\n");

    // ========== Method 1: Traditional Key Opening ==========
    println!("--- Method 1: Traditional Key Opening ---");

    if let Ok(key) = RegistryKey::open(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    ) {
        if let Ok(product_name) = key.get_value::<String>("ProductName") {
            println!("Windows Version: {}", product_name);
        }

        if let Ok(build) = key.get_value::<String>("CurrentBuild") {
            println!("Build Number: {}", build);
        }

        if let Ok(edition) = key.get_value::<String>("EditionID") {
            println!("Edition: {}", edition);
        }
    }

    // ========== Method 2: Convenience Functions (Quickest!) ==========
    println!("\n--- Method 2: Convenience Functions ---");
    println!("(No need to open keys explicitly!)");

    match registry::read_string(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "ProductName",
    ) {
        Ok(name) => println!("Product Name: {}", name),
        Err(e) => println!("Failed to read: {}", e),
    }

    // ========== Method 3: Builder Pattern for Advanced Control ==========
    println!("\n--- Method 3: Builder Pattern ---");

    if let Ok(key) = RegistryKey::builder()
        .hive(Hive::LocalMachine)
        .path(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
        .read()
        .open()
        && let Ok(path) = key.get_value::<String>("Path")
    {
        println!("System PATH length: {} characters", path.len());
    }

    // ========== Method 4: Safe Value Checking ==========
    println!("\n--- Method 4: Safe Value Checking ---");

    let test_key_path = r"Software\WindowsErgTest";
    match RegistryKey::create(Hive::CurrentUser, test_key_path) {
        Ok(key) => {
            println!("✓ Created/Opened test key: {}", test_key_path);

            // Write various types
            key.set_value("TestString", "Hello, Registry!".to_string())?;
            key.set_value("TestDWORD", 42u32)?;
            key.set_value("TestQWORD", 9223372036854775807u64)?;
            key.set_value("TestBool", true)?;
            key.set_value("TestBinary", vec![0xDE, 0xAD, 0xBE, 0xEF])?;
            key.set_value(
                "TestMultiString",
                vec![
                    "First Line".to_string(),
                    "Second Line".to_string(),
                    "Third Line".to_string(),
                ],
            )?;

            println!("✓ Written test values");

            // Check if value exists before reading
            if key.value_exists("TestString")? {
                println!("\n✓ TestString exists");
            }

            // Use try_get for optional values
            if let Some(s) = key.try_get_value::<String>("TestString") {
                println!("  TestString = {}", s);
            }

            if let Some(d) = key.try_get_value::<u32>("TestDWORD") {
                println!("  TestDWORD = {}", d);
            }

            if let Some(q) = key.try_get_value::<u64>("TestQWORD") {
                println!("  TestQWORD = {}", q);
            }

            if let Some(b) = key.try_get_value::<bool>("TestBool") {
                println!("  TestBool = {}", b);
            }

            if let Some(bin) = key.try_get_value::<Vec<u8>>("TestBinary") {
                println!("  TestBinary = {:02X?}", bin);
            }

            if let Some(multi) = key.try_get_value::<Vec<String>>("TestMultiString") {
                println!("  TestMultiString = {:?}", multi);
            }

            // Get value with default
            let non_existent = key.get_value_or("DoesNotExist", 999u32);
            println!("\n  get_value_or('DoesNotExist', 999) = {}", non_existent);

            // Enumerate all values
            println!("\nAll values in key:");
            if let Ok(names) = key.value_names() {
                for name in names {
                    println!("  • {}", name);
                }
            }
        }
        Err(e) => {
            println!("✗ Failed to create test key: {}", e);
        }
    }

    // ========== Method 5: Quick Write with Convenience Functions ==========
    println!("\n--- Method 5: Quick Write Operations ---");

    // Write values without explicitly opening keys
    registry::write_string(
        Hive::CurrentUser,
        r"Software\WindowsErgTest\QuickWrite",
        "AppName",
        "windows-erg",
    )?;

    registry::write_u32(
        Hive::CurrentUser,
        r"Software\WindowsErgTest\QuickWrite",
        "RunCount",
        1,
    )?;

    registry::write_bool(
        Hive::CurrentUser,
        r"Software\WindowsErgTest\QuickWrite",
        "Enabled",
        true,
    )?;

    println!("✓ Written values using convenience functions");

    // Read them back
    if let Ok(app_name) = registry::read_string(
        Hive::CurrentUser,
        r"Software\WindowsErgTest\QuickWrite",
        "AppName",
    ) {
        println!("  AppName = {}", app_name);
    }

    if let Ok(count) = registry::read_u32(
        Hive::CurrentUser,
        r"Software\WindowsErgTest\QuickWrite",
        "RunCount",
    ) {
        println!("  RunCount = {}", count);
    }

    // ========== Enumerate Installed Software ==========
    println!("\n--- Enumerating Installed Software ---");
    if let Ok(key) = RegistryKey::open(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ) && let Ok(subkeys) = key.subkeys()
    {
        println!("Found {} installed applications", subkeys.len());

        // Show first few
        for (i, subkey) in subkeys.iter().take(5).enumerate() {
            println!("  {}. {}", i + 1, subkey);
        }
        if subkeys.len() > 5 {
            println!("  ... and {} more", subkeys.len() - 5);
        }
    }

    // ========== Summary ==========
    println!("\n=== Ergonomics Summary ===");
    println!("1. Traditional: key.get_value() - Full control");
    println!("2. Convenience: registry::read_*() - Quickest for one-off reads/writes");
    println!("3. Builder: RegistryKey::builder() - Advanced options (WOW64, access rights)");
    println!("4. Safe checking: try_get_value() and value_exists() - No unwrap needed");
    println!(
        "5. Type safety: Strongly typed values (String, u32, u64, bool, Vec<u8>, Vec<String>)"
    );

    println!("\n✓ All registry operations completed successfully");
    Ok(())
}
