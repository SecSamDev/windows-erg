//! Registry write operations example.
//!
//! Demonstrates creating keys and writing different value types.
//! Uses HKEY_CURRENT_USER so no admin privileges required.
//!
//! Run with: cargo run --example registry_write

use windows_erg::registry::{Hive, RegistryKey};

fn main() -> windows_erg::Result<()> {
    println!("=== Registry Write Example ===\n");

    let test_path = r"Software\WindowsErg_Example";

    // Create or open a key
    println!("Creating test key: HKEY_CURRENT_USER\\{}", test_path);
    let key = RegistryKey::create(Hive::CurrentUser, test_path)?;
    println!("✓ Key created/opened\n");

    // Write different value types
    println!("Writing values:");

    key.set_value("AppName", "windows-erg".to_string())?;
    println!("  ✓ String value written");

    key.set_value("Version", 1u32)?;
    println!("  ✓ DWORD (u32) value written");

    key.set_value("BuildNumber", 12345u64)?;
    println!("  ✓ QWORD (u64) value written");

    key.set_value("IsEnabled", true)?;
    println!("  ✓ Boolean value written");

    key.set_value("BinaryData", vec![0xDE, 0xAD, 0xBE, 0xEF])?;
    println!("  ✓ Binary data written");

    key.set_value(
        "PathList",
        vec![
            "C:\\Program Files".to_string(),
            "C:\\Windows".to_string(),
            "C:\\Users".to_string(),
        ],
    )?;
    println!("  ✓ Multi-string value written");

    // Read them back to verify
    println!("\nReading values back:");
    println!("  AppName: {}", key.get_value::<String>("AppName")?);
    println!("  Version: {}", key.get_value::<u32>("Version")?);
    println!("  BuildNumber: {}", key.get_value::<u64>("BuildNumber")?);
    println!("  IsEnabled: {}", key.get_value::<bool>("IsEnabled")?);
    println!(
        "  BinaryData: {:02X?}",
        key.get_value::<Vec<u8>>("BinaryData")?
    );
    println!(
        "  PathList: {:?}",
        key.get_value::<Vec<String>>("PathList")?
    );

    println!("\n✓ All operations successful!");
    println!(
        "\nNote: To clean up, run: reg delete HKCU\\{} /f",
        test_path
    );

    Ok(())
}
