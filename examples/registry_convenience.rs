//! Convenience functions example.
//!
//! Demonstrates quick one-off registry operations without explicit key handling.
//!
//! Run with: cargo run --example registry_convenience

use windows_erg::registry::{self, Hive};

fn main() -> windows_erg::Result<()> {
    println!("=== Registry Convenience Functions ===\n");
    
    let test_path = r"Software\WindowsErg_Convenience";

    // Quick write operations - no need to open/close keys
    println!("Writing values using convenience functions:");
    
    registry::write_string(Hive::CurrentUser, test_path, "Name", "Test App")?;
    println!("  ✓ String written");
    
    registry::write_u32(Hive::CurrentUser, test_path, "Count", 42)?;
    println!("  ✓ DWORD written");
    
    registry::write_u64(Hive::CurrentUser, test_path, "LargeNumber", 9876543210)?;
    println!("  ✓ QWORD written");
    
    registry::write_bool(Hive::CurrentUser, test_path, "Active", true)?;
    println!("  ✓ Boolean written");
    
    registry::write_binary(Hive::CurrentUser, test_path, "Data", &[1, 2, 3, 4, 5])?;
    println!("  ✓ Binary written");

    // Quick read operations
    println!("\nReading values back:");
    
    let name = registry::read_string(Hive::CurrentUser, test_path, "Name")?;
    println!("  Name: {}", name);
    
    let count = registry::read_u32(Hive::CurrentUser, test_path, "Count")?;
    println!("  Count: {}", count);
    
    let large = registry::read_u64(Hive::CurrentUser, test_path, "LargeNumber")?;
    println!("  LargeNumber: {}", large);
    
    let active = registry::read_bool(Hive::CurrentUser, test_path, "Active")?;
    println!("  Active: {}", active);
    
    let data = registry::read_binary(Hive::CurrentUser, test_path, "Data")?;
    println!("  Data: {:?}", data);

    println!("\n✓ Convenience functions are perfect for quick operations!");
    
    Ok(())
}
