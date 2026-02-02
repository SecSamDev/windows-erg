//! Basic registry operations example.
//!
//! Demonstrates reading system information from the Windows Registry.
//!
//! Run with: cargo run --example registry_basics

use windows_erg::registry::{Hive, RegistryKey};

fn main() -> windows_erg::Result<()> {
    println!("=== Basic Registry Operations ===\n");

    // Open a well-known registry key
    let key = RegistryKey::open(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    )?;

    // Read various system information
    println!("System Information:");
    
    if let Ok(product_name) = key.get_value::<String>("ProductName") {
        println!("  Product Name: {}", product_name);
    }
    
    if let Ok(build) = key.get_value::<String>("CurrentBuild") {
        println!("  Build Number: {}", build);
    }
    
    if let Ok(edition) = key.get_value::<String>("EditionID") {
        println!("  Edition: {}", edition);
    }

    if let Ok(install_date) = key.get_value::<u32>("InstallDate") {
        // Unix timestamp
        println!("  Install Date (timestamp): {}", install_date);
    }

    println!("\n✓ Successfully read system registry values");
    
    Ok(())
}
