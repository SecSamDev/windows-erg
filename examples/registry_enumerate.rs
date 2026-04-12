//! Registry enumeration example.
//!
//! Demonstrates enumerating subkeys and values in registry keys.
//!
//! Run with: cargo run --example registry_enumerate

use windows_erg::registry::{Hive, RegistryKey};

fn main() -> windows_erg::Result<()> {
    println!("=== Registry Enumeration Example ===\n");

    // Enumerate installed software
    println!("Installed Software (first 10):");
    if let Ok(key) = RegistryKey::open(
        Hive::LocalMachine,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    ) {
        match key.subkeys() {
            Ok(subkeys) => {
                println!("Found {} entries\n", subkeys.len());
                for (i, subkey_name) in subkeys.iter().take(10).enumerate() {
                    println!("  {}. {}", i + 1, subkey_name);
                }
                if subkeys.len() > 10 {
                    println!("  ... and {} more", subkeys.len() - 10);
                }
            }
            Err(e) => println!("Error enumerating: {}", e),
        }
    }

    // Enumerate environment variables
    println!("\n\nSystem Environment Variables:");
    if let Ok(key) = RegistryKey::open(
        Hive::LocalMachine,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    ) {
        match key.value_names() {
            Ok(names) => {
                println!("Found {} variables:\n", names.len());
                for name in names {
                    if let Ok(value) = key.get_value::<String>(&name) {
                        // Truncate long values
                        let display_value = if value.len() > 60 {
                            format!("{}...", &value[..60])
                        } else {
                            value
                        };
                        println!("  {} = {}", name, display_value);
                    }
                }
            }
            Err(e) => println!("Error enumerating: {}", e),
        }
    }

    // Create and enumerate a test key
    println!("\n\nCreating test key with subkeys:");
    let test_path = r"Software\WindowsErg_Enumerate";
    let key = RegistryKey::create(Hive::CurrentUser, test_path)?;

    // Create some subkeys
    RegistryKey::create(Hive::CurrentUser, &format!("{}\\Config", test_path))?;
    RegistryKey::create(Hive::CurrentUser, &format!("{}\\Data", test_path))?;
    RegistryKey::create(Hive::CurrentUser, &format!("{}\\Logs", test_path))?;

    // Add some values
    key.set_value("Value1", "First".to_string())?;
    key.set_value("Value2", 42u32)?;
    key.set_value("Value3", true)?;

    println!("\nSubkeys:");
    for subkey in key.subkeys()? {
        println!("  • {}", subkey);
    }

    println!("\nValues:");
    for value_name in key.value_names()? {
        println!("  • {}", value_name);
    }

    println!("\n✓ Enumeration complete!");

    Ok(())
}
