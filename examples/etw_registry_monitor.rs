//! ETW Registry Monitoring Example
//!
//! Demonstrates real-time Windows Registry monitoring using ETW.
//!
//! This example shows how to:
//! - Monitor registry key/value operations
//! - Filter for specific registry events
//! - Process events with buffer reuse for efficiency
//!
//! # Usage
//!
//! ```shell
//! # Run as Administrator (ETW requires elevated privileges)
//! cargo run --example etw_registry_monitor
//! ```
//!
//! # Event IDs (Registry Provider)
//!
//! Common registry event IDs:
//! - 10: RegCreateKey
//! - 11: RegOpenKey
//! - 12: RegDeleteKey
//! - 13: RegQueryValue
//! - 14: RegSetValue
//! - 15: RegDeleteValue
//! - 16: RegQueryMultipleValue
//! - 17: RegEnumerateKey
//! - 18: RegEnumerateValueKey

use windows_erg::etw::{EventTrace, SystemProvider};

fn main() -> windows_erg::Result<()> {
    println!("Starting ETW Registry Monitor...");
    println!("Press Ctrl+C to stop\n");

    // Create and start ETW session for registry monitoring
    let mut trace = EventTrace::builder("RegistryMonitor")
        .system_provider(SystemProvider::Registry)
        .buffer_size(256) // Larger buffers for registry events
        .min_buffers(10)
        .max_buffers(30)
        .flush_interval(1)
        .start()?;

    println!("✓ ETW session started: {}", trace.name());
    println!("✓ Monitoring registry operations\n");

    // Event processing loop with filtering
    let mut events = Vec::with_capacity(200);
    loop {
        // Filter for create/delete/set operations only
        match trace.next_batch_with_filter(&mut events, |event| {
            matches!(event.id, 10 | 12 | 14 | 15) // Create, Delete, Set, DeleteValue
        }) {
            Ok(count) if count > 0 => {
                for event in &events[..count] {
                    print_registry_event(event);
                }
            }
            Ok(_) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("Error fetching events: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn print_registry_event(event: &windows_erg::etw::TraceEvent) {
    let operation = match event.id {
        10 => "CREATE",
        11 => "OPEN",
        12 => "DELETE",
        13 => "QUERY",
        14 => "SET",
        15 => "DELETE_VALUE",
        16 => "QUERY_MULTI",
        17 => "ENUM_KEY",
        18 => "ENUM_VALUE",
        _ => "UNKNOWN",
    };

    println!(
        "[{}] Registry {} - PID: {}, Level: {}, Data: {} bytes",
        event
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        operation,
        event.process_id,
        event.level,
        event.data.len()
    );
}
