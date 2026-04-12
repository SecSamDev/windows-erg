//! Custom event parsing with raw handle access.
//!
//! This example demonstrates:
//! - `next_batch_raw_with_filter` for custom event types
//! - Direct EVT_HANDLE access for maximum performance
//! - Custom struct with only needed fields
//! - Filtering after conversion (on custom type T)
//!
//! Run with: cargo run --example evt_custom_parsing

use windows_erg::Result;
use windows_erg::evt::EventLog;
use windows_erg::evt::types::{extract_event_id, extract_provider, extract_timestamp};

/// Lightweight event type with only essential fields
#[derive(Debug)]
struct LightweightEvent {
    id: u32,
    provider: String,
    timestamp: Option<std::time::SystemTime>,
}

fn main() -> Result<()> {
    println!("Custom event parsing with raw handle access...\n");

    let log = EventLog::open("System")?;
    let mut query = log.query_stream("*[System[EventID < 50]]")?;

    let mut events = Vec::with_capacity(50);

    // Use next_batch_raw_with_filter for custom parsing
    // - First closure: convert EVT_HANDLE to custom type
    // - Second closure: filter on the custom type (not Event)
    let count = query.next_batch_raw_with_filter(
        &mut events,
        |handle| {
            // Custom converter - extract only needed fields
            Ok(LightweightEvent {
                id: extract_event_id(handle)?,
                provider: extract_provider(handle)?,
                timestamp: extract_timestamp(handle).ok(),
            })
        },
        |event| {
            // Filter on custom type - only events from specific providers
            event.provider.contains("Microsoft-Windows")
        },
    )?;

    println!("Converted {} events (after filtering)\n", count);

    // Display results
    for (i, event) in events.iter().take(10).enumerate() {
        println!("[{}] Event ID: {}", i + 1, event.id);
        println!("    Provider: {}", event.provider);
        println!(
            "    Timestamp: {}",
            event
                .timestamp
                .map(|t| format!("{:?}", t))
                .unwrap_or_else(|| "N/A".to_string())
        );
        println!();
    }

    // Demonstrate memory efficiency
    let event_size = std::mem::size_of::<LightweightEvent>();
    let full_event_size = std::mem::size_of::<windows_erg::evt::types::Event>();

    println!("Memory efficiency:");
    println!("  LightweightEvent: {} bytes", event_size);
    println!(
        "  Full Event struct: {} bytes ({}x larger)",
        full_event_size,
        full_event_size / event_size
    );

    Ok(())
}
