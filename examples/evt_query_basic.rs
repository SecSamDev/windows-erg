//! Basic event log query with message formatting.
//!
//! This example demonstrates:
//! - Opening an event log channel
//! - Querying with XPath filter
//! - Opt-in message formatting with `.with_message()`
//! - Batch processing with buffer reuse
//!
//! Run with: cargo run --example evt_query_basic

use windows_erg::Result;
use windows_erg::evt::EventLog;

fn main() -> Result<()> {
    println!("Querying Security log for logon events (4624)...\n");

    // Open the Security event log
    let log = EventLog::open("Security")?;

    // Query for successful logon events with message formatting enabled
    let mut query = log
        .query_stream("*[System[EventID=4624]]")?
        .with_message() // Enable message formatting via EvtFormatMessage
        .with_event_data(); // Extract EventData key-value pairs

    let mut batch = Vec::with_capacity(10);
    let mut total_count = 0;

    // Process events in batches
    while query.next_batch(&mut batch)? > 0 {
        for event in &batch {
            total_count += 1;

            println!("Event ID: {}", event.id);
            println!("Provider: {}", event.provider);
            println!("Level: {}", event.level);
            println!(
                "Timestamp: {}",
                event
                    .timestamp
                    .map(|t| format!("{:?}", t))
                    .unwrap_or_else(|| "N/A".to_string())
            );

            // Show formatted message if available
            if let Some(ref message) = event.formatted_message {
                println!("Message: {}", message);
            }

            // Show EventData if available
            if let Some(ref data) = event.data {
                println!("EventData:");
                for (key, value) in data {
                    // Common field names like "TargetUserName" use Cow::Borrowed (zero-copy)
                    println!("  {}: {}", key, value);
                }
            }

            println!("---");

            // Limit output for demo
            if total_count >= 5 {
                break;
            }
        }

        if total_count >= 5 {
            break;
        }
    }

    println!("\nProcessed {} events", total_count);

    Ok(())
}
