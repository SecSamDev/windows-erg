//! Event filtering with EventData extraction.
//!
//! This example demonstrates:
//! - Opt-in EventData extraction with `.with_event_data()`
//! - Field name interning (common fields use Cow::Borrowed)
//! - Client-side filtering on EventData values
//! - Buffer reuse pattern
//!
//! Run with: cargo run --example evt_filter

use windows_erg::Result;
use windows_erg::evt::EventLog;

fn main() -> Result<()> {
    println!("Filtering events with EventData extraction...\n");

    // Open Application log
    let log = EventLog::open("Application")?;

    // Query all events with EventData extraction enabled
    let mut query = log.query_stream("*")?.with_event_data();

    let mut batch = Vec::with_capacity(50);
    let mut matched_count = 0;

    // Process batches
    while query.next_batch(&mut batch)? > 0 {
        for event in &batch {
            // Filter: only process events with EventData
            if let Some(ref data) = event.data {
                // Look for specific fields
                let has_error_code = data.contains_key("ErrorCode");
                let has_user = data.contains_key("User") || data.contains_key("TargetUserName");

                if has_error_code || has_user {
                    matched_count += 1;

                    println!("Event ID: {} ({})", event.id, event.provider);
                    println!("EventData:");

                    for (key, value) in data {
                        // Common field names (e.g., "TargetUserName") are Cow::Borrowed
                        // This demonstrates zero-copy for interned strings
                        match key.as_ref() {
                            "TargetUserName" | "SubjectUserName" | "User" => {
                                println!("  {} (interned): {}", key, value);
                            }
                            "ErrorCode" | "ProcessId" | "ThreadId" => {
                                println!("  {} (interned): {}", key, value);
                            }
                            _ => {
                                println!("  {}: {}", key, value);
                            }
                        }
                    }
                    println!("---");

                    // Limit output for demo
                    if matched_count >= 5 {
                        break;
                    }
                }
            }
        }

        if matched_count >= 5 {
            break;
        }
    }

    println!("\nMatched {} events with relevant EventData", matched_count);

    Ok(())
}
