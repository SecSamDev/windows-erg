//! Serde deserialization for custom event types.
//!
//! This example demonstrates:
//! - `next_batch_deserialize` for XML deserialization into owned types
//! - Custom types without explicit lifetime parameters
//! - Flexible field selection using serde attributes
//! - Requires `serde` feature
//!
//! Run with: cargo run --example evt_serde --features serde

#[cfg(feature = "serde")]
use serde::Deserialize;
#[cfg(feature = "serde")]
use windows_erg::Result;
#[cfg(feature = "serde")]
use windows_erg::evt::EventLog;

#[cfg(feature = "serde")]
#[derive(Debug, Deserialize)]
struct CustomEvent {
    #[serde(rename = "System")]
    system: SystemData,
    #[serde(rename = "EventData", default)]
    event_data: Option<EventDataFields>,
}

#[cfg(feature = "serde")]
#[derive(Debug, Deserialize)]
struct SystemData {
    #[serde(rename = "EventID")]
    event_id: u32,
    #[serde(rename = "Provider")]
    provider: ProviderData,
    #[serde(rename = "Level")]
    level: u8,
    #[serde(rename = "TimeCreated")]
    time_created: TimeCreatedData,
}

#[cfg(feature = "serde")]
#[derive(Debug, Deserialize)]
struct ProviderData {
    #[serde(rename = "@Name")]
    name: String,
}

#[cfg(feature = "serde")]
#[derive(Debug, Deserialize)]
struct TimeCreatedData {
    #[serde(rename = "@SystemTime")]
    system_time: String,
}

#[cfg(feature = "serde")]
#[derive(Debug, Deserialize)]
struct EventDataFields {
    #[serde(rename = "Data")]
    data: Vec<DataField>,
}

#[cfg(feature = "serde")]
#[derive(Debug, Deserialize)]
struct DataField {
    #[serde(rename = "@Name")]
    name: Option<String>,
    #[serde(rename = "$value")]
    value: Option<String>,
}

#[cfg(feature = "serde")]
fn main() -> Result<()> {
    println!("Serde deserialization for custom event types...\n");

    let log = EventLog::open("Application")?;
    let mut query = log.query_stream("*[System[EventID < 100]]")?;

    let mut events: Vec<CustomEvent> = Vec::with_capacity(20);

    // Deserialize directly from XML into owned types
    let count = query.next_batch_deserialize(&mut events)?;

    println!("Deserialized {} events\n", count);

    // Display results
    for (i, event) in events.iter().take(5).enumerate() {
        println!("[{}] Event ID: {}", i + 1, event.system.event_id);
        println!("    Provider: {}", event.system.provider.name);
        println!("    Level: {}", event.system.level);
        println!("    Timestamp: {}", event.system.time_created.system_time);

        if let Some(ref data) = event.event_data {
            println!("    EventData fields:");
            for field in &data.data {
                if let (Some(name), Some(value)) = (field.name.as_deref(), field.value.as_deref()) {
                    println!("      {}: {}", name, value);
                }
            }
        }
        println!();
    }

    // Demonstrate owned data access
    if let Some(first_event) = events.first() {
        println!("Owned data demonstration:");
        println!(
            "  Provider name is owned String: {}",
            first_event.system.provider.name
        );
    }

    Ok(())
}

#[cfg(not(feature = "serde"))]
fn main() {
    eprintln!("This example requires the 'serde' feature.");
    eprintln!("Run with: cargo run --example evt_serde --features serde");
    std::process::exit(1);
}
