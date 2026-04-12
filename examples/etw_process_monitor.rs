//! ETW Process Monitoring Example
//!
//! Demonstrates real-time process creation and termination monitoring using ETW.
//!
//! This example shows how to:
//! - Start an ETW kernel trace session
//! - Monitor process and thread events
//! - Process events in batches for efficiency
//!
//! # Usage
//!
//! ```shell
//! # Run as Administrator (ETW requires elevated privileges)
//! cargo run --example etw_process_monitor
//! ```
//!
//! # Event IDs
//!
//! - Process Start: Event ID 1
//! - Process Stop: Event ID 2
//! - Thread Start: Event ID 3
//! - Thread Stop: Event ID 4

use windows_erg::etw::{EventTrace, SystemProvider};

fn main() -> windows_erg::Result<()> {
    println!("Starting ETW Process Monitor...");
    println!("Press Ctrl+C to stop\n");

    // Create and start ETW session
    // Note: This requires Administrator privileges
    let mut trace = EventTrace::builder("ProcessMonitor")
        .system_provider(SystemProvider::Process)
        .buffer_size(128) // 128 KB buffers
        .min_buffers(5) // Minimum 5 buffers
        .max_buffers(25) // Maximum 25 buffers
        .flush_interval(1) // Flush every second
        .start()?;

    println!("✓ ETW session started: {}", trace.name());
    println!("✓ Monitoring process/thread events\n");

    // Event processing loop
    let mut events = Vec::with_capacity(100);
    loop {
        // Fetch next batch of events
        match trace.next_batch(&mut events) {
            Ok(count) if count > 0 => {
                for event in &events[..count] {
                    print_process_event(event);
                }
            }
            Ok(_) => {
                // No events, sleep briefly
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

fn print_process_event(event: &windows_erg::etw::TraceEvent) {
    let event_type = match event.id {
        1 => "Process Start",
        2 => "Process Stop",
        3 => "Thread Start",
        4 => "Thread Stop",
        _ => "Unknown",
    };

    println!(
        "[{}] {} - PID: {}, TID: {}, Opcode: {}",
        event
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        event_type,
        event.process_id,
        event.thread_id,
        event.opcode
    );
}
