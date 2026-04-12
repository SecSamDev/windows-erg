//! ETW Network Monitoring Example
//!
//! Demonstrates real-time network connection monitoring using ETW.
//!
//! This example shows how to:
//! - Monitor TCP/UDP connection events
//! - Track network activity at kernel level
//! - Process network events with filtering
//!
//! # Usage
//!
//! ```shell
//! # Run as Administrator (ETW requires elevated privileges)
//! cargo run --example etw_network_monitor
//! ```
//!
//! # Event IDs (Network Provider)
//!
//! TCP/IP events:
//! - 10: TCP connection attempt
//! - 11: TCP connect
//! - 12: TCP disconnect
//! - 13: TCP retransmit
//! - 14: TCP accept
//! - 15: TCP reconnect
//! - 16: TCP fail
//! - 17: TCP copy
//! - 18: UDP send
//! - 19: UDP receive

use windows_erg::etw::{EventTrace, SystemProvider};

fn main() -> windows_erg::Result<()> {
    println!("Starting ETW Network Monitor...");
    println!("Monitoring TCP/UDP network events");
    println!("Press Ctrl+C to stop\n");

    // Create and start ETW session for network monitoring
    let mut trace = EventTrace::builder("NetworkMonitor")
        .system_provider(SystemProvider::Network)
        .buffer_size(128) // 128 KB buffers for network events
        .min_buffers(5)
        .max_buffers(30)
        .flush_interval(1)
        .start()?;

    println!("✓ ETW session started: {}", trace.name());
    println!("✓ Monitoring network connections\n");

    // Event processing loop
    let mut events = Vec::with_capacity(150);
    let mut event_count = 0;

    loop {
        match trace.next_batch(&mut events) {
            Ok(count) if count > 0 => {
                for event in &events[..count] {
                    event_count += 1;
                    print_network_event(event, event_count);
                }
            }
            Ok(_) => {
                // No events - sleep briefly
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!("Error fetching events: {}", e);
                break;
            }
        }
    }

    println!("\nTotal events processed: {}", trace.events_processed());
    Ok(())
}

fn print_network_event(event: &windows_erg::etw::TraceEvent, count: usize) {
    let event_type = match event.id {
        10 => "TCP_CONNECT_ATTEMPT",
        11 => "TCP_CONNECT",
        12 => "TCP_DISCONNECT",
        13 => "TCP_RETRANSMIT",
        14 => "TCP_ACCEPT",
        15 => "TCP_RECONNECT",
        16 => "TCP_FAIL",
        17 => "TCP_COPY",
        18 => "UDP_SEND",
        19 => "UDP_RECEIVE",
        _ => "UNKNOWN",
    };

    println!(
        "[{}] {} - PID: {}, TID: {}, Level: {}, Data: {} bytes",
        count,
        event_type,
        event.process_id,
        event.thread_id,
        event.level,
        event.data.len()
    );
}
