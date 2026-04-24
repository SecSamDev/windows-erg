//! ETW Multi-Provider Monitoring Example
//!
//! Demonstrates monitoring multiple ETW kernel providers simultaneously.
//!
//! This example shows how to:
//! - Enable multiple kernel providers in one session
//! - Process events from different providers
//! - Distinguish event types from different sources
//!
//! # Usage
//!
//! ```shell
//! # Run as Administrator (ETW requires elevated privileges)
//! cargo run --example etw_multi_provider
//! ```
//!
//! # Providers Monitored
//!
//! - Process: Process/thread creation and termination
//! - Registry: Registry key/value operations
//! - FileIo: File system operations
//! - ImageLoad: DLL/EXE loading

use std::collections::HashMap;
use windows_erg::etw::{EventTrace, SystemProvider};

fn main() -> windows_erg::Result<()> {
    println!("Starting ETW Multi-Provider Monitor...");
    println!("Monitoring: Process, Registry, FileIo, ImageLoad");
    println!("Press Ctrl+C to stop\n");

    // Create session with multiple providers
    let mut trace = EventTrace::builder("MultiProviderMonitor")
        .system_provider(SystemProvider::Process)
        .system_provider(SystemProvider::Registry)
        .system_provider(SystemProvider::FileIo)
        .system_provider(SystemProvider::ImageLoad)
        .buffer_size(256) // Larger buffers for multiple providers
        .min_buffers(10)
        .max_buffers(50)
        .flush_interval(1)
        .channel_capacity(20000) // Higher capacity for multiple providers
        .start()?;

    println!("✓ ETW session started: {}", trace.name());
    println!("✓ Monitoring 4 kernel providers\n");

    // Track event statistics by provider type
    let mut stats = EventStats::new();
    let mut events = Vec::with_capacity(200);

    loop {
        match trace.next_batch(&mut events) {
            Ok(count) if count > 0 => {
                for event in &events[..count] {
                    stats.record(event);

                    // Print every 100th event to avoid spam
                    if stats.total.is_multiple_of(100) {
                        print_event_summary(event, stats.total);
                    }
                }

                // Print stats every 1000 events
                if stats.total.is_multiple_of(1000) {
                    stats.print_summary();
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

    println!("\n=== Final Statistics ===");
    stats.print_summary();
    println!("\nTotal events processed: {}", trace.events_processed());

    Ok(())
}

struct EventStats {
    total: usize,
    by_provider: HashMap<&'static str, usize>,
    by_level: HashMap<u8, usize>,
}

impl EventStats {
    fn new() -> Self {
        EventStats {
            total: 0,
            by_provider: HashMap::new(),
            by_level: HashMap::new(),
        }
    }

    fn record(&mut self, event: &windows_erg::etw::TraceEvent) {
        self.total += 1;

        // Categorize by event ID (rough heuristic for provider type)
        let provider = match event.id {
            1..=9 => "Process",
            10..=19 => "Registry",
            20..=29 => "FileIo",
            30..=39 => "ImageLoad",
            _ => "Other",
        };

        *self.by_provider.entry(provider).or_insert(0) += 1;
        *self.by_level.entry(event.level).or_insert(0) += 1;
    }

    fn print_summary(&self) {
        println!("\n--- Event Statistics (Total: {}) ---", self.total);

        println!("By Provider:");
        let mut providers: Vec<_> = self.by_provider.iter().collect();
        providers.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        for (provider, count) in providers {
            let percentage = (*count as f64 / self.total as f64) * 100.0;
            println!("  {:<12} {:>6} ({:>5.1}%)", provider, count, percentage);
        }

        println!("By Level:");
        let mut levels: Vec<_> = self.by_level.iter().collect();
        levels.sort_by_key(|(level, _)| **level);
        for (level, count) in levels {
            let level_name = match level {
                1 => "Critical",
                2 => "Error",
                3 => "Warning",
                4 => "Info",
                5 => "Verbose",
                _ => "Unknown",
            };
            let percentage = (*count as f64 / self.total as f64) * 100.0;
            println!("  {:<10} {:>6} ({:>5.1}%)", level_name, count, percentage);
        }
    }
}

fn print_event_summary(event: &windows_erg::etw::TraceEvent, count: usize) {
    println!(
        "[{}] Event ID: {}, Level: {}, PID: {}, Data: {} bytes",
        count,
        event.id,
        event.level,
        event.process_id,
        event.data.len()
    );
}
