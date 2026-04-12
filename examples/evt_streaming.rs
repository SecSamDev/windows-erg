//! Streaming event processing with concurrent read access.
//!
//! This example demonstrates:
//! - High-throughput batch processing
//! - Buffer reuse to minimize allocations
//! - Concurrent processing with Arc<RwLock<>>
//! - Real-time monitoring pattern
//!
//! Run with: cargo run --example evt_streaming

use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;
use windows_erg::Result;
use windows_erg::evt::EventLog;

fn main() -> Result<()> {
    println!("Streaming events from System log...\n");

    // Shared event buffer protected by RwLock for concurrent access
    let events = Arc::new(RwLock::new(Vec::new()));

    // Spawn reader thread
    let events_clone = Arc::clone(&events);
    let reader_handle = thread::spawn(move || -> Result<()> {
        let log = EventLog::open("System")?;
        let mut query = log.query_stream("*[System[EventID < 100]]")?;

        let mut batch = Vec::with_capacity(64);
        let mut total_processed = 0;

        // Process events in batches
        while query.next_batch(&mut batch)? > 0 {
            // Acquire write lock to update shared buffer
            let mut shared = events_clone.write().unwrap();
            shared.clear();
            shared.extend_from_slice(&batch);
            drop(shared); // Release write lock

            total_processed += batch.len();

            // Simulate processing delay
            thread::sleep(Duration::from_millis(100));

            // Stop after processing some events for demo
            if total_processed >= 100 {
                break;
            }
        }

        println!("Reader: Processed {} events total", total_processed);
        Ok(())
    });

    // Spawn monitor thread (reads concurrently)
    let events_clone = Arc::clone(&events);
    let monitor_handle = thread::spawn(move || {
        for i in 0..10 {
            thread::sleep(Duration::from_millis(150));

            // Acquire read lock (multiple readers can access concurrently)
            let shared = events_clone.read().unwrap();
            println!("Monitor [{}]: Current batch has {} events", i, shared.len());

            if !shared.is_empty() {
                let event = &shared[0];
                println!(
                    "  First event: ID={}, Provider={}",
                    event.id, event.provider
                );
            }
        }
    });

    // Wait for both threads to complete
    reader_handle.join().unwrap()?;
    monitor_handle.join().unwrap();

    println!("\nStreaming complete!");

    Ok(())
}
