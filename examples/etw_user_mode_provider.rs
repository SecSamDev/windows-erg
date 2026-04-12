//! ETW user-mode provider example.
//!
//! Demonstrates how to subscribe to a user-mode ETW provider by GUID.
//!
//! Usage:
//! `cargo run --example etw_user_mode_provider`

use std::time::Duration;
use windows::core::GUID;
use windows_erg::error::{Error, EtwError};
use windows_erg::etw::EventTrace;

// Microsoft-Windows-DotNETRuntime
// Replace with a provider GUID relevant to your workload.
const DOTNET_RUNTIME_PROVIDER: GUID = GUID::from_u128(0xe13c0d23_ccbc_4e12_931b_d9cc2eee27e4);

fn main() -> windows_erg::Result<()> {
    println!("Starting ETW user-mode provider monitor...");
    println!("Provider GUID: {:?}", DOTNET_RUNTIME_PROVIDER);
    println!("Press Ctrl+C to stop\n");

    let mut trace = match EventTrace::builder("UserModeProviderMonitor")
        .user_provider(DOTNET_RUNTIME_PROVIDER)
        .with_thread_context()
        .with_cpu_samples()
        .channel_capacity(20_000)
        .start()
    {
        Ok(trace) => trace,
        Err(Error::Etw(EtwError::ProviderEnableFailed(e))) => {
            eprintln!("Failed to enable provider: {}", e);
            eprintln!("Hint: verify the provider GUID is registered on this machine.");
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    println!("ETW session started: {}", trace.name());

    let mut events = Vec::with_capacity(256);
    let mut processed = 0usize;

    loop {
        let count = trace.next_batch(&mut events)?;
        if count == 0 {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }

        for event in &events {
            processed += 1;

            if !processed.is_multiple_of(50) {
                continue;
            }

            println!(
                "[{}] id={} opcode={} level={} pid={} tid={} cpu={:?}",
                processed,
                event.id,
                event.opcode,
                event.level,
                event.process_id,
                event.thread_id,
                event.cpu_sample.as_ref().map(|s| s.processor_number),
            );
        }
    }
}
