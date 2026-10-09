//! Kernel-Process probe: what does `Microsoft-Windows-Kernel-Process`
//! ProcessStart (event 1) carry about a new process's token?
//!
//! Starts a user-mode session on the provider with only
//! `WINEVENT_KEYWORD_PROCESS` (0x10), launches `cmd.exe /c exit` so at least
//! one start arrives, and prints every event with all its decoded fields for
//! `--secs N` (default 15), then a count per event ID and version.
//!
//! Run as Administrator:
//! `cargo run --example etw_kernel_process_probe`
//! `cargo run --example etw_kernel_process_probe -- --secs 60`

use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use windows::core::GUID;
use windows_erg::etw::{EventTrace, TraceEvent, TraceLevel};

/// Microsoft-Windows-Kernel-Process.
const KERNEL_PROCESS: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
/// `WINEVENT_KEYWORD_PROCESS`: process start and stop only.
const KEYWORD_PROCESS: u64 = 0x10;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !windows_erg::is_elevated()? {
        eprintln!("run this from an elevated terminal");
        std::process::exit(1);
    }
    let args: Vec<String> = std::env::args().collect();
    let secs: u64 = args
        .iter()
        .position(|a| a == "--secs")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);

    let own_pid = std::process::id();
    let mut trace = EventTrace::builder(format!("KernelProcessProbe-{own_pid}"))
        .user_provider_with(KERNEL_PROCESS, TraceLevel::Info, KEYWORD_PROCESS)
        .with_detailed_events()
        .channel_capacity(65_536)
        .start()?;
    std::thread::sleep(Duration::from_millis(500));

    let child = std::process::Command::new("cmd.exe")
        .args(["/c", "exit"])
        .spawn()?;
    println!("spawned cmd.exe pid {}", child.id());

    let mut counts: BTreeMap<(u16, u8), u64> = BTreeMap::new();
    let mut batch: Vec<TraceEvent> = Vec::with_capacity(1024);
    let deadline = Instant::now() + Duration::from_secs(secs);
    println!("printing every Kernel-Process event for {secs} s...");
    while Instant::now() < deadline {
        trace.next_batch_timeout(&mut batch, Duration::from_millis(200))?;
        for event in &batch {
            *counts.entry((event.id, event.version)).or_default() += 1;
            println!(
                "id={:4} version={} opcode={:3} header_pid={:6}",
                event.id,
                event.version,
                event.opcode,
                event.process_id.as_u32(),
            );
            match event.fields() {
                Some(fields) => {
                    for f in fields {
                        println!("    {} = {:?}", f.name, f.value);
                    }
                }
                None => println!(
                    "    (no decoded fields; {} payload bytes)",
                    event.data.len()
                ),
            }
        }
    }
    trace.stop()?;

    println!("events by (id, version):");
    for ((id, version), n) in &counts {
        println!("  id {id:4} v{version}: {n}");
    }
    Ok(())
}
