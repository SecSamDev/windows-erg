//! Task Scheduler probe: which `Microsoft-Windows-TaskScheduler` events tie a
//! task's name to the process that runs it, and with which fields?
//!
//! A scheduled task implemented as a COM handler runs inside `taskhostw.exe`,
//! often a shared, argument-less instance that hosts several tasks over its
//! lifetime, so the host's command line cannot name the task. This probe
//! starts a user-mode session on the Task Scheduler provider, optionally
//! runs one task by path, and prints every event with all its decoded fields
//! for `--secs N` (default 60), then a count per event ID.
//!
//! Run as Administrator:
//! `cargo run --example etw_taskscheduler_probe`
//! `cargo run --example etw_taskscheduler_probe -- --run "\Microsoft\Windows\Some\Task" --secs 30`

use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use windows::core::GUID;
use windows_erg::etw::{EventTrace, TraceEvent};

/// Microsoft-Windows-TaskScheduler.
const TASK_SCHEDULER: GUID = GUID::from_u128(0xde7b24ea_73c8_4a09_985d_5bdadcfa9017);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !windows_erg::is_elevated()? {
        eprintln!("run this from an elevated terminal");
        std::process::exit(1);
    }
    let args: Vec<String> = std::env::args().collect();
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let secs: u64 = value("--secs").and_then(|s| s.parse().ok()).unwrap_or(60);
    let run_task = value("--run");

    let own_pid = std::process::id();
    let mut trace = EventTrace::builder(format!("TaskSchedulerProbe-{own_pid}"))
        .user_provider(TASK_SCHEDULER)
        .with_detailed_events()
        .channel_capacity(65_536)
        .start()?;
    std::thread::sleep(Duration::from_millis(500));

    if let Some(task) = &run_task {
        let status = std::process::Command::new("schtasks")
            .args(["/run", "/tn", task])
            .status()?;
        println!("schtasks /run /tn {task}: {status}");
    }

    let mut counts: BTreeMap<u16, u64> = BTreeMap::new();
    let mut batch: Vec<TraceEvent> = Vec::with_capacity(1024);
    let deadline = Instant::now() + Duration::from_secs(secs);
    println!("printing every Task Scheduler event for {secs} s...");
    while Instant::now() < deadline {
        trace.next_batch_timeout(&mut batch, Duration::from_millis(200))?;
        for event in &batch {
            *counts.entry(event.id).or_default() += 1;
            println!(
                "id={:4} opcode={:3} header_pid={:6} tid={:6}",
                event.id,
                event.opcode,
                event.process_id.as_u32(),
                event.thread_id.as_u32(),
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

    println!("events by id:");
    for (id, n) in &counts {
        println!("  id {id:4}: {n}");
    }
    Ok(())
}
