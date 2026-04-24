//! Spawn a process as a child of explorer.exe using ProcessSpawner.
//!
//! Run elevated when using token-based launch.
//! Usage:
//!   cargo run --example process_spawn_parented -- "C:\\Windows\\System32\\notepad.exe"

use windows_erg::process::{Process, ProcessSpawner};

fn find_explorer_pid() -> windows_erg::Result<windows_erg::types::ProcessId> {
    let mut processes = Vec::with_capacity(256);
    Process::list_with_filter(&mut processes, |p| p.name.eq_ignore_ascii_case("explorer.exe"))?;

    processes
        .into_iter()
        .next()
        .map(|p| p.pid)
        .ok_or_else(|| {
            windows_erg::Error::Other(windows_erg::error::OtherError::new(
                "explorer.exe was not found",
            ))
        })
}

fn main() -> windows_erg::Result<()> {
    let exe = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "C:\\Windows\\System32\\notepad.exe".to_string());

    let explorer_pid = find_explorer_pid()?;

    println!("Explorer PID: {}", explorer_pid);
    println!("Spawning: {}", exe);

    let spawned = ProcessSpawner::new(&exe)
        .parent(explorer_pid)
        .as_user_of(explorer_pid)
        .spawn()?;

    println!("Spawned PID: {}", spawned.pid());
    println!("Primary TID: {}", spawned.thread_id());
    println!("Done.");

    Ok(())
}
