//! Host and process metrics example.
//!
//! Demonstrates host CPU/RAM snapshot APIs and per-process metrics.

use std::time::Duration;

use windows_erg::process::Process;

fn main() -> windows_erg::Result<()> {
    println!("=== Host Metrics ===\n");

    let host = windows_erg::process::host_metrics()?;
    println!("Logical CPU count: {}", host.logical_cpu_count);
    println!(
        "Physical memory available: {} / {} MB",
        host.memory.available_physical_bytes / 1024 / 1024,
        host.memory.total_physical_bytes / 1024 / 1024
    );
    println!(
        "Virtual memory available: {} / {} MB",
        host.memory.available_virtual_bytes / 1024 / 1024,
        host.memory.total_virtual_bytes / 1024 / 1024
    );
    println!("Memory load: {}%", host.memory.memory_load_percent);

    let host_cpu = windows_erg::process::host_cpu_usage(Duration::from_millis(300))?;
    println!("Host CPU usage (300ms window): {:.2}%", host_cpu);

    println!("\n=== Current Process Metrics ===\n");

    let process = Process::current();
    println!("PID: {}", process.id());
    println!("Name: {}", process.name()?);

    let metrics = process.metrics()?;
    println!(
        "Working set: {} MB (peak {} MB)",
        metrics.memory.working_set_bytes / 1024 / 1024,
        metrics.memory.peak_working_set_bytes / 1024 / 1024
    );
    println!("Page faults: {}", metrics.memory.page_fault_count);
    println!(
        "Private usage: {} MB",
        metrics.memory.private_usage_bytes / 1024 / 1024
    );
    println!(
        "Commit usage: {} MB (peak {} MB)",
        metrics.memory.commit_usage_bytes / 1024 / 1024,
        metrics.memory.peak_commit_usage_bytes / 1024 / 1024
    );

    println!(
        "CPU cumulative: kernel {:.3}s, user {:.3}s, total {:.3}s",
        metrics.cpu.kernel_time_100ns as f64 / 10_000_000.0,
        metrics.cpu.user_time_100ns as f64 / 10_000_000.0,
        metrics.cpu.total_time_100ns as f64 / 10_000_000.0
    );

    let proc_cpu = process.cpu_usage(Duration::from_millis(300))?;
    println!("Process CPU usage (300ms window): {:.2}%", proc_cpu);

    Ok(())
}
