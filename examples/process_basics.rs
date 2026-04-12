//! Basic process operations example
//!
//! Demonstrates listing processes, getting process information, and reading PEB data.

use windows_erg::process::Process;

fn main() -> windows_erg::Result<()> {
    println!("=== Process List Example ===\n");

    // List all processes
    println!("Listing all processes...");
    let processes = Process::list()?;
    println!("Found {} processes\n", processes.len());

    // Show first 10 processes
    for (i, proc_info) in processes.iter().take(10).enumerate() {
        println!(
            "{}. PID: {:5} | PPID: {:5} | Threads: {:3} | Name: {}",
            i + 1,
            proc_info.pid,
            proc_info
                .parent_pid
                .map(|p| format!("{}", p))
                .unwrap_or_else(|| "N/A".to_string()),
            proc_info.thread_count,
            proc_info.name
        );
    }

    println!("\n=== Current Process Information ===\n");

    // Get current process
    let current = Process::current();
    println!("Current PID: {}", current.id());
    println!("Process name: {}", current.name()?);
    println!("Process path: {}", current.path()?.display());

    // Read PEB data
    println!("\nReading PEB data...");
    match current.command_line() {
        Ok(cmd) => println!("Command line: {}", cmd),
        Err(e) => println!("Could not read command line: {}", e),
    }

    match current.parameters() {
        Ok(params) => {
            println!("Image path: {}", params.image_path);
            println!("Current directory: {}", params.current_directory);
        }
        Err(e) => println!("Could not read parameters: {}", e),
    }

    // Get memory info
    match current.memory_info() {
        Ok(mem) => {
            println!("\nMemory Information:");
            println!("  Working set: {} MB", mem.working_set / 1024 / 1024);
            println!(
                "  Peak working set: {} MB",
                mem.peak_working_set / 1024 / 1024
            );
            println!("  Page faults: {}", mem.page_fault_count);
        }
        Err(e) => println!("\nCould not read memory info: {}", e),
    }

    // Get threads
    match current.threads() {
        Ok(threads) => {
            println!("\nThreads: {} total", threads.len());
            for (i, thread) in threads.iter().take(5).enumerate() {
                println!(
                    "  {}. TID: {} | Priority: {}",
                    i + 1,
                    thread.tid,
                    thread.base_priority
                );
            }
        }
        Err(e) => println!("\nCould not enumerate threads: {}", e),
    }

    // Get modules
    match current.modules() {
        Ok(modules) => {
            println!("\nLoaded modules: {} total", modules.len());
            for (i, module) in modules.iter().take(5).enumerate() {
                println!("  {}. {} ({} KB)", i + 1, module.name, module.size / 1024);
            }
        }
        Err(e) => println!("\nCould not enumerate modules: {}", e),
    }

    Ok(())
}
