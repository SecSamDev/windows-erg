//! Process tree operations example
//!
//! Demonstrates killing process trees and finding parent/child relationships.

use windows_erg::process::{Process, ProcessId};
use std::thread;
use std::time::Duration;
use std::process::Child;

fn main() -> windows_erg::Result<()> {
    println!("=== Process Tree Operations ===\n");

    // Spawn a test process tree
    println!("Spawning test process tree...");
    let child = std::process::Command::new("cmd.exe")
        .args(["timeout", "30"])
        .spawn()
        .expect("Failed to spawn test process");
    
    let child_pid = ProcessId::new(child.id());
    println!("Spawned process with PID: {}", child_pid);
    
    thread::sleep(Duration::from_millis(500));

    // Use a guard to ensure child is waited on even if we return early
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.wait();
        }
    }
    
    let _guard = ChildGuard(child);

    // Open the process
    let process = Process::open(child_pid)?;
    
    println!("\nProcess Information:");
    println!("  Name: {}", process.name()?);
    println!("  Path: {}", process.path()?.display());
    println!("  Running: {}", process.is_running()?);
    
    // Get parent
    if let Ok(Some(parent_pid)) = process.parent_id() {
        println!("  Parent PID: {}", parent_pid);
        
        if let Ok(parent) = Process::open(parent_pid) {
            println!("  Parent name: {}", parent.name()?);
        }
    }
    
    // Get children
    match process.children() {
        Ok(children) => {
            println!("  Children: {}", children.len());
            for child_id in children.iter().take(5) {
                if let Ok(child_proc) = Process::open(*child_id)
                    && let Ok(name) = child_proc.name() {
                    println!("    - {} (PID: {})", name, child_id);
                }
            }
        }
        Err(e) => println!("  Could not enumerate children: {}", e),
    }

    // Get threads
    match process.threads() {
        Ok(threads) => {
            println!("  Threads: {}", threads.len());
        }
        Err(e) => println!("  Could not enumerate threads: {}", e),
    }

    // Kill the process tree
    println!("\nKilling process tree...");
    process.kill_tree()?;
    
    println!("Process tree killed successfully");
    
    thread::sleep(Duration::from_millis(100));
    
    // Verify it's terminated
    match process.is_running() {
        Ok(false) => println!("Process confirmed terminated"),
        Ok(true) => println!("Warning: Process still running"),
        Err(e) => println!("Could not check process status: {}", e),
    }

    Ok(())
}
