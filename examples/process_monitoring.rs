//! Process monitoring with buffer reuse
//!
//! Demonstrates efficient process information gathering using buffer reuse.

use std::time::Instant;
use windows_erg::process::Process;

fn main() -> windows_erg::Result<()> {
    println!("=== Process Monitoring with Buffer Reuse ===\n");

    // Create reusable buffer
    let mut buffer = Vec::with_capacity(8192);
    
    // Get all processes once
    let start = Instant::now();
    Process::list_with_buffer(&mut buffer)?;
    let list_time = start.elapsed();
    
    println!("Listed {} processes in {:?}\n", buffer.len(), list_time);

    // Open and query each process, reusing buffer for command lines
    let start = Instant::now();
    let mut successful = 0;
    let mut with_cmdline = 0;
    let mut cmd_buffer = Vec::with_capacity(8192);
    
    for proc_info in buffer.iter().take(50) {
        // Try to open the process
        if let Ok(process) = Process::open(proc_info.pid) {
            successful += 1;
            
            // Try to read command line (reusing buffer)
            if let Ok(cmd) = process.command_line_with_buffer(&mut cmd_buffer)
                && !cmd.is_empty() {
                with_cmdline += 1;
                if with_cmdline <= 10 {
                    println!("{:5} | {} | {}",
                        proc_info.pid,
                        proc_info.name,
                        if cmd.len() > 60 {
                            format!("{}...", &cmd[..60])
                        } else {
                            cmd
                        }
                    );
                }
            }
        }
    }
    
    let query_time = start.elapsed();
    
    println!("\nProcessed 50 processes in {:?}", query_time);
    println!("Successfully opened: {}", successful);
    println!("With command line: {}", with_cmdline);
    
    println!("\n=== Performance Comparison ===\n");
    
    // Without buffer reuse
    let start = Instant::now();
    for proc_info in buffer.iter().take(10) {
        if let Ok(process) = Process::open(proc_info.pid) {
            let _ = process.command_line(); // Allocates internally
        }
    }
    let without_reuse = start.elapsed();
    
    // With buffer reuse
    let start = Instant::now();
    for proc_info in buffer.iter().take(10) {
        if let Ok(process) = Process::open(proc_info.pid) {
            let _ = process.command_line_with_buffer(&mut cmd_buffer);
        }
    }
    let with_reuse = start.elapsed();
    
    println!("10 processes without buffer reuse: {:?}", without_reuse);
    println!("10 processes with buffer reuse: {:?}", with_reuse);
    if with_reuse < without_reuse {
        let speedup = without_reuse.as_nanos() as f64 / with_reuse.as_nanos() as f64;
        println!("Speedup: {:.2}x faster", speedup);
    }

    Ok(())
}
