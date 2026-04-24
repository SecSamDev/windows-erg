use std::time::Duration;

use windows_erg::pipes::{self, NamedPipeChange, NamedPipePoller};

fn main() -> windows_erg::Result<()> {
    let mut listed = pipes::list()?;

    println!("Current named pipes:");
    for pipe in &mut listed {
        pipe.local_info = pipes::query_local_info(&pipe.pipe_name).ok();

        let local = pipe
            .local_info
            .map(|info| {
                format!(
                    ", instances={}, state={}",
                    info.current_instances, info.named_pipe_state
                )
            })
            .unwrap_or_default();

        println!(
            "  {} (attributes=0x{:08X}, eof={}, alloc={}{})",
            pipe.pipe_name, pipe.file_attributes, pipe.end_of_file, pipe.allocation_size, local
        );
    }

    println!("\nPolling for changes with callback (5 rounds, 2s interval):");
    let mut poller = NamedPipePoller::new();
    poller.seed()?;

    let total_changes =
        poller.poll_interval_with_callback(5, Duration::from_secs(2), |round, changes| {
            println!("Round {}:", round);
            if changes.is_empty() {
                println!("  no changes");
                return;
            }

            for change in changes {
                match change {
                    NamedPipeChange::Appeared(pipe) => println!("  appeared: {}", pipe.pipe_name),
                    NamedPipeChange::Removed(pipe) => println!("  removed: {}", pipe.pipe_name),
                }
            }
        })?;

    println!("Total changes observed: {}", total_changes);

    println!("\nPolling snapshots helper (3 rounds, 1s interval):");
    let snapshots = pipes::poll_interval(3, Duration::from_secs(1))?;
    for (index, changes) in snapshots.iter().enumerate() {
        println!("Snapshot {}: {} changes", index + 1, changes.len());
    }

    Ok(())
}
