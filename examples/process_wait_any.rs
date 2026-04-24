use std::process::Command;
use std::thread;
use std::time::Duration;

use windows_erg::process::Process;
use windows_erg::{ProcessId, Wait};

fn run_case(
    name: &str,
    process_seconds: u64,
    cancel_after: Option<Duration>,
    wait_timeout: Duration,
) -> windows_erg::Result<()> {
    println!("\n=== {name} ===");

    let mut child = Command::new("cmd")
        .args([
            "/C",
            "timeout",
            "/T",
            &process_seconds.to_string(),
            "/NOBREAK",
        ])
        .spawn()
        .map_err(|e| {
            windows_erg::Error::Other(windows_erg::error::OtherError::new(format!(
                "spawn failed: {e}"
            )))
        })?;

    let process = Process::open(ProcessId::new(child.id()))?;
    let process_wait = process.as_wait();

    let cancel = Wait::manual_reset(false)?;
    if let Some(cancel_delay) = cancel_after {
        let cancel_signal = cancel.try_clone()?;
        thread::spawn(move || {
            thread::sleep(cancel_delay);
            let _ = cancel_signal.set();
        });
    }

    match Wait::wait_any_timeout(&[&process_wait, &cancel], wait_timeout)? {
        Some(0) => {
            let code = process.wait_for_exit()?;
            println!("result: process exited naturally with code {code}");
        }
        Some(1) => {
            println!("result: cancel signal arrived first; terminating child process");
            let _ = child.kill();
            let _ = child.wait();
        }
        Some(other) => {
            println!("result: unexpected signaled index: {other}");
            let _ = child.kill();
            let _ = child.wait();
        }
        None => {
            println!("result: wait timed out; terminating child process");
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    Ok(())
}

fn main() -> windows_erg::Result<()> {
    run_case(
        "Case 1: cancel arrives first",
        5,
        Some(Duration::from_secs(1)),
        Duration::from_secs(10),
    )?;

    run_case(
        "Case 2: process exits first",
        1,
        Some(Duration::from_secs(5)),
        Duration::from_secs(10),
    )?;

    run_case(
        "Case 3: wait timeout first",
        15,
        None,
        Duration::from_secs(2),
    )?;

    Ok(())
}
