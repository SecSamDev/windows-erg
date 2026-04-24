#![cfg(windows)]

use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

use windows_erg::process::Process;
use windows_erg::{Error, ProcessId, Wait};

fn spawn_timeout_child(seconds: u64) -> windows_erg::Result<Child> {
    Command::new("cmd")
        .args(["/C", "timeout", "/T", &seconds.to_string(), "/NOBREAK"])
        .spawn()
        .map_err(|e| {
            Error::Other(windows_erg::error::OtherError::new(format!(
                "spawn child failed: {e}"
            )))
        })
}

fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn wait_any_reports_cancel_first() -> windows_erg::Result<()> {
    let mut child = spawn_timeout_child(3)?;
    let process = Process::open(ProcessId::new(child.id()))?;
    let process_wait = process.as_wait();

    let cancel = Wait::manual_reset(false)?;
    let cancel_signal = cancel.try_clone()?;

    thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        let _ = cancel_signal.set();
    });

    let result = Wait::wait_any_timeout(&[&process_wait, &cancel], Duration::from_secs(2))?;
    assert_eq!(result, Some(1), "expected cancel handle to signal first");

    kill_and_reap(&mut child);
    Ok(())
}

#[test]
fn wait_any_reports_process_exit_first() -> windows_erg::Result<()> {
    let mut child = spawn_timeout_child(1)?;
    let process = Process::open(ProcessId::new(child.id()))?;
    let process_wait = process.as_wait();

    let cancel = Wait::manual_reset(false)?;
    let cancel_signal = cancel.try_clone()?;

    thread::spawn(move || {
        thread::sleep(Duration::from_secs(3));
        let _ = cancel_signal.set();
    });

    let result = Wait::wait_any_timeout(&[&process_wait, &cancel], Duration::from_secs(4))?;
    assert_eq!(result, Some(0), "expected process handle to signal first");

    let code = process.wait_for_exit()?;
    assert_eq!(code, 0);

    let _ = child.wait();
    Ok(())
}

#[test]
fn wait_any_reports_timeout_first() -> windows_erg::Result<()> {
    let mut child = spawn_timeout_child(5)?;
    let process = Process::open(ProcessId::new(child.id()))?;
    let process_wait = process.as_wait();

    let cancel = Wait::manual_reset(false)?;

    let result = Wait::wait_any_timeout(&[&process_wait, &cancel], Duration::from_millis(250))?;
    assert_eq!(result, None, "expected wait timeout before process/cancel");

    kill_and_reap(&mut child);
    Ok(())
}
