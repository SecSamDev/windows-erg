use std::thread;
use std::time::Duration;

use windows_erg::etw::{EventTrace, SystemProvider};

fn main() -> windows_erg::Result<()> {
    let mut trace = EventTrace::builder("StopWithWait")
        .system_provider(SystemProvider::Process)
        .start()?;

    let stop = trace.stop_handle();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(3));
        let _ = stop.set();
    });

    let mut buffer = Vec::with_capacity(256);
    trace.run_until_stopped(&mut buffer, Duration::from_millis(100))?;

    trace.stop()?;
    println!("ETW trace stopped via Wait signal");

    Ok(())
}
