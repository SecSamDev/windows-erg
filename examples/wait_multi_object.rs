use std::thread;
use std::time::Duration;

use windows_erg::Wait;

fn main() -> windows_erg::Result<()> {
    let wait_a = Wait::manual_reset(false)?;
    let wait_b = Wait::manual_reset(false)?;

    let signal_b = wait_b.try_clone()?;
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(250));
        let _ = signal_b.set();
    });

    let signaled_index = Wait::wait_any(&[&wait_a, &wait_b])?;
    println!("wait_any signaled index: {}", signaled_index);

    wait_a.set()?;
    let all_signaled = Wait::wait_all_timeout(&[&wait_a, &wait_b], Duration::from_secs(1))?;
    println!("wait_all_timeout result: {}", all_signaled);

    Ok(())
}
