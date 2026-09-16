//! Console control signals (Ctrl+C, Ctrl+Break, console close, logoff, shutdown).
//!
//! Console applications that must shut down cleanly register a [`Wait`] with
//! [`signal_on_ctrl`]; the wait object is set when a control signal arrives,
//! so it can interrupt blocking calls such as
//! [`NamedPipeServer::connect_with_wait`](crate::pipes::NamedPipeServer::connect_with_wait).
//!
//! # Example
//!
//! ```no_run
//! use windows_erg::{Wait, console};
//!
//! let stop = Wait::manual_reset(false)?;
//! console::signal_on_ctrl(&stop)?;
//! stop.wait()?; // returns after Ctrl+C
//! # Ok::<(), windows_erg::Error>(())
//! ```

use std::sync::{Mutex, PoisonError};

use windows::Win32::Foundation::BOOL;
use windows::Win32::System::Console::SetConsoleCtrlHandler;

use crate::error::{Error, Result, WindowsApiError};
use crate::wait::Wait;

struct HandlerState {
    installed: bool,
    waits: Vec<Wait>,
}

static STATE: Mutex<HandlerState> = Mutex::new(HandlerState {
    installed: false,
    waits: Vec::new(),
});

/// Set `wait` whenever the process receives a console control signal.
///
/// The process-wide handler is installed on first use; later calls only add
/// wait objects. Registered waits stay registered for the process lifetime.
/// Signals are reported as handled, so Ctrl+C no longer terminates the process
/// by itself.
pub fn signal_on_ctrl(wait: &Wait) -> Result<()> {
    let mut state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
    if !state.installed {
        // SAFETY: `ctrl_handler` is a valid `extern "system"` routine that lives
        // for the whole process and only touches synchronised static state.
        unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), true) }.map_err(|e| {
            Error::WindowsApi(WindowsApiError::with_context(e, "SetConsoleCtrlHandler"))
        })?;
        state.installed = true;
    }
    state.waits.push(wait.clone());
    Ok(())
}

unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> BOOL {
    BOOL::from(signal_all())
}

/// Set every registered wait; `true` when at least one was set.
fn signal_all() -> bool {
    let state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
    let mut any = false;
    for wait in &state.waits {
        any |= wait.set().is_ok();
    }
    any
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn control_signal_sets_registered_waits() {
        let first = Wait::manual_reset(false).unwrap();
        let second = Wait::manual_reset(false).unwrap();
        signal_on_ctrl(&first).unwrap();
        signal_on_ctrl(&second).unwrap();

        // Invoke the handler directly; raising a real Ctrl+C would also hit
        // the test harness.
        // SAFETY: the handler has no preconditions.
        let handled = unsafe { ctrl_handler(0) };

        assert!(handled.as_bool());
        assert!(first.wait_timeout(Duration::ZERO).unwrap());
        assert!(second.wait_timeout(Duration::ZERO).unwrap());
    }
}
