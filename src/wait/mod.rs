//! Shared wait-object primitives used across modules.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent, WaitForSingleObject};

use crate::error::OtherError;
use crate::{Error, Result};

/// Wait object used to coordinate or interrupt long-running operations.
#[derive(Debug, Clone)]
pub struct WaitHandle {
    inner: Arc<WaitHandleInner>,
}

#[derive(Debug)]
struct WaitHandleInner(HANDLE);

unsafe impl Send for WaitHandleInner {}
unsafe impl Sync for WaitHandleInner {}

impl WaitHandle {
    /// Create a new wait-handle-backed event object.
    pub fn new(manual_reset: bool, initial_state: bool) -> Result<Self> {
        let handle = unsafe {
            CreateEventW(
                None,
                manual_reset,
                initial_state,
                windows::core::PCWSTR::null(),
            )
        };

        let handle = handle.map_err(|_| {
            let code = unsafe { GetLastError().0 as i32 };
            Error::Other(OtherError::new(Cow::Owned(format!(
                "wait handle operation 'create' failed (error code: 0x{:08X})",
                code
            ))))
        })?;

        Ok(Self {
            inner: Arc::new(WaitHandleInner(handle)),
        })
    }

    /// Create a manual-reset wait handle event.
    pub fn manual_reset(initial_state: bool) -> Result<Self> {
        Self::new(true, initial_state)
    }

    /// Create an auto-reset wait handle event.
    pub fn auto_reset(initial_state: bool) -> Result<Self> {
        Self::new(false, initial_state)
    }

    /// Return the underlying Win32 handle.
    pub fn raw_handle(&self) -> HANDLE {
        self.inner.0
    }

    /// Clone this wait handle with shared internal ownership.
    ///
    /// This does not duplicate the underlying OS handle.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(self.clone())
    }

    /// Wait indefinitely until this handle is signaled.
    pub fn wait(&self) -> Result<()> {
        let wait_result = unsafe { WaitForSingleObject(self.inner.0, u32::MAX) };
        if wait_result == WAIT_OBJECT_0 {
            return Ok(());
        }
        Err(wait_error("wait"))
    }

    /// Wait until this handle is signaled or the timeout elapses.
    ///
    /// Returns `Ok(true)` if signaled, `Ok(false)` on timeout.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<bool> {
        let wait_result =
            unsafe { WaitForSingleObject(self.inner.0, duration_to_wait_ms(timeout)) };
        if wait_result == WAIT_OBJECT_0 {
            return Ok(true);
        }
        if wait_result == WAIT_TIMEOUT {
            return Ok(false);
        }
        if wait_result == WAIT_FAILED {
            return Err(wait_error("wait_timeout"));
        }
        Err(wait_error("wait_timeout"))
    }

    /// Signal the wait handle.
    pub fn set(&self) -> Result<()> {
        unsafe { SetEvent(self.inner.0) }.map_err(|_| wait_error("set"))?;
        Ok(())
    }

    /// Reset the wait handle to unsignaled state.
    pub fn reset(&self) -> Result<()> {
        unsafe { ResetEvent(self.inner.0) }.map_err(|_| wait_error("reset"))?;
        Ok(())
    }
}

fn duration_to_wait_ms(timeout: Duration) -> u32 {
    timeout.as_millis().min(u32::MAX as u128) as u32
}

fn wait_error(operation: &'static str) -> Error {
    let code = unsafe { GetLastError().0 as i32 };
    Error::Other(OtherError::new(Cow::Owned(format!(
        "wait handle operation '{}' failed (error code: 0x{:08X})",
        operation, code
    ))))
}

impl Drop for WaitHandleInner {
    fn drop(&mut self) {
        if !self.0.is_invalid() && self.0 != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WaitHandle;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn wait_timeout_reports_timeout_then_signal() {
        let wait = WaitHandle::manual_reset(false).expect("wait handle create");
        let timed_out = wait
            .wait_timeout(Duration::from_millis(10))
            .expect("wait timeout should not fail");
        assert!(!timed_out);

        wait.set().expect("set should succeed");
        let signaled = wait
            .wait_timeout(Duration::from_millis(10))
            .expect("wait timeout should not fail");
        assert!(signaled);
    }

    #[test]
    fn cloned_wait_handle_synchronizes_threads() {
        let wait = WaitHandle::manual_reset(false).expect("wait handle create");
        let signaler = wait.try_clone().expect("clone should succeed");

        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            signaler.set().expect("set should succeed");
        });

        wait.wait().expect("wait should succeed after signal");
        worker.join().expect("worker should not panic");
    }
}
