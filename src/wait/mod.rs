//! Shared wait-object primitives used across modules.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use windows::Win32::Foundation::{GetLastError, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};
use windows::core::PCWSTR;

use crate::error::{InvalidParameterError, OtherError};
use crate::utils::{OwnedHandle, to_utf16_nul};
use crate::{Error, Result};

const MAX_WAIT_OBJECTS: usize = 64;

/// Wait object used to coordinate or interrupt long-running operations.
#[derive(Debug, Clone)]
pub struct Wait {
    inner: Arc<OwnedHandle>,
}

impl Wait {
    /// Create a new wait-handle-backed event object.
    pub fn new(manual_reset: bool, initial_state: bool) -> Result<Self> {
        Self::create_event(manual_reset, initial_state, PCWSTR::null(), "create")
    }

    /// Create a named wait event for inter-process synchronization.
    pub fn named(name: &str, manual_reset: bool, initial_state: bool) -> Result<Self> {
        let name_wide = to_utf16_nul(name);
        Self::create_event(
            manual_reset,
            initial_state,
            PCWSTR(name_wide.as_ptr()),
            "create_named",
        )
    }

    /// Create a manual-reset wait handle event.
    pub fn manual_reset(initial_state: bool) -> Result<Self> {
        Self::new(true, initial_state)
    }

    /// Create an auto-reset wait handle event.
    pub fn auto_reset(initial_state: bool) -> Result<Self> {
        Self::new(false, initial_state)
    }

    pub(crate) fn from_handle_borrowed(handle: HANDLE) -> Self {
        Self {
            inner: Arc::new(OwnedHandle::borrowed(handle)),
        }
    }

    /// Return the underlying Win32 handle.
    pub fn raw_handle(&self) -> HANDLE {
        self.inner.raw()
    }

    /// Clone this wait handle with shared internal ownership.
    ///
    /// This does not duplicate the underlying OS handle.
    pub fn try_clone(&self) -> Result<Self> {
        Ok(self.clone())
    }

    /// Check if this wait handle is currently signaled without blocking.
    pub fn is_signaled(&self) -> Result<bool> {
        self.wait_timeout(Duration::ZERO)
    }

    /// Wait indefinitely until this handle is signaled.
    pub fn wait(&self) -> Result<()> {
        let wait_result = unsafe { WaitForSingleObject(self.inner.raw(), u32::MAX) };
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
            unsafe { WaitForSingleObject(self.inner.raw(), duration_to_wait_ms(timeout)) };
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

    /// Wait until any handle in `handles` is signaled.
    ///
    /// Returns the index of the signaled handle.
    pub fn wait_any(handles: &[&Self]) -> Result<usize> {
        let raw_handles = collect_raw_handles(handles)?;
        let wait_result = unsafe { WaitForMultipleObjects(&raw_handles, false, u32::MAX) };
        decode_wait_any_result(wait_result, raw_handles.len(), "wait_any")?.ok_or_else(|| {
            Error::Other(OtherError::new(Cow::Borrowed(
                "wait handle operation 'wait_any' timed out unexpectedly",
            )))
        })
    }

    /// Wait until any handle in `handles` is signaled or timeout elapses.
    ///
    /// Returns `Ok(Some(index))` for a signaled handle, `Ok(None)` on timeout.
    pub fn wait_any_timeout(handles: &[&Self], timeout: Duration) -> Result<Option<usize>> {
        let raw_handles = collect_raw_handles(handles)?;
        let wait_result =
            unsafe { WaitForMultipleObjects(&raw_handles, false, duration_to_wait_ms(timeout)) };
        decode_wait_any_result(wait_result, raw_handles.len(), "wait_any_timeout")
    }

    /// Wait until all handles in `handles` are signaled.
    pub fn wait_all(handles: &[&Self]) -> Result<()> {
        let raw_handles = collect_raw_handles(handles)?;
        let wait_result = unsafe { WaitForMultipleObjects(&raw_handles, true, u32::MAX) };
        if wait_result == WAIT_OBJECT_0 {
            return Ok(());
        }
        Err(wait_error("wait_all"))
    }

    /// Wait until all handles in `handles` are signaled or timeout elapses.
    ///
    /// Returns `Ok(true)` when all are signaled, `Ok(false)` on timeout.
    pub fn wait_all_timeout(handles: &[&Self], timeout: Duration) -> Result<bool> {
        let raw_handles = collect_raw_handles(handles)?;
        let wait_result =
            unsafe { WaitForMultipleObjects(&raw_handles, true, duration_to_wait_ms(timeout)) };
        if wait_result == WAIT_OBJECT_0 {
            return Ok(true);
        }
        if wait_result == WAIT_TIMEOUT {
            return Ok(false);
        }
        if wait_result == WAIT_FAILED {
            return Err(wait_error("wait_all_timeout"));
        }
        Err(wait_error("wait_all_timeout"))
    }

    /// Signal the wait handle.
    pub fn set(&self) -> Result<()> {
        unsafe { SetEvent(self.inner.raw()) }.map_err(|_| wait_error("set"))?;
        Ok(())
    }

    /// Reset the wait handle to unsignaled state.
    pub fn reset(&self) -> Result<()> {
        unsafe { ResetEvent(self.inner.raw()) }.map_err(|_| wait_error("reset"))?;
        Ok(())
    }

    fn create_event(
        manual_reset: bool,
        initial_state: bool,
        name: PCWSTR,
        operation: &'static str,
    ) -> Result<Self> {
        let handle = unsafe { CreateEventW(None, manual_reset, initial_state, name) };

        let handle = handle.map_err(|_| {
            let code = unsafe { GetLastError().0 as i32 };
            Error::Other(OtherError::new(Cow::Owned(format!(
                "wait handle operation '{}' failed (error code: 0x{:08X})",
                operation, code
            ))))
        })?;

        Ok(Self {
            inner: Arc::new(OwnedHandle::new(handle)),
        })
    }
}

fn collect_raw_handles(handles: &[&Wait]) -> Result<Vec<HANDLE>> {
    if handles.is_empty() {
        return Err(Error::InvalidParameter(InvalidParameterError::new(
            "handles",
            "at least one wait handle is required",
        )));
    }

    if handles.len() > MAX_WAIT_OBJECTS {
        return Err(Error::InvalidParameter(InvalidParameterError::new(
            "handles",
            "at most 64 wait handles are supported",
        )));
    }

    Ok(handles.iter().map(|h| h.raw_handle()).collect())
}

fn decode_wait_any_result(
    wait_result: windows::Win32::Foundation::WAIT_EVENT,
    handle_count: usize,
    operation: &'static str,
) -> Result<Option<usize>> {
    if wait_result == WAIT_TIMEOUT {
        return Ok(None);
    }
    if wait_result == WAIT_FAILED {
        return Err(wait_error(operation));
    }

    let result = wait_result.0;
    let base = WAIT_OBJECT_0.0;
    let end = base + handle_count as u32;
    if result >= base && result < end {
        return Ok(Some((result - base) as usize));
    }

    Err(wait_error(operation))
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

#[cfg(test)]
mod tests {
    use super::Wait;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn wait_timeout_reports_timeout_then_signal() {
        let wait = Wait::manual_reset(false).expect("wait handle create");
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
        let wait = Wait::manual_reset(false).expect("wait handle create");
        let signaler = wait.try_clone().expect("clone should succeed");

        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            signaler.set().expect("set should succeed");
        });

        wait.wait().expect("wait should succeed after signal");
        worker.join().expect("worker should not panic");
    }

    #[test]
    fn wait_any_reports_signaled_index() {
        let wait_a = Wait::manual_reset(false).expect("wait handle create");
        let wait_b = Wait::manual_reset(false).expect("wait handle create");
        wait_b.set().expect("set should succeed");

        let index = Wait::wait_any(&[&wait_a, &wait_b]).expect("wait_any should succeed");
        assert_eq!(index, 1);
    }
}
