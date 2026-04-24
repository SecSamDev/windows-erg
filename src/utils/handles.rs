use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// RAII wrapper for Win32 `HANDLE` values.
///
/// This type supports both owned and borrowed handle semantics using the
/// `close_on_drop` flag.
#[derive(Debug)]
pub struct OwnedHandle {
    handle: HANDLE,
    close_on_drop: bool,
}

impl OwnedHandle {
    /// Create an owned handle that closes on drop.
    pub fn new(handle: HANDLE) -> Self {
        Self {
            handle,
            close_on_drop: true,
        }
    }

    /// Create a handle with explicit ownership behavior.
    pub fn with_ownership(handle: HANDLE, close_on_drop: bool) -> Self {
        Self {
            handle,
            close_on_drop,
        }
    }

    /// Create a borrowed handle that does not close on drop.
    pub fn borrowed(handle: HANDLE) -> Self {
        Self {
            handle,
            close_on_drop: false,
        }
    }

    /// Return the raw Win32 handle.
    pub fn raw(&self) -> HANDLE {
        self.handle
    }

    /// Configure whether this handle closes on drop.
    pub fn set_close_on_drop(&mut self, close_on_drop: bool) {
        self.close_on_drop = close_on_drop;
    }

    /// Return whether this handle closes on drop.
    pub fn close_on_drop(&self) -> bool {
        self.close_on_drop
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.close_on_drop && !self.handle.is_invalid() && self.handle != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}
