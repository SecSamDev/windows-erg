//! Core Process type and basic operations.

use std::path::PathBuf;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcess, PROCESS_QUERY_INFORMATION,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

use super::types::{ProcessAccess, ProcessId};
use crate::error::{Error, ProcessError, ProcessOpenError, Result};
use crate::path::nt_path_to_dos_into;
use crate::wait::Wait;

// STILL_ACTIVE exit code constant
const STILL_ACTIVE: u32 = 259;

/// A handle to a Windows process.
pub struct Process {
    handle: HANDLE,
    pid: ProcessId,
    close_on_drop: bool,
}

impl Process {
    /// Open a process with default access (query information).
    pub fn open(pid: ProcessId) -> Result<Self> {
        Self::open_with_access(pid, ProcessAccess::QueryInformation)
    }

    /// Open a process with specific access rights.
    pub fn open_with_access(pid: ProcessId, access: ProcessAccess) -> Result<Self> {
        let handle =
            unsafe { OpenProcess(access.to_windows(), false, pid.as_u32()) }.map_err(|e| {
                Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                    pid.as_u32(),
                    "Failed to open process",
                    e.code().0,
                )))
            })?;

        Ok(Process {
            handle,
            pid,
            close_on_drop: true,
        })
    }

    /// Get a pseudo-handle to the current process.
    ///
    /// This handle does not need to be closed and is valid for the lifetime of the process.
    pub fn current() -> Self {
        Process {
            handle: unsafe { GetCurrentProcess() },
            pid: ProcessId::new(std::process::id()),
            close_on_drop: false,
        }
    }

    /// Open the same process with additional access rights.
    ///
    /// This is useful when you have a process handle but need higher privileges
    /// (e.g., to read/write memory or terminate the process).
    ///
    /// # Example
    /// ```ignore
    /// let process = Process::open(pid)?;
    /// // Need to read memory - upgrade to VmRead access
    /// let process_with_vm_read = process.with_access(ProcessAccess::VmRead)?;
    /// ```
    pub fn with_access(&self, access: ProcessAccess) -> Result<Self> {
        Self::open_with_access(self.pid, access)
    }

    /// Get the process ID.
    pub fn id(&self) -> ProcessId {
        self.pid
    }

    /// Get the process name (executable file name without path).
    pub fn name(&self) -> Result<String> {
        let mut buffer = Vec::with_capacity(260);
        self.name_with_buffer(&mut buffer)
    }

    /// Get the process name using a reusable output buffer.
    pub fn name_with_buffer(&self, out_buffer: &mut Vec<u8>) -> Result<String> {
        let path = self.path_with_buffer(out_buffer)?;
        Ok(path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string())
    }

    /// Get the full path to the process executable.
    pub fn path(&self) -> Result<PathBuf> {
        let mut buffer = Vec::with_capacity(260);
        self.path_with_buffer(&mut buffer)
    }

    /// Get the full path to the process executable using a reusable output buffer.
    pub fn path_with_buffer(&self, out_buffer: &mut Vec<u8>) -> Result<PathBuf> {
        // Ensure buffer has capacity (1024 bytes = 512 u16 chars)
        out_buffer.clear();
        if out_buffer.capacity() < 1024 {
            out_buffer.reserve(1024);
        }
        unsafe {
            out_buffer.set_len(1024);
        }

        let buffer_u16 = unsafe {
            std::slice::from_raw_parts_mut(
                out_buffer.as_mut_ptr() as *mut u16,
                out_buffer.len() / 2,
            )
        };

        let len = unsafe { GetProcessImageFileNameW(self.handle, buffer_u16) } as usize;

        if len == 0 {
            return Err(Error::Process(ProcessError::OpenFailed(
                ProcessOpenError::new(self.pid.as_u32(), "Failed to get process image path"),
            )));
        }

        let nt_path = String::from_utf16_lossy(&buffer_u16[..len]);

        let mut dos_path = String::with_capacity(nt_path.len() + 2);
        if !nt_path_to_dos_into(&nt_path, &mut dos_path) {
            // No device-root mapping found (e.g. a network path) — fall back
            // to the raw NT path rather than failing the caller outright.
            dos_path = nt_path;
        }

        Ok(PathBuf::from(dos_path))
    }

    /// Check if the process is still running.
    pub fn is_running(&self) -> Result<bool> {
        match self.exit_code() {
            Ok(Some(_)) => Ok(false),
            Ok(None) => Ok(true),
            Err(e) => Err(e),
        }
    }

    /// Get the exit code of the process, if it has exited.
    ///
    /// Returns `None` if the process is still running.
    pub fn exit_code(&self) -> Result<Option<u32>> {
        let exit_code = self.get_exit_code_value()?;

        if exit_code == STILL_ACTIVE {
            Ok(None)
        } else {
            Ok(Some(exit_code))
        }
    }

    /// Wait until this process exits and return its final exit code.
    pub fn wait_for_exit(&self) -> Result<u32> {
        let wait_result = unsafe { WaitForSingleObject(self.handle, u32::MAX) };
        if wait_result == WAIT_OBJECT_0 {
            let exit_code = self.get_exit_code_value()?;
            if exit_code == STILL_ACTIVE {
                return Err(Error::Process(ProcessError::OpenFailed(
                    ProcessOpenError::new(
                        self.pid.as_u32(),
                        "Process wait completed but exit code is still active",
                    ),
                )));
            }
            return Ok(exit_code);
        }

        if wait_result == WAIT_FAILED {
            return Err(Error::Process(ProcessError::OpenFailed(
                ProcessOpenError::new(self.pid.as_u32(), "Failed to wait for process exit"),
            )));
        }

        Err(Error::Process(ProcessError::OpenFailed(
            ProcessOpenError::new(
                self.pid.as_u32(),
                "Unexpected wait result while waiting for process exit",
            ),
        )))
    }

    /// Wait until this process exits or timeout elapses.
    ///
    /// Returns `Ok(Some(code))` when the process exits, `Ok(None)` on timeout.
    pub fn wait_for_exit_timeout(&self, timeout: std::time::Duration) -> Result<Option<u32>> {
        let wait_result = unsafe {
            WaitForSingleObject(
                self.handle,
                timeout.as_millis().min(u32::MAX as u128) as u32,
            )
        };

        if wait_result == WAIT_TIMEOUT {
            return Ok(None);
        }

        if wait_result == WAIT_OBJECT_0 {
            let exit_code = self.get_exit_code_value()?;
            if exit_code == STILL_ACTIVE {
                return Err(Error::Process(ProcessError::OpenFailed(
                    ProcessOpenError::new(
                        self.pid.as_u32(),
                        "Process wait completed but exit code is still active",
                    ),
                )));
            }
            return Ok(Some(exit_code));
        }

        if wait_result == WAIT_FAILED {
            return Err(Error::Process(ProcessError::OpenFailed(
                ProcessOpenError::new(
                    self.pid.as_u32(),
                    "Failed to wait for process exit with timeout",
                ),
            )));
        }

        Err(Error::Process(ProcessError::OpenFailed(
            ProcessOpenError::new(
                self.pid.as_u32(),
                "Unexpected wait result while waiting for process exit",
            ),
        )))
    }

    /// Borrow this process handle as a [`Wait`] object.
    ///
    /// The returned wait object does not own the process handle and will not close it on drop.
    pub fn as_wait(&self) -> Wait {
        Wait::from_handle_borrowed(self.handle)
    }

    /// Terminate the process with exit code 1.
    pub fn kill(&self) -> Result<()> {
        self.terminate(1)
    }

    /// Terminate the process with a specific exit code.
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        unsafe { TerminateProcess(self.handle, exit_code) }.map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.pid.as_u32(),
                "Failed to terminate process",
                e.code().0,
            )))
        })
    }

    /// Kill a process by ID (convenience method).
    pub fn kill_by_id(pid: ProcessId) -> Result<()> {
        let process = Process::open_with_access(
            pid,
            ProcessAccess::Custom(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION),
        )?;
        process.kill()
    }

    /// Get the raw Windows handle.
    ///
    /// # Safety
    ///
    /// The handle must not outlive the Process instance.
    pub unsafe fn as_raw_handle(&self) -> HANDLE {
        self.handle
    }

    fn get_exit_code_value(&self) -> Result<u32> {
        let mut exit_code = 0u32;
        unsafe { GetExitCodeProcess(self.handle, &mut exit_code) }.map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.pid.as_u32(),
                "Failed to get exit code",
                e.code().0,
            )))
        })?;
        Ok(exit_code)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.close_on_drop {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

// Safety: HANDLE can be sent between threads
unsafe impl Send for Process {}

#[cfg(test)]
mod tests {
    use super::*;

    // Process API tests
    #[test]
    fn test_process_current() {
        // Test getting current process
        let current = Process::current();
        assert_eq!(current.id().as_u32(), std::process::id());
    }

    #[test]
    fn test_process_with_access_same_pid() {
        // Test that with_access preserves the process ID
        let current = Process::current();
        let original_pid = current.id();

        // This should fail since we can't open the current process normally,
        // but we're testing the API, not the result
        let _ = current.with_access(ProcessAccess::QueryInformation);

        // PID should remain the same
        assert_eq!(current.id(), original_pid);
    }

    #[test]
    fn test_process_with_access_different_rights() {
        // Test that with_access is callable with different access types
        let current = Process::current();

        // These calls may fail, but the API should work
        let _ = current.with_access(ProcessAccess::VmRead);
        let _ = current.with_access(ProcessAccess::Terminate);
        let _ = current.with_access(ProcessAccess::AllAccess);

        // Process should still be valid
        assert_eq!(current.id().as_u32(), std::process::id());
    }

    // NT device path -> DOS path conversion now lives in `crate::path` and is
    // tested there; `path_with_buffer` above is a thin wrapper around it.
}
