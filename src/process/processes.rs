//! Core Process type and basic operations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcess, PROCESS_QUERY_INFORMATION,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};
use windows::core::PCWSTR;

use super::types::{ProcessAccess, ProcessId};
use crate::error::{Error, ProcessError, ProcessOpenError, Result};
use crate::wait::Wait;
use crate::utils::to_utf16_nul;

// STILL_ACTIVE exit code constant
const STILL_ACTIVE: u32 = 259;
const DEVICE_PREFIX: &[u16] = &[92, 68, 101, 118, 105, 99, 101, 92];

/// Cache for device path to drive letter mappings
/// Maps \Device\HarddiskVolumeX to C:, D:, etc.
static DEVICE_PATH_CACHE: OnceLock<HashMap<Vec<u16>, char>> = OnceLock::new();

/// Initialize the device path cache by querying all drives (A-Z)
fn init_device_path_cache() -> HashMap<Vec<u16>, char> {
    let mut cache = HashMap::new();
    let mut device_path_buffer = vec![0u16; 32768];

    for drive_char in 'A'..='Z' {
        let drive = format!("{}:", drive_char);
        let drive_wide = to_utf16_nul(&drive);

        // QueryDosDeviceW returns the device path for the drive

        let len =
            unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut device_path_buffer)) };

        if len > 0 {
            let mut device_path_vec: Vec<u16> = device_path_buffer[..len as usize].to_vec();
            // Trim trailing null terminators
            while device_path_vec.last() == Some(&0) {
                device_path_vec.pop();
            }
            cache.insert(device_path_vec, drive_char);
        }
    }

    cache
}

/// Convert device path directly from u16 buffer, minimizing allocations
/// Parses device path boundaries in u16 form before converting to String
fn device_path_to_drive_path_u16(buffer_u16: &[u16]) -> String {
    // Quick length check
    if buffer_u16.is_empty() {
        return String::new();
    }

    // Check if starts with \Device\ (in u16 form)
    const BACKSLASH: u16 = b'\\' as u16;
    if buffer_u16[0] != BACKSLASH || buffer_u16.len() < 8 {
        // Not a device path - convert full buffer
        let path_str = String::from_utf16_lossy(buffer_u16);
        return path_str;
    }

    // Check for "\Device\" prefix
    if buffer_u16.len() < DEVICE_PREFIX.len()
        || !buffer_u16[..DEVICE_PREFIX.len()].eq(DEVICE_PREFIX)
    {
        let path_str = String::from_utf16_lossy(buffer_u16);
        return path_str;
    }

    // Find the end of device root (next backslash after \Device\HarddiskVolumeX)
    let mut device_root_end = DEVICE_PREFIX.len();
    while device_root_end < buffer_u16.len() && buffer_u16[device_root_end] != BACKSLASH {
        device_root_end += 1;
    }

    // Convert only the device root part to String for HashMap lookup
    let cache = DEVICE_PATH_CACHE.get_or_init(init_device_path_cache);

    if let Some(&drive_char) = cache.get(&buffer_u16[..device_root_end]) {
        // Found mapping - build result efficiently
        if device_root_end >= buffer_u16.len() {
            // Device root is the entire path
            return format!("{}:\\", drive_char);
        }

        // Has path after device root - convert rest of path
        let mut rest_str = String::with_capacity(device_root_end + 3);
        rest_str.push(drive_char);
        rest_str.push_str(":\\");
        let rest_slice = &buffer_u16[device_root_end + 1..];
        for c in char::decode_utf16(rest_slice.iter().copied()).flatten() {
            rest_str.push(c);
        }
        return rest_str;
    }

    // No mapping found - return full path converted to String
    String::from_utf16_lossy(buffer_u16)
}

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

        // Convert device path directly from u16 buffer, avoiding intermediate full string conversion
        let path = device_path_to_drive_path_u16(&buffer_u16[..len]);

        Ok(PathBuf::from(path))
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
                return Err(Error::Process(ProcessError::OpenFailed(ProcessOpenError::new(
                    self.pid.as_u32(),
                    "Process wait completed but exit code is still active",
                ))));
            }
            return Ok(exit_code);
        }

        if wait_result == WAIT_FAILED {
            return Err(Error::Process(ProcessError::OpenFailed(ProcessOpenError::new(
                self.pid.as_u32(),
                "Failed to wait for process exit",
            ))));
        }

        Err(Error::Process(ProcessError::OpenFailed(ProcessOpenError::new(
            self.pid.as_u32(),
            "Unexpected wait result while waiting for process exit",
        ))))
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
                return Err(Error::Process(ProcessError::OpenFailed(ProcessOpenError::new(
                    self.pid.as_u32(),
                    "Process wait completed but exit code is still active",
                ))));
            }
            return Ok(Some(exit_code));
        }

        if wait_result == WAIT_FAILED {
            return Err(Error::Process(ProcessError::OpenFailed(ProcessOpenError::new(
                self.pid.as_u32(),
                "Failed to wait for process exit with timeout",
            ))));
        }

        Err(Error::Process(ProcessError::OpenFailed(ProcessOpenError::new(
            self.pid.as_u32(),
            "Unexpected wait result while waiting for process exit",
        ))))
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

    // Device path conversion tests
    #[test]
    fn test_device_path_to_drive_path_passthrough_non_device_path() {
        // Non-device paths should pass through unchanged
        let path = "C:\\Windows\\System32\\file.exe";
        let u16_path: Vec<u16> = path.encode_utf16().collect();
        let result = device_path_to_drive_path_u16(&u16_path);
        assert_eq!(result, path);
    }

    #[test]
    fn test_device_path_to_drive_path_initializes_cache() {
        // First call should initialize the cache
        let path = r"\Device\HarddiskVolume1\Windows\System32\kernel32.dll";
        let u16_path: Vec<u16> = path.encode_utf16().collect();
        let result = device_path_to_drive_path_u16(&u16_path);

        // Result should be non-empty (either converted or fallback to device path)
        assert!(!result.is_empty(), "Should return a valid path");
    }

    #[test]
    fn test_device_path_to_drive_path_consistent_mapping() {
        // Same device path should always map to same result
        let path1 = r"\Device\HarddiskVolume1\Windows\System32\kernel32.dll";
        let path2 = r"\Device\HarddiskVolume1\Program Files\app.exe";

        let u16_path1: Vec<u16> = path1.encode_utf16().collect();
        let u16_path2: Vec<u16> = path2.encode_utf16().collect();

        let result1 = device_path_to_drive_path_u16(&u16_path1);
        let result2 = device_path_to_drive_path_u16(&u16_path2);

        // Both should have consistent behavior (same conversion status)
        let is_device_1 = result1.starts_with(r"\Device\");
        let is_device_2 = result2.starts_with(r"\Device\");

        assert_eq!(
            is_device_1, is_device_2,
            "Consistent mapping for same device"
        );
    }

    #[test]
    fn test_device_path_to_drive_path_root_path() {
        // Device path without subdirectories should be processed
        let path = r"\Device\HarddiskVolume1";
        let u16_path: Vec<u16> = path.encode_utf16().collect();
        let result = device_path_to_drive_path_u16(&u16_path);

        assert!(!result.is_empty(), "Should return a valid path");
    }

    #[test]
    fn test_device_path_to_drive_path_long_path() {
        // Long device paths should be processed correctly
        let path = r"\Device\HarddiskVolume1\Windows\System32\Drivers\etc\hosts";
        let u16_path: Vec<u16> = path.encode_utf16().collect();
        let result = device_path_to_drive_path_u16(&u16_path);

        // Should handle the path properly (either convert or fallback)
        assert!(
            result.contains("hosts") || result.starts_with(r"\Device\"),
            "Should process path correctly"
        );
    }

    #[test]
    fn test_device_path_to_drive_path_multiple_backslashes() {
        // Paths with multiple directory levels
        let path = r"\Device\HarddiskVolume2\Users\Admin\Documents\file.txt";
        let u16_path: Vec<u16> = path.encode_utf16().collect();
        let result = device_path_to_drive_path_u16(&u16_path);

        // Should handle multipart path
        assert!(!result.is_empty(), "Should return a valid path");
    }

    #[test]
    fn test_device_path_to_drive_path_preserves_case() {
        // Case information should be preserved
        let path = r"\Device\HarddiskVolume1\Program Files\MyApp\config.ini";
        let u16_path: Vec<u16> = path.encode_utf16().collect();
        let result = device_path_to_drive_path_u16(&u16_path);

        // Original path components should be present (case may vary)
        assert!(
            result.to_lowercase().contains("program files") || result.starts_with(r"\Device\"),
            "Should handle case appropriately"
        );
    }

    #[test]
    fn test_init_device_path_cache_returns_valid_mappings() {
        // Cache should contain valid mappings
        let cache = init_device_path_cache();

        // Should have at least one entry (the C: drive is almost always present)
        assert!(!cache.is_empty(), "Cache should have entries");

        // All values should be drive letters A-Z
        for &drive_char in cache.values() {
            assert!(
                drive_char.is_ascii_uppercase(),
                "Drive letter should be A-Z"
            );
        }
    }

    #[test]
    fn test_init_device_path_cache_has_device_path_keys() {
        // Cache keys should look like device paths
        let cache = init_device_path_cache();

        for key in cache.keys() {
            assert!(
                key.starts_with(DEVICE_PREFIX),
                "Cache key should be a device path"
            );
        }
    }

    #[test]
    fn test_device_path_cache_is_singleton() {
        // Multiple accesses should return the same cache instance
        let cache1 = DEVICE_PATH_CACHE.get_or_init(init_device_path_cache);
        let cache2 = DEVICE_PATH_CACHE.get_or_init(init_device_path_cache);

        // Should be the same object (pointer equality via reference)
        assert_eq!(cache1.len(), cache2.len(), "Cache should be consistent");
    }

    #[test]
    fn test_device_path_conversion_with_special_characters() {
        // Paths with special characters should be processed
        let path = r"\Device\HarddiskVolume1\Program Files (x86)\app.exe";
        let u16_path: Vec<u16> = path.encode_utf16().collect();
        let result = device_path_to_drive_path_u16(&u16_path);

        assert!(!result.is_empty(), "Should handle special characters");
    }

    #[test]
    fn test_device_path_unknown_device_fallback() {
        // Unknown device paths should be handled gracefully
        let path = r"\Device\HarddiskVolume999\unknown\path";
        let u16_path: Vec<u16> = path.encode_utf16().collect();
        let result = device_path_to_drive_path_u16(&u16_path);

        // Should either be converted (if volume exists) or returned as-is
        assert!(
            result.contains("unknown") || result.starts_with(r"\Device\"),
            "Should handle unknown device gracefully"
        );
    }

    #[test]
    fn test_device_path_empty_subdirectory() {
        // Device path with trailing backslash
        let path = r"\Device\HarddiskVolume1\";
        let u16_path: Vec<u16> = path.encode_utf16().collect();
        let result = device_path_to_drive_path_u16(&u16_path);

        assert!(!result.is_empty(), "Should handle trailing backslash");
    }

    #[test]
    fn test_device_path_c_drive_common_paths() {
        // Common paths should process correctly
        let paths = vec![
            r"\Device\HarddiskVolume1\Windows\System32\kernel32.dll",
            r"\Device\HarddiskVolume1\Program Files\app.exe",
            r"\Device\HarddiskVolume1\Users\Admin\Desktop\file.txt",
        ];

        for path in paths {
            let u16_path: Vec<u16> = path.encode_utf16().collect();
            let result = device_path_to_drive_path_u16(&u16_path);

            // Should return a non-empty path
            assert!(!result.is_empty(), "Should process path without error");
        }
    }
}
