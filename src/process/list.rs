//! Process listing and enumeration.

use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_FILES};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

use super::processes::Process;
use super::types::{ProcessId, ProcessInfo};
use crate::error::{Error, ProcessError, ProcessOpenError, Result};

impl Process {
    /// List all processes in the system.
    pub fn list() -> Result<Vec<ProcessInfo>> {
        let mut buffer = Vec::with_capacity(128);
        Self::list_with_buffer(&mut buffer)?;
        Ok(buffer)
    }

    /// List all processes using a reusable output buffer.
    ///
    /// Returns the number of processes found and added to the buffer.
    pub fn list_with_buffer(out_processes: &mut Vec<ProcessInfo>) -> Result<usize> {
        Self::list_with_filter_impl(out_processes, |_| true)
    }

    /// List all processes matching a filter using a reusable output buffer.
    ///
    /// The filter function is called for each process. Only processes where the filter
    /// returns `true` are added to the buffer. This is more efficient than listing all
    /// and filtering afterwards as it avoids unnecessary buffer operations.
    ///
    /// Returns the number of matching processes found and added to the buffer.
    pub fn list_with_filter<F>(out_processes: &mut Vec<ProcessInfo>, filter: F) -> Result<usize>
    where
        F: Fn(&ProcessInfo) -> bool,
    {
        Self::list_with_filter_impl(out_processes, filter)
    }

    /// Internal: Common implementation for list enumeration with optional filtering.
    fn list_with_filter_impl<F>(out_processes: &mut Vec<ProcessInfo>, filter: F) -> Result<usize>
    where
        F: Fn(&ProcessInfo) -> bool,
    {
        // Clear the output buffer for reuse
        out_processes.clear();

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                0,
                "Failed to create process snapshot",
                e.code().0,
            )))
        })?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
            loop {
                // Extract process name
                let name_end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..name_end]);

                let parent_pid = if entry.th32ParentProcessID == 0 {
                    None
                } else {
                    Some(ProcessId::new(entry.th32ParentProcessID))
                };

                let process_info = ProcessInfo {
                    pid: ProcessId::new(entry.th32ProcessID),
                    parent_pid,
                    name,
                    thread_count: entry.cntThreads,
                };

                // Apply filter and add to output buffer if it matches
                if filter(&process_info) {
                    out_processes.push(process_info);
                }

                // Get next entry
                match unsafe { Process32NextW(snapshot, &mut entry) } {
                    Ok(_) => continue,
                    Err(e) if e.code() == ERROR_NO_MORE_FILES.into() => break,
                    Err(_) => break,
                }
            }
        }

        unsafe {
            let _ = CloseHandle(snapshot);
        }
        Ok(out_processes.len())
    }

    /// Get the parent process ID.
    pub fn parent_id(&self) -> Result<Option<ProcessId>> {
        // We need to enumerate processes to find parent
        let processes = Self::list()?;

        for proc in processes {
            if proc.pid == self.id() {
                return Ok(proc.parent_pid);
            }
        }

        Ok(None)
    }

    /// Get all immediate child processes.
    pub fn children(&self) -> Result<Vec<ProcessId>> {
        let mut buffer = Vec::with_capacity(128);
        self.children_with_buffer(&mut buffer)?;
        // Convert buffer of ProcessInfo to Vec<ProcessId>
        Ok(buffer.into_iter().map(|p| p.pid).collect())
    }

    /// Get all immediate child processes using a reusable buffer.
    pub fn children_with_buffer(&self, buffer: &mut Vec<ProcessInfo>) -> Result<usize> {
        let self_id = self.id();
        Self::list_with_filter(buffer, |p| p.parent_pid == Some(self_id))
    }
}
