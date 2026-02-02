//! Thread enumeration and operations.

use windows::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_FILES};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
    TH32CS_SNAPTHREAD,
};

use crate::error::{Error, ProcessError, ProcessOpenError, Result};
use super::types::{ProcessId, ThreadId, ThreadInfo};
use super::processes::Process;

impl Process {
    /// Enumerate all threads in this process.
    pub fn threads(&self) -> Result<Vec<ThreadInfo>> {
        let mut buffer = Vec::with_capacity(256);
        self.threads_with_buffer(&mut buffer)?;
        Ok(buffer)
    }

    /// Enumerate threads using a reusable output buffer.
    pub fn threads_with_buffer(&self, out_threads: &mut Vec<ThreadInfo>) -> Result<usize> {
        self.threads_with_filter(out_threads, |_| true)
    }

    /// Enumerate threads matching a filter using a reusable output buffer.
    ///
    /// The filter function is called for each thread. Only threads where the filter
    /// returns `true` are added to the output buffer. This is more efficient than enumerating all
    /// and filtering afterwards.
    ///
    /// Returns the number of matching threads found and added to the buffer.
    pub fn threads_with_filter<F>(&self, out_threads: &mut Vec<ThreadInfo>, filter: F) -> Result<usize>
    where
        F: Fn(&ThreadInfo) -> bool,
    {
        out_threads.clear();
        
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
            .map_err(|e| {
                Error::Process(ProcessError::OpenFailed(
                    ProcessOpenError::with_code(self.id().as_u32(), "Failed to create thread snapshot", e.code().0)
                ))
            })?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let process_id = self.id().as_u32();

        if unsafe { Thread32First(snapshot, &mut entry) }.is_ok() {
            loop {
                // Only include threads from this process
                if entry.th32OwnerProcessID == process_id {
                    let thread_info = ThreadInfo {
                        tid: ThreadId::new(entry.th32ThreadID),
                        pid: ProcessId::new(entry.th32OwnerProcessID),
                        base_priority: entry.tpBasePri,
                    };

                    // Apply filter and add to output buffer if it matches
                    if filter(&thread_info) {
                        out_threads.push(thread_info);
                    }
                }

                // Get next entry
                match unsafe { Thread32Next(snapshot, &mut entry) } {
                    Ok(_) => continue,
                    Err(e) if e.code() == ERROR_NO_MORE_FILES.into() => break,
                    Err(_) => break,
                }
            }
        }

        unsafe { let _ = CloseHandle(snapshot); }
        Ok(out_threads.len())
    }
}
