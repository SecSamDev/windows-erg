//! Memory information and statistics.

use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};

use super::processes::Process;
use super::types::MemoryInfo;
use crate::error::{Error, ProcessError, ProcessOpenError, Result};

impl Process {
    /// Get memory usage information for this process.
    pub fn memory_info(&self) -> Result<MemoryInfo> {
        let mut counters = windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };

        unsafe { GetProcessMemoryInfo(self.as_raw_handle(), &mut counters, counters.cb) }.map_err(
            |e| {
                Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                    self.id().as_u32(),
                    "Failed to get process memory info",
                    e.code().0,
                )))
            },
        )?;

        Ok(MemoryInfo {
            working_set: counters.WorkingSetSize,
            peak_working_set: counters.PeakWorkingSetSize,
            page_fault_count: counters.PageFaultCount,
        })
    }
}
