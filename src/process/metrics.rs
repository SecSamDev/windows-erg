//! Host and process metrics.

use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::{
    ALL_PROCESSOR_GROUPS, GetActiveProcessorCount, GetProcessTimes, GetSystemTimes,
};

use super::processes::Process;
use super::types::{
    HostMemoryMetrics, HostMetrics, ProcessCpuTimes, ProcessMemoryMetrics, ProcessMetrics,
};
use crate::error::{Error, InvalidParameterError, ProcessError, ProcessOpenError, Result};

impl Process {
    /// Get cumulative process CPU time counters.
    ///
    /// Returned values are cumulative since process start in 100ns units.
    pub fn cpu_times(&self) -> Result<ProcessCpuTimes> {
        let mut creation_time = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel_time = FILETIME::default();
        let mut user_time = FILETIME::default();

        unsafe {
            GetProcessTimes(
                self.as_raw_handle(),
                &mut creation_time,
                &mut exit_time,
                &mut kernel_time,
                &mut user_time,
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to get process CPU times",
                e.code().0,
            )))
        })?;

        let kernel = filetime_to_u64_100ns(kernel_time);
        let user = filetime_to_u64_100ns(user_time);

        Ok(ProcessCpuTimes {
            user_time_100ns: user,
            kernel_time_100ns: kernel,
            total_time_100ns: kernel.saturating_add(user),
        })
    }

    /// Get extended memory metrics for this process.
    pub fn memory_metrics(&self) -> Result<ProcessMemoryMetrics> {
        let mut counters = PROCESS_MEMORY_COUNTERS_EX {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            ..Default::default()
        };

        unsafe {
            GetProcessMemoryInfo(
                self.as_raw_handle(),
                &mut counters as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
                counters.cb,
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to get process memory metrics",
                e.code().0,
            )))
        })?;

        Ok(ProcessMemoryMetrics {
            working_set_bytes: counters.WorkingSetSize,
            peak_working_set_bytes: counters.PeakWorkingSetSize,
            page_fault_count: counters.PageFaultCount,
            private_usage_bytes: counters.PrivateUsage,
            commit_usage_bytes: counters.PagefileUsage,
            peak_commit_usage_bytes: counters.PeakPagefileUsage,
        })
    }

    /// Get point-in-time CPU and memory metrics for this process.
    pub fn metrics(&self) -> Result<ProcessMetrics> {
        Ok(ProcessMetrics {
            memory: self.memory_metrics()?,
            cpu: self.cpu_times()?,
        })
    }

    /// Calculate process CPU usage percentage over a sampling interval.
    ///
    /// The returned value is normalized to whole-machine CPU usage scale [0.0, 100.0].
    pub fn cpu_usage(&self, interval: Duration) -> Result<f64> {
        if interval.is_zero() {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "interval",
                "interval must be greater than zero",
            )));
        }

        let start_proc = self.cpu_times()?;
        let (_, start_kernel, start_user) = read_system_times_100ns()?;

        thread::sleep(interval);

        let end_proc = self.cpu_times()?;
        let (_, end_kernel, end_user) = read_system_times_100ns()?;

        let start_total = start_kernel.saturating_add(start_user);
        let end_total = end_kernel.saturating_add(end_user);

        Ok(calculate_cpu_percentage(
            start_proc.total_time_100ns,
            end_proc.total_time_100ns,
            start_total,
            end_total,
        ))
    }
}

/// Get point-in-time host metrics.
pub fn host_metrics() -> Result<HostMetrics> {
    let mut memory_status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };

    unsafe { GlobalMemoryStatusEx(&mut memory_status) }.map_err(|e| {
        Error::WindowsApi(crate::error::WindowsApiError::with_context(
            e,
            "GlobalMemoryStatusEx",
        ))
    })?;

    let logical_cpu_count = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };

    Ok(HostMetrics {
        logical_cpu_count,
        memory: HostMemoryMetrics {
            total_physical_bytes: memory_status.ullTotalPhys,
            available_physical_bytes: memory_status.ullAvailPhys,
            total_virtual_bytes: memory_status.ullTotalVirtual,
            available_virtual_bytes: memory_status.ullAvailVirtual,
            memory_load_percent: memory_status.dwMemoryLoad,
        },
    })
}

/// Calculate overall host CPU usage percentage over a sampling interval.
///
/// The returned value is in the range [0.0, 100.0].
pub fn host_cpu_usage(interval: Duration) -> Result<f64> {
    if interval.is_zero() {
        return Err(Error::InvalidParameter(InvalidParameterError::new(
            "interval",
            "interval must be greater than zero",
        )));
    }

    let (idle_start, kernel_start, user_start) = read_system_times_100ns()?;
    thread::sleep(interval);
    let (idle_end, kernel_end, user_end) = read_system_times_100ns()?;

    let total_start = kernel_start.saturating_add(user_start);
    let total_end = kernel_end.saturating_add(user_end);
    let total_delta = total_end.saturating_sub(total_start);
    if total_delta == 0 {
        return Ok(0.0);
    }

    let idle_delta = idle_end.saturating_sub(idle_start);
    let busy_delta = total_delta.saturating_sub(idle_delta);
    let usage = (busy_delta as f64 / total_delta as f64) * 100.0;
    Ok(usage.clamp(0.0, 100.0))
}

fn read_system_times_100ns() -> Result<(u64, u64, u64)> {
    let mut idle = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();

    unsafe {
        GetSystemTimes(
            Some(&mut idle as *mut FILETIME),
            Some(&mut kernel as *mut FILETIME),
            Some(&mut user as *mut FILETIME),
        )
    }
    .map_err(|e| {
        Error::WindowsApi(crate::error::WindowsApiError::with_context(
            e,
            "GetSystemTimes",
        ))
    })?;

    Ok((
        filetime_to_u64_100ns(idle),
        filetime_to_u64_100ns(kernel),
        filetime_to_u64_100ns(user),
    ))
}

fn filetime_to_u64_100ns(file_time: FILETIME) -> u64 {
    ((file_time.dwHighDateTime as u64) << 32) | (file_time.dwLowDateTime as u64)
}

fn calculate_cpu_percentage(start_proc: u64, end_proc: u64, start_sys: u64, end_sys: u64) -> f64 {
    let proc_delta = end_proc.saturating_sub(start_proc);
    let sys_delta = end_sys.saturating_sub(start_sys);

    if sys_delta == 0 {
        return 0.0;
    }

    ((proc_delta as f64 / sys_delta as f64) * 100.0).clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::calculate_cpu_percentage;

    #[test]
    fn cpu_percentage_zero_when_no_delta() {
        let usage = calculate_cpu_percentage(100, 100, 1000, 1000);
        assert_eq!(usage, 0.0);
    }

    #[test]
    fn cpu_percentage_computes_expected_ratio() {
        let usage = calculate_cpu_percentage(100, 300, 1000, 2000);
        assert!((usage - 20.0).abs() < 0.000_1);
    }
}
