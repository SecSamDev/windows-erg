use windows::Win32::System::Services::{ENUM_SERVICE_STATUS_PROCESSW, SERVICE_STATUS_PROCESS};

use super::types::ServiceState;

/// Runtime status for a Windows service.
#[derive(Debug, Clone)]
pub struct ServiceStatus {
    /// Service key name.
    pub name: String,
    /// Optional display name when available.
    pub display_name: Option<String>,
    /// Current service state.
    pub state: ServiceState,
    /// Process ID owning the service instance (0 for some stopped/shared services).
    pub process_id: u32,
    /// Service type flags.
    pub service_type: u32,
    /// Accepted control flags.
    pub controls_accepted: u32,
    /// Win32 exit code.
    pub exit_code: u32,
    /// Service-specific exit code.
    pub service_specific_exit_code: u32,
    /// Checkpoint value for pending states.
    pub checkpoint: u32,
    /// Wait hint in milliseconds.
    pub wait_hint_ms: u32,
    /// Service flags.
    pub service_flags: u32,
}

impl ServiceStatus {
    pub(crate) fn from_status_process(
        name: String,
        display_name: Option<String>,
        status: &SERVICE_STATUS_PROCESS,
    ) -> Self {
        ServiceStatus {
            name,
            display_name,
            state: ServiceState::from_windows(status.dwCurrentState),
            process_id: status.dwProcessId,
            service_type: status.dwServiceType.0,
            controls_accepted: status.dwControlsAccepted,
            exit_code: status.dwWin32ExitCode,
            service_specific_exit_code: status.dwServiceSpecificExitCode,
            checkpoint: status.dwCheckPoint,
            wait_hint_ms: status.dwWaitHint,
            service_flags: status.dwServiceFlags.0,
        }
    }

    pub(crate) fn from_enum_status(raw: &ENUM_SERVICE_STATUS_PROCESSW) -> Self {
        ServiceStatus {
            name: unsafe { read_pwstr(raw.lpServiceName.0) },
            display_name: Some(unsafe { read_pwstr(raw.lpDisplayName.0) }),
            state: ServiceState::from_windows(raw.ServiceStatusProcess.dwCurrentState),
            process_id: raw.ServiceStatusProcess.dwProcessId,
            service_type: raw.ServiceStatusProcess.dwServiceType.0,
            controls_accepted: raw.ServiceStatusProcess.dwControlsAccepted,
            exit_code: raw.ServiceStatusProcess.dwWin32ExitCode,
            service_specific_exit_code: raw.ServiceStatusProcess.dwServiceSpecificExitCode,
            checkpoint: raw.ServiceStatusProcess.dwCheckPoint,
            wait_hint_ms: raw.ServiceStatusProcess.dwWaitHint,
            service_flags: raw.ServiceStatusProcess.dwServiceFlags.0,
        }
    }
}

unsafe fn read_pwstr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }

    let mut len = 0usize;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }

    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}
