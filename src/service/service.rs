use std::time::{Duration, Instant};

use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, QueryServiceStatusEx, StartServiceW, SC_STATUS_PROCESS_INFO,
    SC_HANDLE, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
};
use windows::core::PCWSTR;

use super::status::ServiceStatus;
use super::types::{ServiceAccess, ServiceControl, ServiceState};
use crate::error::{
    Error, ServiceError, ServiceInvalidStateError, ServiceNotFoundError, ServiceOperationError,
};
use crate::Result;

/// Handle to an opened Windows service.
pub struct Service {
    handle: SC_HANDLE,
    name: String,
}

impl Service {
    pub(crate) fn new(handle: SC_HANDLE, name: String) -> Self {
        Service { handle, name }
    }

    /// Open a service by name using default access rights.
    pub fn open(name: &str) -> Result<Self> {
        super::manager::ServiceManager::connect()?.open_with_access(name, ServiceAccess::QueryStatus)
    }

    /// Open a service by name with explicit access rights.
    pub fn open_with_access(name: &str, access: ServiceAccess) -> Result<Self> {
        super::manager::ServiceManager::connect()?.open_with_access(name, access)
    }

    /// Service key name.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Query current service status.
    pub fn query(&self) -> Result<ServiceStatus> {
        let mut work_buffer = Vec::with_capacity(std::mem::size_of::<SERVICE_STATUS_PROCESS>());
        self.query_with_buffer(&mut work_buffer)
    }

    /// Query current service status using a reusable workspace buffer.
    pub fn query_with_buffer(&self, work_buffer: &mut Vec<u8>) -> Result<ServiceStatus> {
        work_buffer.clear();

        let mut bytes_needed = 0u32;
        let _ = unsafe {
            QueryServiceStatusEx(
                self.handle,
                SC_STATUS_PROCESS_INFO,
                None,
                &mut bytes_needed,
            )
        };

        let required = (bytes_needed as usize).max(std::mem::size_of::<SERVICE_STATUS_PROCESS>());
        if work_buffer.len() < required {
            work_buffer.resize(required, 0);
        }

        unsafe {
            QueryServiceStatusEx(
                self.handle,
                SC_STATUS_PROCESS_INFO,
                Some(work_buffer),
                &mut bytes_needed,
            )
        }
        .map_err(|e| {
            if e.code().0 == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult().0 {
                return Error::Service(ServiceError::NotFound(ServiceNotFoundError::with_code(
                    self.name.clone(),
                    e.code().0,
                )));
            }

            Error::Service(ServiceError::OperationFailed(ServiceOperationError::with_code(
                self.name.clone(),
                "query",
                "QueryServiceStatusEx failed",
                e.code().0,
            )))
        })?;

        let raw = unsafe { &*(work_buffer.as_ptr() as *const SERVICE_STATUS_PROCESS) };
        Ok(ServiceStatus::from_status_process(
            self.name.clone(),
            None,
            raw,
        ))
    }

    /// Start the service.
    pub fn start(&self) -> Result<()> {
        unsafe { StartServiceW(self.handle, None) }.map_err(|e| {
            Error::Service(ServiceError::OperationFailed(ServiceOperationError::with_code(
                self.name.clone(),
                "start",
                "StartServiceW failed",
                e.code().0,
            )))
        })
    }

    /// Stop the service.
    pub fn stop(&self) -> Result<()> {
        self.send_control(ServiceControl::Stop)
    }

    /// Send a control code to the service.
    pub fn send_control(&self, control: ServiceControl) -> Result<()> {
        let mut status = SERVICE_STATUS::default();
        unsafe {
            ControlService(self.handle, control.to_windows(), &mut status)
        }
        .map_err(|e| {
            Error::Service(ServiceError::OperationFailed(ServiceOperationError::with_code(
                self.name.clone(),
                control.operation_name(),
                "ControlService failed",
                e.code().0,
            )))
        })
    }

    /// Restart the service by waiting for stopped state and then starting it.
    pub fn restart(&self, timeout: Duration) -> Result<()> {
        self.stop()?;
        self.wait_for_state(ServiceState::Stopped, timeout)?;
        self.start()
    }

    fn wait_for_state(&self, desired: ServiceState, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let mut work_buffer = Vec::with_capacity(std::mem::size_of::<SERVICE_STATUS_PROCESS>());
        let mut last_checkpoint = 0u32;
        let mut checkpoint_stale_since = Instant::now();

        while start.elapsed() <= timeout {
            let status = self.query_with_buffer(&mut work_buffer)?;
            if status.state == desired {
                return Ok(());
            }

            if status.checkpoint != last_checkpoint {
                last_checkpoint = status.checkpoint;
                checkpoint_stale_since = Instant::now();
            }

            if checkpoint_stale_since.elapsed() > timeout {
                break;
            }

            let wait_hint_ms = status.wait_hint_ms.clamp(100, 10_000);
            let poll_ms = (wait_hint_ms / 10).clamp(100, 1000);
            std::thread::sleep(Duration::from_millis(poll_ms as u64));
        }

        Err(Error::Service(ServiceError::InvalidState(
            ServiceInvalidStateError::new(
                self.name.clone(),
                desired.as_str(),
                "timed out waiting for state transition",
            ),
        )))
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.handle) };
    }
}

pub(crate) fn as_pcwstr(wide: &[u16]) -> PCWSTR {
    PCWSTR(wide.as_ptr())
}
