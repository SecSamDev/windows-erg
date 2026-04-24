use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SERVICE_DOES_NOT_EXIST};
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW,
    OpenServiceW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
};

use super::service::{Service, as_pcwstr};
use super::status::ServiceStatus;
use super::types::{ServiceAccess, ServiceManagerAccess};
use crate::Result;
use crate::error::{
    AccessDeniedError, Error, InvalidParameterError, NotFoundError, ServiceError,
    ServiceManagerError, ServiceNotFoundError,
};
use crate::utils::to_utf16_nul;

/// Handle to the Windows Service Control Manager.
pub struct ServiceManager {
    handle: SC_HANDLE,
}

impl ServiceManager {
    /// Open a service manager handle with default connect + enumeration rights.
    pub fn connect() -> Result<Self> {
        let rights = SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE;
        Self::connect_with_access(ServiceManagerAccess::Custom(rights))
    }

    /// Open a service manager handle with explicit access rights.
    pub fn connect_with_access(access: ServiceManagerAccess) -> Result<Self> {
        let handle = unsafe { OpenSCManagerW(None, None, access.to_windows()) }.map_err(|e| {
            if e.code().0 == ERROR_ACCESS_DENIED.to_hresult().0 {
                return Error::AccessDenied(AccessDeniedError::new("service manager", "connect"));
            }

            Error::Service(ServiceError::ManagerError(ServiceManagerError::with_code(
                "connect",
                "OpenSCManagerW failed",
                e.code().0,
            )))
        })?;

        Ok(ServiceManager { handle })
    }

    /// Open a service by name with default access (query/start/stop/pause-continue).
    pub fn open(&self, name: &str) -> Result<Service> {
        let access = ServiceAccess::QueryStatus.to_windows()
            | ServiceAccess::Start.to_windows()
            | ServiceAccess::Stop.to_windows()
            | ServiceAccess::PauseContinue.to_windows();
        self.open_with_access(name, ServiceAccess::Custom(access))
    }

    /// Open a service by name with explicit access rights.
    pub fn open_with_access(&self, name: &str, access: ServiceAccess) -> Result<Service> {
        if name.trim().is_empty() {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "name",
                "service name cannot be empty",
            )));
        }

        let name_wide = to_utf16_nul(name);
        let handle =
            unsafe { OpenServiceW(self.handle, as_pcwstr(&name_wide), access.to_windows()) }
                .map_err(|e| {
                    if e.code().0 == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult().0 {
                        return Error::NotFound(NotFoundError::new("service", name.to_owned()));
                    }
                    if e.code().0 == ERROR_ACCESS_DENIED.to_hresult().0 {
                        return Error::AccessDenied(AccessDeniedError::new(
                            name.to_owned(),
                            "open",
                        ));
                    }

                    Error::Service(ServiceError::NotFound(ServiceNotFoundError::with_code(
                        name.to_owned(),
                        e.code().0,
                    )))
                })?;

        Ok(Service::new(handle, name.to_owned()))
    }

    /// Enumerate all services.
    pub fn list(&self) -> Result<Vec<ServiceStatus>> {
        let mut out_services = Vec::with_capacity(256);
        self.list_with_buffer(&mut out_services)?;
        Ok(out_services)
    }

    /// Enumerate all services into a reusable output buffer.
    pub fn list_with_buffer(&self, out_services: &mut Vec<ServiceStatus>) -> Result<usize> {
        self.list_with_filter(out_services, |_| true)
    }

    /// Enumerate services into a reusable output buffer, filtered during enumeration.
    pub fn list_with_filter<F>(
        &self,
        out_services: &mut Vec<ServiceStatus>,
        filter: F,
    ) -> Result<usize>
    where
        F: Fn(&ServiceStatus) -> bool,
    {
        out_services.clear();

        let mut work_buffer = Vec::new();
        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;

        let _ = unsafe {
            EnumServicesStatusExW(
                self.handle,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                None,
                &mut bytes_needed,
                &mut services_returned,
                None,
                None,
            )
        };

        if bytes_needed == 0 {
            return Ok(0);
        }

        work_buffer.resize(bytes_needed as usize, 0);

        unsafe {
            EnumServicesStatusExW(
                self.handle,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(&mut work_buffer),
                &mut bytes_needed,
                &mut services_returned,
                None,
                None,
            )
        }
        .map_err(|e| {
            Error::Service(ServiceError::ManagerError(ServiceManagerError::with_code(
                "enumerate",
                "EnumServicesStatusExW failed",
                e.code().0,
            )))
        })?;

        let entries = unsafe {
            std::slice::from_raw_parts(
                work_buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                services_returned as usize,
            )
        };

        for entry in entries {
            let status = ServiceStatus::from_enum_status(entry);
            if filter(&status) {
                out_services.push(status);
            }
        }

        Ok(out_services.len())
    }
}

impl Drop for ServiceManager {
    fn drop(&mut self) {
        let _ = unsafe { CloseServiceHandle(self.handle) };
    }
}
