//! Windows Service Control Manager operations.
//!
//! This module provides ergonomic wrappers around the Windows Service Control
//! Manager (SCM) APIs for querying and controlling services.

#![allow(clippy::module_inception)]

mod manager;
mod service;
mod status;
mod types;

pub use manager::ServiceManager;
pub use service::Service;
pub use status::ServiceStatus;
pub use types::{ServiceAccess, ServiceControl, ServiceManagerAccess, ServiceState};

use std::time::Duration;

use crate::Result;

/// Query a service status by name.
pub fn query(name: &str) -> Result<ServiceStatus> {
    Service::open(name)?.query()
}

/// Start a service by name.
pub fn start(name: &str) -> Result<()> {
    Service::open_with_access(name, ServiceAccess::Start)?.start()
}

/// Stop a service by name.
pub fn stop(name: &str) -> Result<()> {
    Service::open_with_access(name, ServiceAccess::Stop)?.stop()
}

/// Restart a service by name, waiting for stopped state before start.
pub fn restart(name: &str, timeout: Duration) -> Result<()> {
    Service::open_with_access(
        name,
        ServiceAccess::Custom(
            ServiceAccess::QueryStatus.to_windows()
                | ServiceAccess::Start.to_windows()
                | ServiceAccess::Stop.to_windows(),
        ),
    )?
    .restart(timeout)
}

/// List all services.
pub fn list() -> Result<Vec<ServiceStatus>> {
    ServiceManager::connect()?.list()
}

/// List all services using a reusable output buffer.
///
/// Returns the number of services added to the output buffer.
pub fn list_with_buffer(out_services: &mut Vec<ServiceStatus>) -> Result<usize> {
    ServiceManager::connect()?.list_with_buffer(out_services)
}

/// List matching services using a reusable output buffer.
///
/// Returns the number of services added to the output buffer.
pub fn list_with_filter<F>(out_services: &mut Vec<ServiceStatus>, filter: F) -> Result<usize>
where
    F: Fn(&ServiceStatus) -> bool,
{
    ServiceManager::connect()?.list_with_filter(out_services, filter)
}
