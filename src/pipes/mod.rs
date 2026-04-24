//! Windows pipe operations.
//!
//! This module contains the initial API surface for Windows named and anonymous
//! pipes. The first implementation phase provides core types, builders, and
//! structured error mapping helpers.

mod anonymous;
mod client;
mod enumerate;
mod error_map;
mod integration;
mod security_attrs;
mod server;
mod types;

use crate::Error;

pub use crate::wait::Wait;
pub use anonymous::{
    AnonymousPipeBuilder, AnonymousPipeConfig, AnonymousPipeReader, AnonymousPipeWriter,
};
pub use client::{NamedPipeClient, NamedPipeClientBuilder, NamedPipeClientConfig};
pub use enumerate::NamedPipePoller;
pub use integration::{ChildPipeEndpoints, PipeStdio};
pub use server::{NamedPipeServer, NamedPipeServerBuilder, NamedPipeServerConfig};
pub use types::{
    NamedPipeChange, NamedPipeInfo, NamedPipeLocalInfo, NamedPipeOpenMode, NamedPipeType,
    PipeClientEndpoint, PipeName, PipeSecurityOptions, PipeServerEndpoint,
};

use crate::Result;
use std::time::Duration;

/// Convert Win32 pipe error codes to structured crate errors.
pub fn map_win32_pipe_error(
    operation: &'static str,
    pipe_name: Option<&PipeName>,
    error_code: i32,
) -> Error {
    error_map::map_pipe_windows_error(operation, pipe_name, error_code)
}

/// List all currently available named pipes in the local pipe namespace.
pub fn list() -> Result<Vec<NamedPipeInfo>> {
    enumerate::list()
}

/// List all currently available named pipes using a reusable output buffer.
pub fn list_with_buffer(out_pipes: &mut Vec<NamedPipeInfo>) -> Result<usize> {
    enumerate::list_with_buffer(out_pipes)
}

/// List matching named pipes using a reusable output buffer.
pub fn list_with_filter<F>(out_pipes: &mut Vec<NamedPipeInfo>, filter: F) -> Result<usize>
where
    F: Fn(&NamedPipeInfo) -> bool,
{
    enumerate::list_with_filter(out_pipes, filter)
}

/// Query `FilePipeLocalInformation` for a specific named pipe.
pub fn query_local_info(pipe_name: &PipeName) -> Result<NamedPipeLocalInfo> {
    enumerate::query_local_info(pipe_name)
}

/// Poll named-pipe snapshots at a fixed interval for a fixed number of rounds.
pub fn poll_interval(rounds: usize, interval: Duration) -> Result<Vec<Vec<NamedPipeChange>>> {
    enumerate::poll_interval(rounds, interval)
}

/// Poll named-pipe snapshots at a fixed interval and invoke a callback each round.
///
/// Returns the total number of changes observed across all rounds.
pub fn poll_interval_with_callback<F>(
    rounds: usize,
    interval: Duration,
    callback: F,
) -> Result<usize>
where
    F: FnMut(usize, &[NamedPipeChange]),
{
    enumerate::poll_interval_with_callback(rounds, interval, callback)
}
