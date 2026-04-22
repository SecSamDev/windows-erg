//! Windows pipe operations.
//!
//! This module contains the initial API surface for Windows named and anonymous
//! pipes. The first implementation phase provides core types, builders, and
//! structured error mapping helpers.

mod anonymous;
mod client;
mod error_map;
mod integration;
mod security_attrs;
mod server;
mod types;

use crate::Error;

pub use anonymous::{
    AnonymousPipeBuilder, AnonymousPipeConfig, AnonymousPipeReader, AnonymousPipeWriter,
};
pub use client::{NamedPipeClient, NamedPipeClientBuilder, NamedPipeClientConfig};
pub use integration::{ChildPipeEndpoints, PipeStdio};
pub use server::{NamedPipeServer, NamedPipeServerBuilder, NamedPipeServerConfig};
pub use crate::wait::WaitHandle;
pub use types::{
    NamedPipeOpenMode, NamedPipeType, PipeClientEndpoint, PipeName, PipeSecurityOptions,
    PipeServerEndpoint,
};

/// Convert Win32 pipe error codes to structured crate errors.
pub fn map_win32_pipe_error(
    operation: &'static str,
    pipe_name: Option<&PipeName>,
    error_code: i32,
) -> Error {
    error_map::map_pipe_windows_error(operation, pipe_name, error_code)
}
