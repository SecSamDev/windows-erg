use std::borrow::Cow;
use std::time::{Duration, SystemTime};

use windows::Win32::Foundation::HANDLE;

use crate::error::InvalidParameterError;
use crate::security::SecurityDescriptor;
use crate::utils::OwnedHandle;
use crate::{Error, Result};

/// Canonical named pipe path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PipeName(String);

impl PipeName {
    /// Prefix required by Win32 named pipes.
    pub const PREFIX: &'static str = r"\\.\pipe\";

    /// Validate and create a named pipe path.
    pub fn new(path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        if path.is_empty() {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "path",
                "Pipe name cannot be empty",
            )));
        }
        if !path.starts_with(Self::PREFIX) {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "path",
                "Pipe name must start with \\\\.\\pipe\\",
            )));
        }
        if path == Self::PREFIX {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "path",
                "Pipe name must include a segment after \\\\.\\pipe\\",
            )));
        }

        Ok(Self(path))
    }

    /// Return the canonical named pipe path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Create a canonical pipe name from a relative NamedPipe directory entry.
    pub fn from_relative_name(name: impl AsRef<str>) -> Result<Self> {
        let name = name.as_ref();
        Self::new(format!("{}{}", Self::PREFIX, name))
    }
}

impl std::fmt::Display for PipeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Snapshot metadata for a named pipe currently present in the local pipe namespace.
#[derive(Debug, Clone)]
pub struct NamedPipeInfo {
    /// Canonical pipe path (for example `\\.\pipe\my-pipe`).
    pub pipe_name: PipeName,
    /// Relative entry name as returned by the NamedPipe filesystem.
    pub relative_name: String,
    /// Optional creation time when the filesystem reports it.
    pub creation_time: Option<SystemTime>,
    /// Optional last access time when the filesystem reports it.
    pub last_access_time: Option<SystemTime>,
    /// Optional last write time when the filesystem reports it.
    pub last_write_time: Option<SystemTime>,
    /// Optional metadata change time when the filesystem reports it.
    pub change_time: Option<SystemTime>,
    /// End-of-file size reported by the filesystem.
    pub end_of_file: i64,
    /// Allocation size reported by the filesystem.
    pub allocation_size: i64,
    /// Raw Win32 file attribute bits.
    pub file_attributes: u32,
    /// Directory file index when reported by the filesystem.
    pub file_index: u32,
    /// Optional local pipe state details from `FilePipeLocalInformation`.
    pub local_info: Option<NamedPipeLocalInfo>,
}

impl NamedPipeInfo {
    /// Return the canonical pipe path.
    pub fn pipe_name(&self) -> &PipeName {
        &self.pipe_name
    }
}

/// Local named-pipe state details returned by `FilePipeLocalInformation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedPipeLocalInfo {
    /// Named pipe type as reported by the kernel.
    pub named_pipe_type: u32,
    /// Server/client configuration value.
    pub named_pipe_configuration: u32,
    /// Maximum pipe instances allowed.
    pub maximum_instances: u32,
    /// Current number of connected/open instances.
    pub current_instances: u32,
    /// Inbound quota size in bytes.
    pub inbound_quota: u32,
    /// Bytes currently available for reading.
    pub read_data_available: u32,
    /// Outbound quota size in bytes.
    pub outbound_quota: u32,
    /// Remaining write quota in bytes.
    pub write_quota_available: u32,
    /// Current pipe state value.
    pub named_pipe_state: u32,
    /// Whether this handle points at server or client end.
    pub named_pipe_end: u32,
    /// PID of the server process that created this pipe, if available.
    pub server_process_id: Option<crate::types::ProcessId>,
}

/// Change detected between named pipe snapshots.
#[derive(Debug, Clone)]
pub enum NamedPipeChange {
    /// A pipe is present in the current snapshot but was absent previously.
    Appeared(NamedPipeInfo),
    /// A pipe disappeared since the previous snapshot.
    Removed(NamedPipeInfo),
}

pub(crate) fn filetime_to_system_time(filetime: i64) -> Option<SystemTime> {
    const FILETIME_TO_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

    if filetime <= 0 {
        return None;
    }

    let intervals_since_unix = filetime.saturating_sub(FILETIME_TO_UNIX_EPOCH);
    let seconds = intervals_since_unix.div_euclid(10_000_000) as u64;
    let nanos = (intervals_since_unix.rem_euclid(10_000_000) as u32) * 100;

    Some(SystemTime::UNIX_EPOCH + Duration::new(seconds, nanos))
}

/// Access direction for a named pipe instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedPipeOpenMode {
    /// Read-only server endpoint.
    Inbound,
    /// Write-only server endpoint.
    Outbound,
    /// Read/write server endpoint.
    Duplex,
}

/// Message semantics for a named pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedPipeType {
    /// Byte stream mode.
    Byte,
    /// Message-framed mode.
    Message,
}

/// Security attributes used when creating or opening a pipe handle.
#[derive(Debug, Clone)]
pub struct PipeSecurityOptions {
    /// Whether spawned child processes can inherit this handle.
    pub inherit_handle: bool,
    /// Optional descriptor model used for ACL/owner semantics.
    pub security_descriptor: Option<SecurityDescriptor>,
}

impl PipeSecurityOptions {
    /// Create default security options.
    pub fn new() -> Self {
        Self {
            inherit_handle: false,
            security_descriptor: None,
        }
    }

    /// Enable or disable handle inheritance.
    pub fn inherit_handle(mut self, inherit_handle: bool) -> Self {
        self.inherit_handle = inherit_handle;
        self
    }

    /// Set a structured security descriptor model.
    pub fn security_descriptor(mut self, security_descriptor: SecurityDescriptor) -> Self {
        self.security_descriptor = Some(security_descriptor);
        self
    }
}

impl Default for PipeSecurityOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Server-side named pipe endpoint handle.
#[derive(Debug)]
pub struct PipeServerEndpoint {
    handle: OwnedHandle,
    pipe_name: PipeName,
    open_mode: NamedPipeOpenMode,
    pipe_type: NamedPipeType,
}

impl PipeServerEndpoint {
    /// Create a server endpoint from a raw handle.
    pub(crate) fn from_raw(
        handle: HANDLE,
        close_on_drop: bool,
        pipe_name: PipeName,
        open_mode: NamedPipeOpenMode,
        pipe_type: NamedPipeType,
    ) -> Self {
        Self {
            handle: OwnedHandle::with_ownership(handle, close_on_drop),
            pipe_name,
            open_mode,
            pipe_type,
        }
    }

    /// Return underlying Win32 handle.
    pub fn raw_handle(&self) -> HANDLE {
        self.handle.raw()
    }

    /// Return named pipe path.
    pub fn pipe_name(&self) -> &PipeName {
        &self.pipe_name
    }

    /// Return open direction.
    pub fn open_mode(&self) -> NamedPipeOpenMode {
        self.open_mode
    }

    /// Return byte/message behavior.
    pub fn pipe_type(&self) -> NamedPipeType {
        self.pipe_type
    }

    /// Configure whether this handle should be closed on drop.
    pub fn set_close_on_drop(&mut self, close_on_drop: bool) {
        self.handle.set_close_on_drop(close_on_drop);
    }
}

/// Client-side named pipe endpoint handle.
#[derive(Debug)]
pub struct PipeClientEndpoint {
    handle: OwnedHandle,
    pipe_name: PipeName,
    open_mode: NamedPipeOpenMode,
}

impl PipeClientEndpoint {
    /// Create a client endpoint from a raw handle.
    pub(crate) fn from_raw(
        handle: HANDLE,
        close_on_drop: bool,
        pipe_name: PipeName,
        open_mode: NamedPipeOpenMode,
    ) -> Self {
        Self {
            handle: OwnedHandle::with_ownership(handle, close_on_drop),
            pipe_name,
            open_mode,
        }
    }

    /// Return underlying Win32 handle.
    pub fn raw_handle(&self) -> HANDLE {
        self.handle.raw()
    }

    /// Return named pipe path.
    pub fn pipe_name(&self) -> &PipeName {
        &self.pipe_name
    }

    /// Return open direction.
    pub fn open_mode(&self) -> NamedPipeOpenMode {
        self.open_mode
    }

    /// Configure whether this handle should be closed on drop.
    pub fn set_close_on_drop(&mut self, close_on_drop: bool) {
        self.handle.set_close_on_drop(close_on_drop);
    }
}

pub(crate) fn to_cow_pipe_name(pipe_name: Option<&PipeName>) -> Cow<'static, str> {
    match pipe_name {
        Some(name) => Cow::Owned(name.to_string()),
        None => Cow::Borrowed("<unnamed pipe>"),
    }
}
