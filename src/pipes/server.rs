use std::time::Duration;
use std::io;

use windows::Win32::Foundation::{ERROR_PIPE_CONNECTED, GetLastError};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAGS_AND_ATTRIBUTES, PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
    ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, NAMED_PIPE_MODE, PIPE_READMODE_BYTE,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::core::PCWSTR;

use crate::error::InvalidParameterError;
use crate::{Error, Result};

use super::error_map::map_pipe_windows_error;
use super::security_attrs::NativePipeSecurityAttributes;
use super::types::{
    NamedPipeOpenMode, NamedPipeType, PipeName, PipeSecurityOptions, PipeServerEndpoint,
};

/// Builder for creating a named pipe server configuration.
#[derive(Debug, Clone)]
pub struct NamedPipeServerBuilder {
    pipe_name: Option<PipeName>,
    open_mode: NamedPipeOpenMode,
    pipe_type: NamedPipeType,
    max_instances: u8,
    out_buffer_size: u32,
    in_buffer_size: u32,
    default_timeout: Duration,
    security: PipeSecurityOptions,
}

impl NamedPipeServerBuilder {
    /// Create a new named pipe server builder.
    pub fn new() -> Self {
        Self {
            pipe_name: None,
            open_mode: NamedPipeOpenMode::Duplex,
            pipe_type: NamedPipeType::Byte,
            max_instances: 1,
            out_buffer_size: 4096,
            in_buffer_size: 4096,
            default_timeout: Duration::from_secs(5),
            security: PipeSecurityOptions::default(),
        }
    }

    /// Set the named pipe path.
    pub fn pipe_name(mut self, pipe_name: PipeName) -> Self {
        self.pipe_name = Some(pipe_name);
        self
    }

    /// Set the open direction.
    pub fn open_mode(mut self, open_mode: NamedPipeOpenMode) -> Self {
        self.open_mode = open_mode;
        self
    }

    /// Set byte/message semantics.
    pub fn pipe_type(mut self, pipe_type: NamedPipeType) -> Self {
        self.pipe_type = pipe_type;
        self
    }

    /// Set number of server instances for this pipe name.
    pub fn max_instances(mut self, max_instances: u8) -> Self {
        self.max_instances = max_instances;
        self
    }

    /// Set outbound buffer size.
    pub fn out_buffer_size(mut self, out_buffer_size: u32) -> Self {
        self.out_buffer_size = out_buffer_size;
        self
    }

    /// Set inbound buffer size.
    pub fn in_buffer_size(mut self, in_buffer_size: u32) -> Self {
        self.in_buffer_size = in_buffer_size;
        self
    }

    /// Set default timeout.
    pub fn default_timeout(mut self, default_timeout: Duration) -> Self {
        self.default_timeout = default_timeout;
        self
    }

    /// Set raw security options.
    pub fn security(mut self, security: PipeSecurityOptions) -> Self {
        self.security = security;
        self
    }

    /// Build a named pipe server configuration.
    pub fn build(self) -> Result<NamedPipeServerConfig> {
        let pipe_name = self.pipe_name.ok_or_else(|| {
            Error::InvalidParameter(InvalidParameterError::new(
                "pipe_name",
                "Pipe name must be specified",
            ))
        })?;

        if self.max_instances == 0 {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "max_instances",
                "max_instances must be at least 1",
            )));
        }

        Ok(NamedPipeServerConfig {
            pipe_name,
            open_mode: self.open_mode,
            pipe_type: self.pipe_type,
            max_instances: self.max_instances,
            out_buffer_size: self.out_buffer_size,
            in_buffer_size: self.in_buffer_size,
            default_timeout: self.default_timeout,
            security: self.security,
        })
    }
}

impl Default for NamedPipeServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Named pipe server runtime configuration.
#[derive(Debug)]
pub struct NamedPipeServerConfig {
    pipe_name: PipeName,
    open_mode: NamedPipeOpenMode,
    pipe_type: NamedPipeType,
    max_instances: u8,
    out_buffer_size: u32,
    in_buffer_size: u32,
    default_timeout: Duration,
    security: PipeSecurityOptions,
}

impl NamedPipeServerConfig {
    /// Create a new builder.
    pub fn builder() -> NamedPipeServerBuilder {
        NamedPipeServerBuilder::new()
    }

    /// Create a named pipe server instance.
    pub fn create(&self) -> Result<NamedPipeServer> {
        let name_wide = to_wide(self.pipe_name.as_str());
        let open_mode = to_server_open_mode(self.open_mode);
        let pipe_mode = to_pipe_mode(self.pipe_type);
        let max_instances = if self.max_instances == u8::MAX {
            PIPE_UNLIMITED_INSTANCES
        } else {
            self.max_instances as u32
        };

        let default_timeout_ms = self.default_timeout.as_millis().min(u32::MAX as u128) as u32;
        let security_attributes =
            NativePipeSecurityAttributes::from_options(&self.security, self.pipe_name.as_str())?;

        let raw_handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name_wide.as_ptr()),
                open_mode,
                pipe_mode,
                max_instances,
                self.out_buffer_size,
                self.in_buffer_size,
                default_timeout_ms,
                security_attributes.as_option_ptr(),
            )
        };

        if raw_handle.is_invalid() {
            let code = unsafe { GetLastError().0 as i32 };
            return Err(map_pipe_windows_error(
                "create",
                Some(&self.pipe_name),
                code,
            ));
        }

        Ok(NamedPipeServer {
            endpoint: PipeServerEndpoint::from_raw(
                raw_handle,
                true,
                self.pipe_name.clone(),
                self.open_mode,
                self.pipe_type,
            ),
            default_timeout: self.default_timeout,
        })
    }

    /// Return pipe name.
    pub fn pipe_name(&self) -> &PipeName {
        &self.pipe_name
    }

    /// Return open mode.
    pub fn open_mode(&self) -> NamedPipeOpenMode {
        self.open_mode
    }

    /// Return pipe type.
    pub fn pipe_type(&self) -> NamedPipeType {
        self.pipe_type
    }

    /// Return configured max instances.
    pub fn max_instances(&self) -> u8 {
        self.max_instances
    }

    /// Return configured outbound buffer size.
    pub fn out_buffer_size(&self) -> u32 {
        self.out_buffer_size
    }

    /// Return configured inbound buffer size.
    pub fn in_buffer_size(&self) -> u32 {
        self.in_buffer_size
    }

    /// Return default timeout.
    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Return security options.
    pub fn security(&self) -> PipeSecurityOptions {
        self.security.clone()
    }
}

/// A connected or connectable named pipe server instance.
#[derive(Debug)]
pub struct NamedPipeServer {
    endpoint: PipeServerEndpoint,
    default_timeout: Duration,
}

impl NamedPipeServer {
    /// Return the underlying endpoint.
    pub fn endpoint(&self) -> &PipeServerEndpoint {
        &self.endpoint
    }

    /// Return the configured default timeout.
    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Block until a client connects to this instance.
    pub fn connect(&self) -> Result<()> {
        let result = unsafe { ConnectNamedPipe(self.endpoint.raw_handle(), None) };
        if result.is_ok() {
            return Ok(());
        }

        let code = unsafe { GetLastError().0 as i32 };
        if code == ERROR_PIPE_CONNECTED.0 as i32 {
            return Ok(());
        }

        Err(map_pipe_windows_error(
            "connect",
            Some(self.endpoint.pipe_name()),
            code,
        ))
    }

    /// Disconnect the currently connected client.
    pub fn disconnect(&self) -> Result<()> {
        unsafe { DisconnectNamedPipe(self.endpoint.raw_handle()) }.map_err(|_| {
            let code = unsafe { GetLastError().0 as i32 };
            map_pipe_windows_error("disconnect", Some(self.endpoint.pipe_name()), code)
        })
    }
}

impl io::Read for NamedPipeServer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0u32;
        unsafe { ReadFile(self.endpoint.raw_handle(), Some(buf), Some(&mut read), None) }
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(read as usize)
    }
}

impl io::Write for NamedPipeServer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0u32;
        unsafe {
            WriteFile(
                self.endpoint.raw_handle(),
                Some(buf),
                Some(&mut written),
                None,
            )
        }
        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn to_server_open_mode(open_mode: NamedPipeOpenMode) -> FILE_FLAGS_AND_ATTRIBUTES {
    match open_mode {
        NamedPipeOpenMode::Inbound => PIPE_ACCESS_INBOUND,
        NamedPipeOpenMode::Outbound => PIPE_ACCESS_OUTBOUND,
        NamedPipeOpenMode::Duplex => PIPE_ACCESS_DUPLEX,
    }
}

fn to_pipe_mode(pipe_type: NamedPipeType) -> NAMED_PIPE_MODE {
    match pipe_type {
        NamedPipeType::Byte => NAMED_PIPE_MODE(
            PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0,
        ),
        NamedPipeType::Message => NAMED_PIPE_MODE(
            PIPE_TYPE_MESSAGE.0
                | PIPE_READMODE_MESSAGE.0
                | PIPE_WAIT.0
                | PIPE_REJECT_REMOTE_CLIENTS.0,
        ),
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
