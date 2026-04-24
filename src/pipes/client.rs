use std::io;
use std::time::Duration;

use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING, ReadFile, WriteFile,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use windows::core::PCWSTR;

use crate::error::InvalidParameterError;
use crate::utils::to_utf16_nul;
use crate::{Error, Result};

use super::error_map::map_pipe_windows_error;
use super::security_attrs::NativePipeSecurityAttributes;
use super::types::{NamedPipeOpenMode, PipeClientEndpoint, PipeName, PipeSecurityOptions};

/// Builder for named pipe client configuration.
#[derive(Debug, Clone)]
pub struct NamedPipeClientBuilder {
    pipe_name: Option<PipeName>,
    open_mode: NamedPipeOpenMode,
    connect_timeout: Duration,
    security: PipeSecurityOptions,
}

impl NamedPipeClientBuilder {
    /// Create a new named pipe client builder.
    pub fn new() -> Self {
        Self {
            pipe_name: None,
            open_mode: NamedPipeOpenMode::Duplex,
            connect_timeout: Duration::from_secs(5),
            security: PipeSecurityOptions::default(),
        }
    }

    /// Set the named pipe path.
    pub fn pipe_name(mut self, pipe_name: PipeName) -> Self {
        self.pipe_name = Some(pipe_name);
        self
    }

    /// Set open direction.
    pub fn open_mode(mut self, open_mode: NamedPipeOpenMode) -> Self {
        self.open_mode = open_mode;
        self
    }

    /// Set connect timeout.
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    /// Set raw security options.
    pub fn security(mut self, security: PipeSecurityOptions) -> Self {
        self.security = security;
        self
    }

    /// Build a named pipe client configuration.
    pub fn build(self) -> Result<NamedPipeClientConfig> {
        let pipe_name = self.pipe_name.ok_or_else(|| {
            Error::InvalidParameter(InvalidParameterError::new(
                "pipe_name",
                "Pipe name must be specified",
            ))
        })?;

        Ok(NamedPipeClientConfig {
            pipe_name,
            open_mode: self.open_mode,
            connect_timeout: self.connect_timeout,
            security: self.security,
        })
    }
}

impl Default for NamedPipeClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Named pipe client runtime configuration.
#[derive(Debug)]
pub struct NamedPipeClientConfig {
    pipe_name: PipeName,
    open_mode: NamedPipeOpenMode,
    connect_timeout: Duration,
    security: PipeSecurityOptions,
}

impl NamedPipeClientConfig {
    /// Create a new builder.
    pub fn builder() -> NamedPipeClientBuilder {
        NamedPipeClientBuilder::new()
    }

    /// Connect to the target named pipe endpoint.
    pub fn connect(&self) -> Result<NamedPipeClient> {
        let pipe_name_wide = to_utf16_nul(self.pipe_name.as_str());
        let timeout_ms = self.connect_timeout.as_millis().min(u32::MAX as u128) as u32;

        let waited = unsafe { WaitNamedPipeW(PCWSTR(pipe_name_wide.as_ptr()), timeout_ms) };
        if !waited.as_bool() {
            let code = unsafe { GetLastError().0 as i32 };
            return Err(map_pipe_windows_error(
                "connect",
                Some(&self.pipe_name),
                code,
            ));
        }

        let security_attributes =
            NativePipeSecurityAttributes::from_options(&self.security, self.pipe_name.as_str())?;

        let desired_access = to_client_access(self.open_mode);
        let raw_handle = unsafe {
            CreateFileW(
                PCWSTR(pipe_name_wide.as_ptr()),
                desired_access,
                FILE_SHARE_MODE(0),
                security_attributes.as_option_ptr(),
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .map_err(|e| map_pipe_windows_error("connect", Some(&self.pipe_name), e.code().0))?;

        Ok(NamedPipeClient {
            endpoint: PipeClientEndpoint::from_raw(
                raw_handle,
                true,
                self.pipe_name.clone(),
                self.open_mode,
            ),
        })
    }

    /// Return named pipe path.
    pub fn pipe_name(&self) -> &PipeName {
        &self.pipe_name
    }

    /// Return open mode.
    pub fn open_mode(&self) -> NamedPipeOpenMode {
        self.open_mode
    }

    /// Return configured connect timeout.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Return security options.
    pub fn security(&self) -> PipeSecurityOptions {
        self.security.clone()
    }
}

/// A connected named pipe client handle.
#[derive(Debug)]
pub struct NamedPipeClient {
    endpoint: PipeClientEndpoint,
}

impl NamedPipeClient {
    /// Return the underlying endpoint.
    pub fn endpoint(&self) -> &PipeClientEndpoint {
        &self.endpoint
    }
}

impl io::Read for NamedPipeClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0u32;
        unsafe { ReadFile(self.endpoint.raw_handle(), Some(buf), Some(&mut read), None) }
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(read as usize)
    }
}

impl io::Write for NamedPipeClient {
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

fn to_client_access(open_mode: NamedPipeOpenMode) -> u32 {
    match open_mode {
        NamedPipeOpenMode::Inbound => GENERIC_READ.0,
        NamedPipeOpenMode::Outbound => GENERIC_WRITE.0,
        NamedPipeOpenMode::Duplex => GENERIC_READ.0 | GENERIC_WRITE.0,
    }
}
