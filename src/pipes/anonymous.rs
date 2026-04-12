use std::io;

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Pipes::CreatePipe;

use crate::{Error, Result};

use super::security_attrs::NativePipeSecurityAttributes;
use super::types::PipeSecurityOptions;

/// Builder for anonymous pipe configuration.
#[derive(Debug, Clone)]
pub struct AnonymousPipeBuilder {
    buffer_size: u32,
    security: PipeSecurityOptions,
}

impl AnonymousPipeBuilder {
    /// Create a new anonymous pipe builder.
    pub fn new() -> Self {
        Self {
            buffer_size: 4096,
            security: PipeSecurityOptions::default(),
        }
    }

    /// Set requested pipe buffer size.
    pub fn buffer_size(mut self, buffer_size: u32) -> Self {
        self.buffer_size = buffer_size;
        self
    }

    /// Set security options.
    pub fn security(mut self, security: PipeSecurityOptions) -> Self {
        self.security = security;
        self
    }

    /// Build anonymous pipe configuration.
    pub fn build(self) -> AnonymousPipeConfig {
        AnonymousPipeConfig {
            buffer_size: self.buffer_size,
            security: self.security,
        }
    }
}

impl Default for AnonymousPipeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Anonymous pipe runtime configuration.
#[derive(Debug, Clone)]
pub struct AnonymousPipeConfig {
    buffer_size: u32,
    security: PipeSecurityOptions,
}

impl AnonymousPipeConfig {
    /// Return configured buffer size.
    pub fn buffer_size(&self) -> u32 {
        self.buffer_size
    }

    /// Return configured security options.
    pub fn security(&self) -> PipeSecurityOptions {
        self.security.clone()
    }

    /// Create an anonymous pipe pair.
    pub fn create(&self) -> Result<(AnonymousPipeReader, AnonymousPipeWriter)> {
        let mut read_handle = HANDLE::default();
        let mut write_handle = HANDLE::default();

        let security_attributes =
            NativePipeSecurityAttributes::from_options(&self.security, "<anonymous>")?;

        unsafe {
            CreatePipe(
                &mut read_handle,
                &mut write_handle,
                security_attributes.as_option_ptr(),
                self.buffer_size,
            )
        }
        .map_err(|e| {
            Error::Pipe(crate::error::PipeError::Create(
                crate::error::PipeCreateError::with_code("<anonymous>", "create", e.code().0),
            ))
        })?;

        Ok((
            AnonymousPipeReader {
                handle: OwnedAnonymousHandle::new(read_handle),
            },
            AnonymousPipeWriter {
                handle: OwnedAnonymousHandle::new(write_handle),
            },
        ))
    }
}

#[derive(Debug)]
struct OwnedAnonymousHandle {
    handle: HANDLE,
}

impl OwnedAnonymousHandle {
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for OwnedAnonymousHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() && self.handle != INVALID_HANDLE_VALUE {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

/// Read endpoint for an anonymous pipe.
#[derive(Debug)]
pub struct AnonymousPipeReader {
    handle: OwnedAnonymousHandle,
}

impl AnonymousPipeReader {
    /// Return raw handle value.
    pub fn raw_handle(&self) -> HANDLE {
        self.handle.raw()
    }
}

impl io::Read for AnonymousPipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0u32;
        unsafe { ReadFile(self.handle.raw(), Some(buf), Some(&mut read), None) }
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(read as usize)
    }
}

/// Write endpoint for an anonymous pipe.
#[derive(Debug)]
pub struct AnonymousPipeWriter {
    handle: OwnedAnonymousHandle,
}

impl AnonymousPipeWriter {
    /// Return raw handle value.
    pub fn raw_handle(&self) -> HANDLE {
        self.handle.raw()
    }
}

impl io::Write for AnonymousPipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0u32;
        unsafe { WriteFile(self.handle.raw(), Some(buf), Some(&mut written), None) }
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
