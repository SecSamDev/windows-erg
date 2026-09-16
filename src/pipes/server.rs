use std::borrow::Cow;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use windows::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, GetLastError,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_FLAGS_AND_ATTRIBUTES,
    FlushFileBuffers, PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND, ReadFile,
    WriteFile,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    NAMED_PIPE_MODE, PIPE_READMODE_BYTE, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{INFINITE, WaitForMultipleObjects, WaitForSingleObject};
use windows::core::PCWSTR;

use crate::error::{
    AccessDeniedError, InvalidParameterError, PipeConnectError, PipeError, PipeTimeoutError,
};
use crate::process::{Process, ProcessId};
use crate::utils::io::{PipeReadError, classify_pipe_read_error, win_to_io_error, win32_code};
use crate::utils::to_utf16_nul;
use crate::wait::Wait;
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
    allowed_executables: Vec<PathBuf>,
    first_instance: bool,
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
            allowed_executables: Vec::new(),
            first_instance: false,
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

    /// Fail creation if a pipe with this name already exists
    /// (`FILE_FLAG_FIRST_PIPE_INSTANCE`).
    ///
    /// Use this for well-known service pipes: it stops another process from
    /// squatting on the name before the service starts, since the service then
    /// refuses to share the pipe instead of silently joining it.
    pub fn first_instance(mut self, first_instance: bool) -> Self {
        self.first_instance = first_instance;
        self
    }

    /// Restrict connections to processes whose executable path matches one of the given paths.
    ///
    /// The comparison is case-insensitive. If no paths are added (the default), all processes
    /// are allowed to connect.
    pub fn allow_executable(mut self, path: impl Into<PathBuf>) -> Self {
        self.allowed_executables.push(path.into());
        self
    }

    /// Remove a previously added executable path from the allow-list.
    ///
    /// The comparison is case-insensitive. Does nothing if the path is not present.
    pub fn remove_executable(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        self.allowed_executables.retain(|p| {
            !p.as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&path.as_os_str().to_string_lossy())
        });
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
            allowed_executables: self.allowed_executables,
            first_instance: self.first_instance,
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
    allowed_executables: Vec<PathBuf>,
    first_instance: bool,
}

impl NamedPipeServerConfig {
    /// Create a new builder.
    pub fn builder() -> NamedPipeServerBuilder {
        NamedPipeServerBuilder::new()
    }

    /// Create a named pipe server instance.
    pub fn create(&self) -> Result<NamedPipeServer> {
        let name_wide = to_utf16_nul(self.pipe_name.as_str());
        let mut open_mode = to_server_open_mode(self.open_mode);
        if self.first_instance {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
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
            allowed_executables: self.allowed_executables.clone(),
            io_event: Wait::manual_reset(false)?,
            io_timeout: None,
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
    allowed_executables: Vec<PathBuf>,
    /// Completion event reused by every overlapped read/write.
    io_event: Wait,
    io_timeout: Option<Duration>,
}

impl NamedPipeServer {
    /// Return the underlying endpoint.
    pub fn endpoint(&self) -> &PipeServerEndpoint {
        &self.endpoint
    }

    /// Limit how long a single [`io::Read::read`] or [`io::Write::write`] may
    /// block. `None` (the default) waits indefinitely.
    ///
    /// A timed-out operation is cancelled and reported as
    /// [`io::ErrorKind::TimedOut`]; the connection stays usable.
    pub fn set_io_timeout(&mut self, timeout: Option<Duration>) {
        self.io_timeout = timeout;
    }

    /// Return the per-operation I/O timeout.
    pub fn io_timeout(&self) -> Option<Duration> {
        self.io_timeout
    }

    /// Return the configured default timeout.
    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Add an executable path to the allow-list.
    ///
    /// The comparison is case-insensitive. If no paths are in the allow-list (the default),
    /// all processes are allowed to connect.
    pub fn allow_executable(&mut self, path: impl Into<PathBuf>) {
        self.allowed_executables.push(path.into());
    }

    /// Remove an executable path from the allow-list.
    ///
    /// The comparison is case-insensitive. Does nothing if the path is not present.
    pub fn remove_executable(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        self.allowed_executables.retain(|p| {
            !p.as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&path.as_os_str().to_string_lossy())
        });
    }

    /// Block until a client connects to this instance.
    ///
    /// If an executable allow-list was configured via [`NamedPipeServerBuilder::allow_executable`],
    /// the connecting process's image path is checked against the list. If it does not match,
    /// the connection is immediately disconnected and an [`Error::AccessDenied`] error is returned.
    /// An empty allow-list (the default) permits all processes to connect.
    pub fn connect(&self) -> Result<()> {
        let result = unsafe { ConnectNamedPipe(self.endpoint.raw_handle(), None) };
        if result.is_err() {
            let code = unsafe { GetLastError().0 as i32 };
            if code != ERROR_PIPE_CONNECTED.0 as i32 {
                return Err(map_pipe_windows_error(
                    "connect",
                    Some(self.endpoint.pipe_name()),
                    code,
                ));
            }
        }

        self.validate_connected_client()?;
        Ok(())
    }

    /// Block until a client connects to this instance or the timeout elapses.
    ///
    /// This method returns [`Error::Pipe(PipeError::Timeout)`] if no client connection is
    /// completed within the provided timeout.
    pub fn connect_with_timeout(&self, timeout: Duration) -> Result<()> {
        let wait = Wait::manual_reset(false)?;
        self.connect_with_wait_timeout(&wait, timeout)
    }

    /// Block until a client connects or an external wait handle is signaled
    ///
    /// If `wait` is signaled first, this method cancels the pending connect operation and
    /// returns [`Error::Pipe(PipeError::Connect)`] with interruption context.
    pub fn connect_with_wait(&self, wait: &Wait) -> Result<()> {
        self.connect_with_wait_timeout(wait, Duration::MAX)
    }

    /// Block until a client connects, an external wait handle is signaled, or timeout elapses.
    ///
    /// If `wait` is signaled first, this method cancels the pending connect operation and
    /// returns [`Error::Pipe(PipeError::Connect)`] with interruption context.
    pub fn connect_with_wait_timeout(&self, wait: &Wait, timeout: Duration) -> Result<()> {
        let connect_event = Wait::manual_reset(false)?;
        let mut overlapped = OVERLAPPED {
            hEvent: connect_event.raw_handle(),
            ..Default::default()
        };

        let mut connect_code: Option<i32> = None;
        let result = unsafe { ConnectNamedPipe(self.endpoint.raw_handle(), Some(&mut overlapped)) };
        if result.is_err() {
            let code = unsafe { GetLastError().0 as i32 };
            connect_code = Some(code);
            if code != ERROR_IO_PENDING.0 as i32 && code != ERROR_PIPE_CONNECTED.0 as i32 {
                return Err(map_pipe_windows_error(
                    "connect",
                    Some(self.endpoint.pipe_name()),
                    code,
                ));
            }
        }

        if result.is_ok() || connect_code == Some(ERROR_PIPE_CONNECTED.0 as i32) {
            self.validate_connected_client()?;
            return Ok(());
        }

        let handles = [connect_event.raw_handle(), wait.raw_handle()];
        let wait_result =
            unsafe { WaitForMultipleObjects(&handles, false, duration_to_wait_ms(timeout)) };

        if wait_result == WAIT_OBJECT_0 {
            let mut transferred = 0u32;
            unsafe {
                GetOverlappedResult(
                    self.endpoint.raw_handle(),
                    &overlapped,
                    &mut transferred,
                    false,
                )
            }
            .map_err(|_| {
                let code = unsafe { GetLastError().0 as i32 };
                map_pipe_windows_error("connect", Some(self.endpoint.pipe_name()), code)
            })?;

            self.validate_connected_client()?;
            return Ok(());
        }

        if wait_result == windows::Win32::Foundation::WAIT_EVENT(WAIT_OBJECT_0.0 + 1) {
            let _ = unsafe { CancelIoEx(self.endpoint.raw_handle(), Some(&overlapped)) };
            return Err(Error::Pipe(PipeError::Connect(
                PipeConnectError::new(Cow::Owned(self.endpoint.pipe_name().as_str().to_owned()))
                    .with_context("connect interrupted by wait handle signal")
                    .with_code(ERROR_OPERATION_ABORTED.0 as i32),
            )));
        }

        if wait_result == WAIT_TIMEOUT {
            let _ = unsafe { CancelIoEx(self.endpoint.raw_handle(), Some(&overlapped)) };
            return Err(Error::Pipe(PipeError::Timeout(PipeTimeoutError::new(
                Cow::Owned(self.endpoint.pipe_name().as_str().to_owned()),
                Cow::Borrowed("connect"),
            ))));
        }

        let _ = unsafe { CancelIoEx(self.endpoint.raw_handle(), Some(&overlapped)) };
        if wait_result == WAIT_FAILED {
            let code = unsafe { GetLastError().0 as i32 };
            return Err(map_pipe_windows_error(
                "connect",
                Some(self.endpoint.pipe_name()),
                code,
            ));
        }

        Err(map_pipe_windows_error(
            "connect",
            Some(self.endpoint.pipe_name()),
            wait_result.0 as i32,
        ))
    }

    fn validate_connected_client(&self) -> Result<()> {
        if !self.allowed_executables.is_empty()
            && let Err(e) = self.check_client_executable()
        {
            let _ = self.disconnect();
            return Err(e);
        }
        Ok(())
    }

    /// Retrieve the connecting client's executable path and verify it is on the allow-list.
    fn check_client_executable(&self) -> Result<()> {
        let pipe_name = Cow::Owned(self.endpoint.pipe_name().as_str().to_owned());
        let mut pid: u32 = 0;
        let ok = unsafe { GetNamedPipeClientProcessId(self.endpoint.raw_handle(), &mut pid) };
        if ok.is_err() {
            return Err(Error::AccessDenied(AccessDeniedError::with_reason(
                pipe_name,
                "connect",
                "could not determine client process id",
            )));
        }

        let client_path = match Process::open(ProcessId::new(pid)) {
            Ok(proc) => match proc.path() {
                Ok(p) => p,
                Err(_) => {
                    return Err(Error::AccessDenied(AccessDeniedError::with_reason(
                        pipe_name,
                        "connect",
                        "could not retrieve client executable path",
                    )));
                }
            },
            Err(_) => {
                return Err(Error::AccessDenied(AccessDeniedError::with_reason(
                    pipe_name,
                    "connect",
                    "could not open client process",
                )));
            }
        };

        let allowed = self.allowed_executables.iter().any(|allowed| {
            allowed
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&client_path.as_os_str().to_string_lossy())
        });

        if allowed {
            Ok(())
        } else {
            Err(Error::AccessDenied(AccessDeniedError::with_reason(
                pipe_name,
                "connect",
                Cow::Owned(format!(
                    "client executable '{}' is not in the allow-list",
                    client_path.display()
                )),
            )))
        }
    }

    /// Disconnect the currently connected client.
    pub fn disconnect(&self) -> Result<()> {
        unsafe { DisconnectNamedPipe(self.endpoint.raw_handle()) }.map_err(|_| {
            let code = unsafe { GetLastError().0 as i32 };
            map_pipe_windows_error("disconnect", Some(self.endpoint.pipe_name()), code)
        })
    }

    /// Whether the connected client runs with the BUILTIN\Administrators
    /// group enabled, i.e. elevated (or as SYSTEM). A UAC-filtered admin
    /// token counts as not elevated.
    ///
    /// Windows only allows impersonation after data has been read from the
    /// pipe, so call this after the client's first message.
    pub fn client_is_elevated_admin(&self) -> Result<bool> {
        use windows::Win32::Foundation::{BOOL, HANDLE};
        use windows::Win32::Security::{
            CheckTokenMembership, CreateWellKnownSid, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
            WinBuiltinAdministratorsSid,
        };
        use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
        use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

        let context = |api: &'static str| {
            move |e: windows::core::Error| {
                Error::WindowsApi(crate::error::WindowsApiError::with_context(e, api))
            }
        };

        // SAFETY: the handle is a connected server pipe.
        unsafe { ImpersonateNamedPipeClient(self.endpoint.raw_handle()) }
            .map_err(context("ImpersonateNamedPipeClient"))?;
        let _revert = RevertOnDrop;

        let mut token = HANDLE::default();
        // SAFETY: the thread is impersonating; `openasself` uses the server's
        // own identity to open the client's token.
        unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) }
            .map_err(context("OpenThreadToken"))?;
        let token = crate::utils::OwnedHandle::new(token);

        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut sid_len = SECURITY_MAX_SID_SIZE;
        let sid_ptr = PSID(sid.as_mut_ptr().cast());
        // SAFETY: `sid` holds SECURITY_MAX_SID_SIZE bytes, enough for any SID.
        unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                PSID::default(),
                sid_ptr,
                &mut sid_len,
            )
        }
        .map_err(context("CreateWellKnownSid"))?;

        let mut member = BOOL(0);
        // SAFETY: `token` is an impersonation token opened with TOKEN_QUERY and
        // `sid_ptr` points at a valid SID.
        unsafe { CheckTokenMembership(token.raw(), sid_ptr, &mut member) }
            .map_err(context("CheckTokenMembership"))?;
        Ok(member.as_bool())
    }
}

/// Ends impersonation on drop.
struct RevertOnDrop;

impl Drop for RevertOnDrop {
    fn drop(&mut self) {
        // SAFETY: plain Win32 call without arguments.
        if unsafe { windows::Win32::Security::RevertToSelf() }.is_err() {
            // Continuing would run server code with the client's identity.
            std::process::abort();
        }
    }
}

fn duration_to_wait_ms(timeout: Duration) -> u32 {
    timeout.as_millis().min(u32::MAX as u128) as u32
}

impl NamedPipeServer {
    /// Run one overlapped read or write and wait for it to finish.
    ///
    /// The server handle is opened with `FILE_FLAG_OVERLAPPED`, so `ReadFile` and
    /// `WriteFile` must receive an `OVERLAPPED`; passing `None` can report
    /// completion before the operation has finished.
    fn overlapped_io(
        &mut self,
        operation: &'static str,
        start: impl FnOnce(&mut OVERLAPPED) -> windows::core::Result<()>,
    ) -> io::Result<OverlappedOutcome> {
        let handle = self.endpoint.raw_handle();
        self.io_event.reset().map_err(io::Error::other)?;
        let mut overlapped = OVERLAPPED {
            hEvent: self.io_event.raw_handle(),
            ..Default::default()
        };

        if let Err(err) = start(&mut overlapped) {
            let code = win32_code(&err);
            // Pending I/O and a completed partial message both finish below.
            if code != Some(ERROR_IO_PENDING.0) && code != Some(ERROR_MORE_DATA.0) {
                return match classify_pipe_read_error(err) {
                    PipeReadError::EndOfStream => Ok(OverlappedOutcome::EndOfStream),
                    PipeReadError::Failed(e) => Err(e),
                    PipeReadError::MoreData => Err(io::Error::other("unexpected ERROR_MORE_DATA")),
                };
            }
        }

        let timeout_ms = self.io_timeout.map_or(INFINITE, duration_to_wait_ms);
        // SAFETY: `io_event` is a valid event handle owned by `self`.
        let waited = unsafe { WaitForSingleObject(self.io_event.raw_handle(), timeout_ms) };
        if waited == WAIT_TIMEOUT {
            // SAFETY: `overlapped` describes the operation started above on `handle`.
            let _ = unsafe { CancelIoEx(handle, Some(&overlapped)) };
            let mut ignored = 0u32;
            // SAFETY: wait for the cancellation to complete before `overlapped` is dropped.
            let _ = unsafe { GetOverlappedResult(handle, &overlapped, &mut ignored, true) };
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("pipe {operation} timed out"),
            ));
        }

        let mut transferred = 0u32;
        // SAFETY: `overlapped` belongs to the operation started on `handle`.
        match unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, true) } {
            Ok(()) => Ok(OverlappedOutcome::Done(transferred as usize)),
            Err(err) => match classify_pipe_read_error(err) {
                PipeReadError::MoreData => Ok(OverlappedOutcome::Partial(transferred as usize)),
                PipeReadError::EndOfStream => Ok(OverlappedOutcome::EndOfStream),
                PipeReadError::Failed(e) => Err(e),
            },
        }
    }
}

enum OverlappedOutcome {
    Done(usize),
    /// Message-mode read: the buffer is full and the message continues.
    Partial(usize),
    EndOfStream,
}

impl io::Read for NamedPipeServer {
    /// Reads follow `std` pipe semantics: a closed client yields `Ok(0)`, and a
    /// message larger than `buf` is returned across several reads.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let handle = self.endpoint.raw_handle();
        let outcome = self.overlapped_io("read", |overlapped| {
            // SAFETY: `buf` and `overlapped` outlive the operation, which
            // `overlapped_io` waits for before returning.
            unsafe { ReadFile(handle, Some(buf), None, Some(overlapped)) }
        })?;
        Ok(match outcome {
            OverlappedOutcome::Done(n) | OverlappedOutcome::Partial(n) => n,
            OverlappedOutcome::EndOfStream => 0,
        })
    }
}

impl io::Write for NamedPipeServer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let handle = self.endpoint.raw_handle();
        let outcome = self.overlapped_io("write", |overlapped| {
            // SAFETY: `buf` and `overlapped` outlive the operation, which
            // `overlapped_io` waits for before returning.
            unsafe { WriteFile(handle, Some(buf), None, Some(overlapped)) }
        })?;
        match outcome {
            OverlappedOutcome::Done(n) | OverlappedOutcome::Partial(n) => Ok(n),
            OverlappedOutcome::EndOfStream => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    /// Block until the client has read everything written so far.
    ///
    /// Call this before [`NamedPipeServer::disconnect`]: disconnecting discards
    /// data the client has not read yet.
    fn flush(&mut self) -> io::Result<()> {
        // SAFETY: the handle is owned by `self.endpoint` and open.
        unsafe { FlushFileBuffers(self.endpoint.raw_handle()) }.map_err(win_to_io_error)
    }
}

fn to_server_open_mode(open_mode: NamedPipeOpenMode) -> FILE_FLAGS_AND_ATTRIBUTES {
    match open_mode {
        NamedPipeOpenMode::Inbound => {
            FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_INBOUND.0 | FILE_FLAG_OVERLAPPED.0)
        }
        NamedPipeOpenMode::Outbound => {
            FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_OUTBOUND.0 | FILE_FLAG_OVERLAPPED.0)
        }
        NamedPipeOpenMode::Duplex => {
            FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_OVERLAPPED.0)
        }
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
