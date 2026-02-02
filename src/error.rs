//! Error types for the windows-erg crate.

use std::borrow::Cow;
use std::fmt;

/// Result type for windows-erg operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for windows-erg.
#[derive(Debug)]
pub enum Error {
    /// A Windows API error occurred.
    WindowsApi(WindowsApiError),

    /// Access was denied (insufficient permissions).
    AccessDenied(AccessDeniedError),

    /// The requested resource was not found.
    NotFound(NotFoundError),

    /// An invalid parameter was provided.
    InvalidParameter(InvalidParameterError),

    /// A registry-specific error.
    Registry(RegistryError),

    /// A process-specific error.
    Process(ProcessError),

    /// A thread-specific error.
    Thread(ThreadError),

    /// An event log-specific error.
    EventLog(EventLogError),

    /// An ETW-specific error.
    Etw(EtwError),

    /// A file operation error.
    FileOperation(FileOperationError),

    /// A generic error with a message.
    Other(OtherError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WindowsApi(e) => write!(f, "{}", e),
            Error::AccessDenied(e) => write!(f, "{}", e),
            Error::NotFound(e) => write!(f, "{}", e),
            Error::InvalidParameter(e) => write!(f, "{}", e),
            Error::Registry(e) => write!(f, "{}", e),
            Error::Process(e) => write!(f, "{}", e),
            Error::Thread(e) => write!(f, "{}", e),
            Error::EventLog(e) => write!(f, "{}", e),
            Error::Etw(e) => write!(f, "{}", e),
            Error::FileOperation(e) => write!(f, "{}", e),
            Error::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {}

impl From<windows::core::Error> for Error {
    fn from(err: windows::core::Error) -> Self {
        Error::WindowsApi(WindowsApiError {
            inner: err,
            context: None,
        })
    }
}

// ============================================================================
// Structured Error Types
// ============================================================================

/// Windows API error with optional context.
#[derive(Debug)]
pub struct WindowsApiError {
    /// The underlying Windows error.
    pub inner: windows::core::Error,
    /// Optional context about what operation failed.
    pub context: Option<Cow<'static, str>>,
}

impl WindowsApiError {
    /// Create a new Windows API error.
    pub fn new(inner: windows::core::Error) -> Self {
        WindowsApiError {
            inner,
            context: None,
        }
    }

    /// Create a Windows API error with context.
    pub fn with_context(inner: windows::core::Error, context: impl Into<Cow<'static, str>>) -> Self {
        WindowsApiError {
            inner,
            context: Some(context.into()),
        }
    }

    /// Get the Windows error code.
    pub fn code(&self) -> i32 {
        self.inner.code().0
    }
}

impl fmt::Display for WindowsApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(context) = &self.context {
            write!(f, "Windows API error in {}: {}", context, self.inner)
        } else {
            write!(f, "Windows API error: {}", self.inner)
        }
    }
}

impl std::error::Error for WindowsApiError {}

/// Access denied error.
#[derive(Debug)]
pub struct AccessDeniedError {
    /// What resource was being accessed.
    pub resource: Cow<'static, str>,
    /// What operation was attempted.
    pub operation: Cow<'static, str>,
    /// Optional additional context.
    pub reason: Option<Cow<'static, str>>,
}

impl AccessDeniedError {
    /// Create a new access denied error.
    pub fn new(resource: impl Into<Cow<'static, str>>, operation: impl Into<Cow<'static, str>>) -> Self {
        AccessDeniedError {
            resource: resource.into(),
            operation: operation.into(),
            reason: None,
        }
    }

    /// Create an access denied error with a reason.
    pub fn with_reason(
        resource: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        AccessDeniedError {
            resource: resource.into(),
            operation: operation.into(),
            reason: Some(reason.into()),
        }
    }
}

impl fmt::Display for AccessDeniedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(reason) = &self.reason {
            write!(
                f,
                "Access denied: cannot {} '{}' ({})",
                self.operation, self.resource, reason
            )
        } else {
            write!(f, "Access denied: cannot {} '{}'", self.operation, self.resource)
        }
    }
}

impl std::error::Error for AccessDeniedError {}

/// Resource not found error.
#[derive(Debug)]
pub struct NotFoundError {
    /// Type of resource that was not found.
    pub resource_type: Cow<'static, str>,
    /// Identifier of the resource.
    pub identifier: Cow<'static, str>,
}

impl NotFoundError {
    /// Create a new not found error.
    pub fn new(
        resource_type: impl Into<Cow<'static, str>>,
        identifier: impl Into<Cow<'static, str>>,
    ) -> Self {
        NotFoundError {
            resource_type: resource_type.into(),
            identifier: identifier.into(),
        }
    }
}

impl fmt::Display for NotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} not found: {}", self.resource_type, self.identifier)
    }
}

impl std::error::Error for NotFoundError {}

/// Invalid parameter error.
#[derive(Debug)]
pub struct InvalidParameterError {
    /// Name of the parameter.
    pub parameter: Cow<'static, str>,
    /// Why the parameter is invalid.
    pub reason: Cow<'static, str>,
}

impl InvalidParameterError {
    /// Create a new invalid parameter error.
    pub fn new(
        parameter: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        InvalidParameterError {
            parameter: parameter.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for InvalidParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid parameter '{}': {}", self.parameter, self.reason)
    }
}

impl std::error::Error for InvalidParameterError {}

/// File operation error.
#[derive(Debug)]
pub struct FileOperationError {
    /// The file path.
    pub path: Cow<'static, str>,
    /// The operation that failed.
    pub operation: Cow<'static, str>,
    /// Windows error code if available.
    pub error_code: Option<i32>,
}

impl FileOperationError {
    /// Create a new file operation error.
    pub fn new(
        path: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
    ) -> Self {
        FileOperationError {
            path: path.into(),
            operation: operation.into(),
            error_code: None,
        }
    }

    /// Create a file operation error with an error code.
    pub fn with_code(
        path: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
        error_code: i32,
    ) -> Self {
        FileOperationError {
            path: path.into(),
            operation: operation.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for FileOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "File operation '{}' failed on '{}' (error code: 0x{:08X})",
                self.operation, self.path, code
            )
        } else {
            write!(f, "File operation '{}' failed on '{}'", self.operation, self.path)
        }
    }
}

impl std::error::Error for FileOperationError {}

/// Generic error with a message.
#[derive(Debug)]
pub struct OtherError {
    /// Error message.
    pub message: Cow<'static, str>,
}

impl OtherError {
    /// Create a new generic error.
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        OtherError {
            message: message.into(),
        }
    }
}

impl fmt::Display for OtherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OtherError {}

// ============================================================================
// Registry Errors
// ============================================================================

/// Registry-specific errors.
#[derive(Debug)]
pub enum RegistryError {
    /// Registry key not found.
    KeyNotFound(RegistryKeyNotFoundError),

    /// Registry value not found.
    ValueNotFound(RegistryValueNotFoundError),

    /// Invalid value type.
    InvalidType(RegistryInvalidTypeError),

    /// Error converting value.
    ConversionError(RegistryConversionError),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::KeyNotFound(e) => write!(f, "{}", e),
            RegistryError::ValueNotFound(e) => write!(f, "{}", e),
            RegistryError::InvalidType(e) => write!(f, "{}", e),
            RegistryError::ConversionError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Registry key not found.
#[derive(Debug)]
pub struct RegistryKeyNotFoundError {
    /// The key path that was not found.
    pub key_path: Cow<'static, str>,
    /// Windows error code.
    pub error_code: Option<i32>,
}

impl RegistryKeyNotFoundError {
    /// Create a new key not found error.
    pub fn new(key_path: impl Into<Cow<'static, str>>) -> Self {
        RegistryKeyNotFoundError {
            key_path: key_path.into(),
            error_code: None,
        }
    }

    /// Create a key not found error with error code.
    pub fn with_code(key_path: impl Into<Cow<'static, str>>, error_code: i32) -> Self {
        RegistryKeyNotFoundError {
            key_path: key_path.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for RegistryKeyNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Registry key not found: {} (error code: 0x{:08X})",
                self.key_path, code
            )
        } else {
            write!(f, "Registry key not found: {}", self.key_path)
        }
    }
}

impl std::error::Error for RegistryKeyNotFoundError {}

/// Registry value not found.
#[derive(Debug)]
pub struct RegistryValueNotFoundError {
    /// The value name that was not found.
    pub value_name: Cow<'static, str>,
    /// Optional key path for context.
    pub key_path: Option<Cow<'static, str>>,
}

impl RegistryValueNotFoundError {
    /// Create a new value not found error.
    pub fn new(value_name: impl Into<Cow<'static, str>>) -> Self {
        RegistryValueNotFoundError {
            value_name: value_name.into(),
            key_path: None,
        }
    }

    /// Create a value not found error with key path.
    pub fn with_key(
        value_name: impl Into<Cow<'static, str>>,
        key_path: impl Into<Cow<'static, str>>,
    ) -> Self {
        RegistryValueNotFoundError {
            value_name: value_name.into(),
            key_path: Some(key_path.into()),
        }
    }
}

impl fmt::Display for RegistryValueNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(key) = &self.key_path {
            write!(f, "Registry value '{}' not found in key '{}'", self.value_name, key)
        } else {
            write!(f, "Registry value not found: {}", self.value_name)
        }
    }
}

impl std::error::Error for RegistryValueNotFoundError {}

/// Invalid registry value type.
#[derive(Debug)]
pub struct RegistryInvalidTypeError {
    /// The expected type.
    pub expected: Cow<'static, str>,
    /// The actual type found.
    pub found: Cow<'static, str>,
    /// The value name.
    pub value_name: Option<Cow<'static, str>>,
}

impl RegistryInvalidTypeError {
    /// Create a new invalid type error.
    pub fn new(
        expected: impl Into<Cow<'static, str>>,
        found: impl Into<Cow<'static, str>>,
    ) -> Self {
        RegistryInvalidTypeError {
            expected: expected.into(),
            found: found.into(),
            value_name: None,
        }
    }

    /// Create an invalid type error with value name.
    pub fn with_name(
        expected: impl Into<Cow<'static, str>>,
        found: impl Into<Cow<'static, str>>,
        value_name: impl Into<Cow<'static, str>>,
    ) -> Self {
        RegistryInvalidTypeError {
            expected: expected.into(),
            found: found.into(),
            value_name: Some(value_name.into()),
        }
    }
}

impl fmt::Display for RegistryInvalidTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = &self.value_name {
            write!(
                f,
                "Invalid registry type for '{}': expected {}, found {}",
                name, self.expected, self.found
            )
        } else {
            write!(f, "Invalid registry type: expected {}, found {}", self.expected, self.found)
        }
    }
}

impl std::error::Error for RegistryInvalidTypeError {}

/// Registry value conversion error.
#[derive(Debug)]
pub struct RegistryConversionError {
    /// What conversion was being attempted.
    pub conversion: Cow<'static, str>,
    /// Why it failed.
    pub reason: Cow<'static, str>,
}

impl RegistryConversionError {
    /// Create a new conversion error.
    pub fn new(
        conversion: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        RegistryConversionError {
            conversion: conversion.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for RegistryConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Registry conversion error ({}): {}", self.conversion, self.reason)
    }
}

impl std::error::Error for RegistryConversionError {}

// ============================================================================
// Process Errors
// ============================================================================

/// Process-specific errors.
#[derive(Debug)]
pub enum ProcessError {
    /// Process not found.
    NotFound(ProcessNotFoundError),

    /// Process already terminated.
    AlreadyTerminated(ProcessTerminatedError),

    /// Failed to open process.
    OpenFailed(ProcessOpenError),

    /// Failed to spawn process.
    SpawnFailed(ProcessSpawnError),

    /// Invalid process ID.
    InvalidProcessId,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessError::NotFound(e) => write!(f, "{}", e),
            ProcessError::AlreadyTerminated(e) => write!(f, "{}", e),
            ProcessError::OpenFailed(e) => write!(f, "{}", e),
            ProcessError::SpawnFailed(e) => write!(f, "{}", e),
            ProcessError::InvalidProcessId => write!(f, "Invalid process ID"),
        }
    }
}

impl std::error::Error for ProcessError {}

/// Process not found error.
#[derive(Debug)]
pub struct ProcessNotFoundError {
    /// The process ID that was not found.
    pub pid: u32,
}

impl ProcessNotFoundError {
    /// Create a new process not found error.
    pub fn new(pid: u32) -> Self {
        ProcessNotFoundError { pid }
    }
}

impl fmt::Display for ProcessNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Process {} not found", self.pid)
    }
}

impl std::error::Error for ProcessNotFoundError {}

/// Process already terminated error.
#[derive(Debug)]
pub struct ProcessTerminatedError {
    /// The process ID.
    pub pid: u32,
    /// Optional exit code.
    pub exit_code: Option<u32>,
}

impl ProcessTerminatedError {
    /// Create a new process terminated error.
    pub fn new(pid: u32) -> Self {
        ProcessTerminatedError {
            pid,
            exit_code: None,
        }
    }

    /// Create a process terminated error with exit code.
    pub fn with_exit_code(pid: u32, exit_code: u32) -> Self {
        ProcessTerminatedError {
            pid,
            exit_code: Some(exit_code),
        }
    }
}

impl fmt::Display for ProcessTerminatedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.exit_code {
            write!(f, "Process {} already terminated (exit code: {})", self.pid, code)
        } else {
            write!(f, "Process {} already terminated", self.pid)
        }
    }
}

impl std::error::Error for ProcessTerminatedError {}

/// Failed to open process error.
#[derive(Debug)]
pub struct ProcessOpenError {
    /// The process ID.
    pub pid: u32,
    /// Reason for failure.
    pub reason: Cow<'static, str>,
    /// Windows error code if available.
    pub error_code: Option<i32>,
}

impl ProcessOpenError {
    /// Create a new process open error.
    pub fn new(pid: u32, reason: impl Into<Cow<'static, str>>) -> Self {
        ProcessOpenError {
            pid,
            reason: reason.into(),
            error_code: None,
        }
    }

    /// Create a process open error with error code.
    pub fn with_code(pid: u32, reason: impl Into<Cow<'static, str>>, error_code: i32) -> Self {
        ProcessOpenError {
            pid,
            reason: reason.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for ProcessOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Failed to open process {}: {} (error code: 0x{:08X})",
                self.pid, self.reason, code
            )
        } else {
            write!(f, "Failed to open process {}: {}", self.pid, self.reason)
        }
    }
}

impl std::error::Error for ProcessOpenError {}

/// Failed to spawn process error.
#[derive(Debug)]
pub struct ProcessSpawnError {
    /// The command that was attempted.
    pub command: Cow<'static, str>,
    /// Reason for failure.
    pub reason: Cow<'static, str>,
    /// Windows error code if available.
    pub error_code: Option<i32>,
}

impl ProcessSpawnError {
    /// Create a new process spawn error.
    pub fn new(
        command: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        ProcessSpawnError {
            command: command.into(),
            reason: reason.into(),
            error_code: None,
        }
    }

    /// Create a process spawn error with error code.
    pub fn with_code(
        command: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
        error_code: i32,
    ) -> Self {
        ProcessSpawnError {
            command: command.into(),
            reason: reason.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for ProcessSpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Failed to spawn process '{}': {} (error code: 0x{:08X})",
                self.command, self.reason, code
            )
        } else {
            write!(f, "Failed to spawn process '{}': {}", self.command, self.reason)
        }
    }
}

impl std::error::Error for ProcessSpawnError {}

// ============================================================================
// Thread Errors
// ============================================================================

/// Thread-specific errors.
#[derive(Debug)]
pub enum ThreadError {
    /// Thread not found.
    NotFound(ThreadNotFoundError),

    /// Failed to open thread.
    OpenFailed(ThreadOpenError),
}

impl fmt::Display for ThreadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreadError::NotFound(e) => write!(f, "{}", e),
            ThreadError::OpenFailed(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ThreadError {}

/// Thread not found error.
#[derive(Debug)]
pub struct ThreadNotFoundError {
    /// The thread ID that was not found.
    pub tid: u32,
}

impl ThreadNotFoundError {
    /// Create a new thread not found error.
    pub fn new(tid: u32) -> Self {
        ThreadNotFoundError { tid }
    }
}

impl fmt::Display for ThreadNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Thread {} not found", self.tid)
    }
}

impl std::error::Error for ThreadNotFoundError {}

/// Failed to open thread error.
#[derive(Debug)]
pub struct ThreadOpenError {
    /// The thread ID.
    pub tid: u32,
    /// Reason for failure.
    pub reason: Cow<'static, str>,
    /// Windows error code if available.
    pub error_code: Option<i32>,
}

impl ThreadOpenError {
    /// Create a new thread open error.
    pub fn new(tid: u32, reason: impl Into<Cow<'static, str>>) -> Self {
        ThreadOpenError {
            tid,
            reason: reason.into(),
            error_code: None,
        }
    }

    /// Create a thread open error with error code.
    pub fn with_code(tid: u32, reason: impl Into<Cow<'static, str>>, error_code: i32) -> Self {
        ThreadOpenError {
            tid,
            reason: reason.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for ThreadOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Failed to open thread {}: {} (error code: 0x{:08X})",
                self.tid, self.reason, code
            )
        } else {
            write!(f, "Failed to open thread {}: {}", self.tid, self.reason)
        }
    }
}

impl std::error::Error for ThreadOpenError {}

// ============================================================================
// Event Log Errors
// ============================================================================

/// Event log-specific errors.
#[derive(Debug)]
pub enum EventLogError {
    /// Event log not found.
    LogNotFound(EventLogNotFoundError),

    /// Failed to query events.
    QueryFailed(EventLogQueryError),

    /// Failed to parse event.
    ParseFailed(EventLogParseError),
}

impl fmt::Display for EventLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventLogError::LogNotFound(e) => write!(f, "{}", e),
            EventLogError::QueryFailed(e) => write!(f, "{}", e),
            EventLogError::ParseFailed(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for EventLogError {}

/// Event log not found error.
#[derive(Debug)]
pub struct EventLogNotFoundError {
    /// The name of the log that was not found.
    pub log_name: Cow<'static, str>,
}

impl EventLogNotFoundError {
    /// Create a new event log not found error.
    pub fn new(log_name: impl Into<Cow<'static, str>>) -> Self {
        EventLogNotFoundError {
            log_name: log_name.into(),
        }
    }
}

impl fmt::Display for EventLogNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Event log not found: {}", self.log_name)
    }
}

impl std::error::Error for EventLogNotFoundError {}

/// Event log query error.
#[derive(Debug)]
pub struct EventLogQueryError {
    /// The log name.
    pub log_name: Cow<'static, str>,
    /// Reason for failure.
    pub reason: Cow<'static, str>,
    /// Windows error code if available.
    pub error_code: Option<i32>,
}

impl EventLogQueryError {
    /// Create a new query error.
    pub fn new(
        log_name: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        EventLogQueryError {
            log_name: log_name.into(),
            reason: reason.into(),
            error_code: None,
        }
    }

    /// Create a query error with error code.
    pub fn with_code(
        log_name: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
        error_code: i32,
    ) -> Self {
        EventLogQueryError {
            log_name: log_name.into(),
            reason: reason.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for EventLogQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Failed to query event log '{}': {} (error code: 0x{:08X})",
                self.log_name, self.reason, code
            )
        } else {
            write!(f, "Failed to query event log '{}': {}", self.log_name, self.reason)
        }
    }
}

impl std::error::Error for EventLogQueryError {}

/// Event log parse error.
#[derive(Debug)]
pub struct EventLogParseError {
    /// What failed to parse.
    pub component: Cow<'static, str>,
    /// Reason for failure.
    pub reason: Cow<'static, str>,
}

impl EventLogParseError {
    /// Create a new parse error.
    pub fn new(
        component: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        EventLogParseError {
            component: component.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for EventLogParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to parse {}: {}", self.component, self.reason)
    }
}

impl std::error::Error for EventLogParseError {}

// ============================================================================
// ETW Errors
// ============================================================================

/// ETW-specific errors.
#[derive(Debug)]
pub enum EtwError {
    /// Failed to start ETW session.
    SessionStartFailed(EtwSessionError),

    /// Failed to enable provider.
    ProviderEnableFailed(EtwProviderError),

    /// Failed to consume events.
    ConsumeFailed(EtwConsumeError),
}

impl fmt::Display for EtwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtwError::SessionStartFailed(e) => write!(f, "{}", e),
            EtwError::ProviderEnableFailed(e) => write!(f, "{}", e),
            EtwError::ConsumeFailed(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for EtwError {}

/// ETW session error.
#[derive(Debug)]
pub struct EtwSessionError {
    /// The session name.
    pub session_name: Cow<'static, str>,
    /// Reason for failure.
    pub reason: Cow<'static, str>,
    /// Windows error code if available.
    pub error_code: Option<i32>,
}

impl EtwSessionError {
    /// Create a new session error.
    pub fn new(
        session_name: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        EtwSessionError {
            session_name: session_name.into(),
            reason: reason.into(),
            error_code: None,
        }
    }

    /// Create a session error with error code.
    pub fn with_code(
        session_name: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
        error_code: i32,
    ) -> Self {
        EtwSessionError {
            session_name: session_name.into(),
            reason: reason.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for EtwSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Failed to start ETW session '{}': {} (error code: 0x{:08X})",
                self.session_name, self.reason, code
            )
        } else {
            write!(f, "Failed to start ETW session '{}': {}", self.session_name, self.reason)
        }
    }
}

impl std::error::Error for EtwSessionError {}

/// ETW provider error.
#[derive(Debug)]
pub struct EtwProviderError {
    /// The provider name or GUID.
    pub provider: Cow<'static, str>,
    /// Reason for failure.
    pub reason: Cow<'static, str>,
    /// Windows error code if available.
    pub error_code: Option<i32>,
}

impl EtwProviderError {
    /// Create a new provider error.
    pub fn new(
        provider: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        EtwProviderError {
            provider: provider.into(),
            reason: reason.into(),
            error_code: None,
        }
    }

    /// Create a provider error with error code.
    pub fn with_code(
        provider: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
        error_code: i32,
    ) -> Self {
        EtwProviderError {
            provider: provider.into(),
            reason: reason.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for EtwProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Failed to enable ETW provider '{}': {} (error code: 0x{:08X})",
                self.provider, self.reason, code
            )
        } else {
            write!(f, "Failed to enable ETW provider '{}': {}", self.provider, self.reason)
        }
    }
}

impl std::error::Error for EtwProviderError {}

/// ETW consume error.
#[derive(Debug)]
pub struct EtwConsumeError {
    /// Reason for failure.
    pub reason: Cow<'static, str>,
    /// Windows error code if available.
    pub error_code: Option<i32>,
}

impl EtwConsumeError {
    /// Create a new consume error.
    pub fn new(reason: impl Into<Cow<'static, str>>) -> Self {
        EtwConsumeError {
            reason: reason.into(),
            error_code: None,
        }
    }

    /// Create a consume error with error code.
    pub fn with_code(reason: impl Into<Cow<'static, str>>, error_code: i32) -> Self {
        EtwConsumeError {
            reason: reason.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for EtwConsumeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Failed to consume ETW events: {} (error code: 0x{:08X})",
                self.reason, code
            )
        } else {
            write!(f, "Failed to consume ETW events: {}", self.reason)
        }
    }
}

impl std::error::Error for EtwConsumeError {}
