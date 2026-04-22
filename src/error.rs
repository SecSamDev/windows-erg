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

    /// A service-specific error.
    Service(ServiceError),

    /// A thread-specific error.
    Thread(ThreadError),

    /// An event log-specific error.
    EventLog(EventLogError),

    /// An ETW-specific error.
    Etw(EtwError),

    /// A mitigation-specific error.
    Mitigation(MitigationError),

    /// A proxy-specific error.
    Proxy(ProxyError),

    /// A security/permissions-specific error.
    Security(SecurityError),

    /// A file operation error.
    FileOperation(FileOperationError),

    /// A pipe operation error.
    Pipe(PipeError),

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
            Error::Service(e) => write!(f, "{}", e),
            Error::Thread(e) => write!(f, "{}", e),
            Error::EventLog(e) => write!(f, "{}", e),
            Error::Etw(e) => write!(f, "{}", e),
            Error::Mitigation(e) => write!(f, "{}", e),
            Error::Proxy(e) => write!(f, "{}", e),
            Error::Security(e) => write!(f, "{}", e),
            Error::FileOperation(e) => write!(f, "{}", e),
            Error::Pipe(e) => write!(f, "{}", e),
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
    pub fn with_context(
        inner: windows::core::Error,
        context: impl Into<Cow<'static, str>>,
    ) -> Self {
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
    pub fn new(
        resource: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
    ) -> Self {
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
            write!(
                f,
                "Access denied: cannot {} '{}'",
                self.operation, self.resource
            )
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
            write!(
                f,
                "File operation '{}' failed on '{}'",
                self.operation, self.path
            )
        }
    }
}

impl std::error::Error for FileOperationError {}

// ============================================================================
// Pipe Errors
// ============================================================================

/// Pipe-specific errors.
#[derive(Debug)]
pub enum PipeError {
    /// Pipe creation failed.
    Create(PipeCreateError),

    /// Pipe connection failed.
    Connect(PipeConnectError),

    /// Pipe I/O operation failed.
    Io(PipeIoError),

    /// Pipe reached timeout.
    Timeout(PipeTimeoutError),

    /// Pipe is in an invalid state for the operation.
    InvalidState(PipeInvalidStateError),
}

impl fmt::Display for PipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipeError::Create(e) => write!(f, "{}", e),
            PipeError::Connect(e) => write!(f, "{}", e),
            PipeError::Io(e) => write!(f, "{}", e),
            PipeError::Timeout(e) => write!(f, "{}", e),
            PipeError::InvalidState(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for PipeError {}

/// Pipe creation error.
#[derive(Debug)]
pub struct PipeCreateError {
    /// Pipe name used during creation.
    pub pipe_name: Cow<'static, str>,
    /// Operation description.
    pub operation: Cow<'static, str>,
    /// Optional Windows error code.
    pub error_code: Option<i32>,
}

impl PipeCreateError {
    /// Create a new pipe creation error.
    pub fn new(
        pipe_name: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
    ) -> Self {
        PipeCreateError {
            pipe_name: pipe_name.into(),
            operation: operation.into(),
            error_code: None,
        }
    }

    /// Create a new pipe creation error with an error code.
    pub fn with_code(
        pipe_name: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
        error_code: i32,
    ) -> Self {
        PipeCreateError {
            pipe_name: pipe_name.into(),
            operation: operation.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for PipeCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Pipe creation '{}' failed for '{}' (error code: 0x{:08X})",
                self.operation, self.pipe_name, code
            )
        } else {
            write!(
                f,
                "Pipe creation '{}' failed for '{}'",
                self.operation, self.pipe_name
            )
        }
    }
}

impl std::error::Error for PipeCreateError {}

/// Pipe connection error.
#[derive(Debug)]
pub struct PipeConnectError {
    /// Pipe name used during connection.
    pub pipe_name: Cow<'static, str>,
    /// Optional connection context.
    pub context: Option<Cow<'static, str>>,
    /// Optional Windows error code.
    pub error_code: Option<i32>,
}

impl PipeConnectError {
    /// Create a new pipe connection error.
    pub fn new(pipe_name: impl Into<Cow<'static, str>>) -> Self {
        PipeConnectError {
            pipe_name: pipe_name.into(),
            context: None,
            error_code: None,
        }
    }

    /// Add context to a pipe connection error.
    pub fn with_context(mut self, context: impl Into<Cow<'static, str>>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Add a Windows error code to a pipe connection error.
    pub fn with_code(mut self, error_code: i32) -> Self {
        self.error_code = Some(error_code);
        self
    }
}

impl fmt::Display for PipeConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.context, self.error_code) {
            (Some(context), Some(code)) => write!(
                f,
                "Pipe connect failed for '{}' ({}, error code: 0x{:08X})",
                self.pipe_name, context, code
            ),
            (Some(context), None) => {
                write!(
                    f,
                    "Pipe connect failed for '{}' ({})",
                    self.pipe_name, context
                )
            }
            (None, Some(code)) => write!(
                f,
                "Pipe connect failed for '{}' (error code: 0x{:08X})",
                self.pipe_name, code
            ),
            (None, None) => write!(f, "Pipe connect failed for '{}'", self.pipe_name),
        }
    }
}

impl std::error::Error for PipeConnectError {}

/// Pipe I/O error.
#[derive(Debug)]
pub struct PipeIoError {
    /// Pipe name involved in I/O.
    pub pipe_name: Cow<'static, str>,
    /// I/O operation that failed.
    pub operation: Cow<'static, str>,
    /// Optional Windows error code.
    pub error_code: Option<i32>,
}

impl PipeIoError {
    /// Create a new pipe I/O error.
    pub fn new(
        pipe_name: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
    ) -> Self {
        PipeIoError {
            pipe_name: pipe_name.into(),
            operation: operation.into(),
            error_code: None,
        }
    }

    /// Create a new pipe I/O error with an error code.
    pub fn with_code(
        pipe_name: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
        error_code: i32,
    ) -> Self {
        PipeIoError {
            pipe_name: pipe_name.into(),
            operation: operation.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for PipeIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Pipe I/O '{}' failed for '{}' (error code: 0x{:08X})",
                self.operation, self.pipe_name, code
            )
        } else {
            write!(
                f,
                "Pipe I/O '{}' failed for '{}'",
                self.operation, self.pipe_name
            )
        }
    }
}

impl std::error::Error for PipeIoError {}

/// Pipe timeout error.
#[derive(Debug)]
pub struct PipeTimeoutError {
    /// Pipe name that timed out.
    pub pipe_name: Cow<'static, str>,
    /// Timeout operation.
    pub operation: Cow<'static, str>,
}

impl PipeTimeoutError {
    /// Create a new pipe timeout error.
    pub fn new(
        pipe_name: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
    ) -> Self {
        PipeTimeoutError {
            pipe_name: pipe_name.into(),
            operation: operation.into(),
        }
    }
}

impl fmt::Display for PipeTimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pipe operation '{}' timed out for '{}'",
            self.operation, self.pipe_name
        )
    }
}

impl std::error::Error for PipeTimeoutError {}

/// Pipe invalid-state error.
#[derive(Debug)]
pub struct PipeInvalidStateError {
    /// Operation attempted.
    pub operation: Cow<'static, str>,
    /// Why state is invalid.
    pub reason: Cow<'static, str>,
}

impl PipeInvalidStateError {
    /// Create a new invalid-state error for a pipe operation.
    pub fn new(
        operation: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        PipeInvalidStateError {
            operation: operation.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for PipeInvalidStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pipe operation '{}' is invalid in current state: {}",
            self.operation, self.reason
        )
    }
}

impl std::error::Error for PipeInvalidStateError {}

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
// Security Errors
// ============================================================================

/// Security and permissions errors.
#[derive(Debug)]
pub enum SecurityError {
    /// SID parsing or encoding failed.
    SidParse(SidParseError),

    /// Permission edit validation or execution failed.
    PermissionEdit(PermissionEditError),

    /// Operation is not supported by the current backend/target.
    Unsupported(SecurityUnsupportedError),
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::SidParse(e) => write!(f, "{}", e),
            SecurityError::PermissionEdit(e) => write!(f, "{}", e),
            SecurityError::Unsupported(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for SecurityError {}

/// SID parsing error.
#[derive(Debug)]
pub struct SidParseError {
    /// Input SID representation that failed.
    pub input: Cow<'static, str>,
    /// Why parsing failed.
    pub reason: Cow<'static, str>,
}

impl SidParseError {
    /// Create a new SID parse error.
    pub fn new(input: impl Into<Cow<'static, str>>, reason: impl Into<Cow<'static, str>>) -> Self {
        SidParseError {
            input: input.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for SidParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SID parse error for '{}': {}", self.input, self.reason)
    }
}

impl std::error::Error for SidParseError {}

/// Permission edit error.
#[derive(Debug)]
pub struct PermissionEditError {
    /// Operation that failed.
    pub operation: Cow<'static, str>,
    /// Why it failed.
    pub reason: Cow<'static, str>,
}

impl PermissionEditError {
    /// Create a new permission edit error.
    pub fn new(
        operation: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        PermissionEditError {
            operation: operation.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for PermissionEditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Permission edit '{}' failed: {}",
            self.operation, self.reason
        )
    }
}

impl std::error::Error for PermissionEditError {}

/// Unsupported security operation.
#[derive(Debug)]
pub struct SecurityUnsupportedError {
    /// The target/backend where operation was attempted.
    pub target: Cow<'static, str>,
    /// The unsupported operation.
    pub operation: Cow<'static, str>,
    /// Optional additional reason.
    pub reason: Option<Cow<'static, str>>,
}

impl SecurityUnsupportedError {
    /// Create a new unsupported security operation error.
    pub fn new(
        target: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
    ) -> Self {
        SecurityUnsupportedError {
            target: target.into(),
            operation: operation.into(),
            reason: None,
        }
    }

    /// Create a new unsupported security operation error with reason.
    pub fn with_reason(
        target: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        SecurityUnsupportedError {
            target: target.into(),
            operation: operation.into(),
            reason: Some(reason.into()),
        }
    }
}

impl fmt::Display for SecurityUnsupportedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(reason) = &self.reason {
            write!(
                f,
                "Security operation '{}' is not supported for '{}': {}",
                self.operation, self.target, reason
            )
        } else {
            write!(
                f,
                "Security operation '{}' is not supported for '{}'",
                self.operation, self.target
            )
        }
    }
}

impl std::error::Error for SecurityUnsupportedError {}

// ============================================================================
// Proxy Errors
// ============================================================================

/// Proxy-specific errors.
#[derive(Debug)]
pub enum ProxyError {
    /// Proxy configuration is invalid.
    InvalidConfig(ProxyConfigError),

    /// Proxy discovery operation failed.
    DiscoveryFailed(ProxyConfigError),

    /// Proxy URL resolution failed.
    ResolutionFailed(ProxyResolutionError),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::InvalidConfig(e) => write!(f, "{}", e),
            ProxyError::DiscoveryFailed(e) => write!(f, "{}", e),
            ProxyError::ResolutionFailed(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ProxyError {}

/// Invalid or unavailable proxy configuration.
#[derive(Debug)]
pub struct ProxyConfigError {
    /// Name of the relevant setting.
    pub setting: Cow<'static, str>,
    /// Reason the setting is invalid or unavailable.
    pub reason: Cow<'static, str>,
}

impl ProxyConfigError {
    /// Create a new proxy configuration error.
    pub fn new(
        setting: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        ProxyConfigError {
            setting: setting.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ProxyConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Proxy configuration error for '{}': {}",
            self.setting, self.reason
        )
    }
}

impl std::error::Error for ProxyConfigError {}

/// URL-specific proxy resolution error.
#[derive(Debug)]
pub struct ProxyResolutionError {
    /// URL that was being resolved.
    pub url: Cow<'static, str>,
    /// Why resolution failed.
    pub reason: Cow<'static, str>,
}

impl ProxyResolutionError {
    /// Create a new proxy resolution error.
    pub fn new(url: impl Into<Cow<'static, str>>, reason: impl Into<Cow<'static, str>>) -> Self {
        ProxyResolutionError {
            url: url.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ProxyResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Proxy resolution failed for '{}': {}",
            self.url, self.reason
        )
    }
}

impl std::error::Error for ProxyResolutionError {}

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
            write!(
                f,
                "Registry value '{}' not found in key '{}'",
                self.value_name, key
            )
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
            write!(
                f,
                "Invalid registry type: expected {}, found {}",
                self.expected, self.found
            )
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
        write!(
            f,
            "Registry conversion error ({}): {}",
            self.conversion, self.reason
        )
    }
}

impl std::error::Error for RegistryConversionError {}

// ============================================================================
// Service Errors
// ============================================================================

/// Service-specific errors.
#[derive(Debug)]
pub enum ServiceError {
    /// Failed to open or use the Service Control Manager.
    ManagerError(ServiceManagerError),

    /// Service not found.
    NotFound(ServiceNotFoundError),

    /// Service operation failed.
    OperationFailed(ServiceOperationError),

    /// Service is in an invalid state for the requested operation.
    InvalidState(ServiceInvalidStateError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::ManagerError(e) => write!(f, "{}", e),
            ServiceError::NotFound(e) => write!(f, "{}", e),
            ServiceError::OperationFailed(e) => write!(f, "{}", e),
            ServiceError::InvalidState(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ServiceError {}

/// Service Control Manager failure details.
#[derive(Debug)]
pub struct ServiceManagerError {
    /// Operation that failed.
    pub operation: Cow<'static, str>,
    /// Failure reason.
    pub reason: Cow<'static, str>,
    /// Optional Windows error code.
    pub error_code: Option<i32>,
}

impl ServiceManagerError {
    /// Create a new service manager error.
    pub fn new(
        operation: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        ServiceManagerError {
            operation: operation.into(),
            reason: reason.into(),
            error_code: None,
        }
    }

    /// Create a service manager error with error code.
    pub fn with_code(
        operation: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
        error_code: i32,
    ) -> Self {
        ServiceManagerError {
            operation: operation.into(),
            reason: reason.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for ServiceManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Service manager operation '{}' failed: {} (error code: 0x{:08X})",
                self.operation, self.reason, code
            )
        } else {
            write!(
                f,
                "Service manager operation '{}' failed: {}",
                self.operation, self.reason
            )
        }
    }
}

impl std::error::Error for ServiceManagerError {}

/// Service not found details.
#[derive(Debug)]
pub struct ServiceNotFoundError {
    /// Service key name.
    pub name: Cow<'static, str>,
    /// Optional Windows error code.
    pub error_code: Option<i32>,
}

impl ServiceNotFoundError {
    /// Create a new service not found error.
    pub fn new(name: impl Into<Cow<'static, str>>) -> Self {
        ServiceNotFoundError {
            name: name.into(),
            error_code: None,
        }
    }

    /// Create a service not found error with error code.
    pub fn with_code(name: impl Into<Cow<'static, str>>, error_code: i32) -> Self {
        ServiceNotFoundError {
            name: name.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for ServiceNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Service '{}' not found (error code: 0x{:08X})",
                self.name, code
            )
        } else {
            write!(f, "Service '{}' not found", self.name)
        }
    }
}

impl std::error::Error for ServiceNotFoundError {}

/// Service operation failure details.
#[derive(Debug)]
pub struct ServiceOperationError {
    /// Service key name.
    pub name: Cow<'static, str>,
    /// Operation that failed.
    pub operation: Cow<'static, str>,
    /// Failure reason.
    pub reason: Cow<'static, str>,
    /// Optional Windows error code.
    pub error_code: Option<i32>,
}

impl ServiceOperationError {
    /// Create a new service operation error.
    pub fn new(
        name: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        ServiceOperationError {
            name: name.into(),
            operation: operation.into(),
            reason: reason.into(),
            error_code: None,
        }
    }

    /// Create a service operation error with error code.
    pub fn with_code(
        name: impl Into<Cow<'static, str>>,
        operation: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
        error_code: i32,
    ) -> Self {
        ServiceOperationError {
            name: name.into(),
            operation: operation.into(),
            reason: reason.into(),
            error_code: Some(error_code),
        }
    }
}

impl fmt::Display for ServiceOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.error_code {
            write!(
                f,
                "Service '{}' operation '{}' failed: {} (error code: 0x{:08X})",
                self.name, self.operation, self.reason, code
            )
        } else {
            write!(
                f,
                "Service '{}' operation '{}' failed: {}",
                self.name, self.operation, self.reason
            )
        }
    }
}

impl std::error::Error for ServiceOperationError {}

/// Service invalid-state error details.
#[derive(Debug)]
pub struct ServiceInvalidStateError {
    /// Service key name.
    pub name: Cow<'static, str>,
    /// Expected state or condition.
    pub expected: Cow<'static, str>,
    /// Why the state is invalid.
    pub reason: Cow<'static, str>,
}

impl ServiceInvalidStateError {
    /// Create a new service invalid-state error.
    pub fn new(
        name: impl Into<Cow<'static, str>>,
        expected: impl Into<Cow<'static, str>>,
        reason: impl Into<Cow<'static, str>>,
    ) -> Self {
        ServiceInvalidStateError {
            name: name.into(),
            expected: expected.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ServiceInvalidStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Service '{}' is not in expected state '{}': {}",
            self.name, self.expected, self.reason
        )
    }
}

impl std::error::Error for ServiceInvalidStateError {}

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
            write!(
                f,
                "Process {} already terminated (exit code: {})",
                self.pid, code
            )
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
            write!(
                f,
                "Failed to spawn process '{}': {}",
                self.command, self.reason
            )
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
            write!(
                f,
                "Failed to query event log '{}': {}",
                self.log_name, self.reason
            )
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

    /// Session already exists error (common case).
    pub fn already_exists(session_name: impl Into<Cow<'static, str>>) -> Self {
        EtwSessionError {
            session_name: session_name.into(),
            reason: Cow::Borrowed("Session already exists"),
            error_code: Some(-2147024713), // ERROR_ALREADY_EXISTS (0x800700B7)
        }
    }

    /// Invalid configuration error.
    pub fn invalid_config(
        session_name: impl Into<Cow<'static, str>>,
        field: &'static str,
        issue: impl Into<Cow<'static, str>>,
    ) -> Self {
        EtwSessionError {
            session_name: session_name.into(),
            reason: Cow::Owned(format!("Invalid {}: {}", field, issue.into())),
            error_code: None,
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
            write!(
                f,
                "Failed to start ETW session '{}': {}",
                self.session_name, self.reason
            )
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

    /// Provider not found/registered error (common case).
    pub fn not_found(provider: impl Into<Cow<'static, str>>) -> Self {
        EtwProviderError {
            provider: provider.into(),
            reason: Cow::Borrowed("Provider not registered"),
            error_code: Some(0x00000490), // ERROR_NOT_FOUND
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
            write!(
                f,
                "Failed to enable ETW provider '{}': {}",
                self.provider, self.reason
            )
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

// ============================================================================
// Mitigation Errors
// ============================================================================

/// Mitigation-specific errors.
#[derive(Debug)]
pub enum MitigationError {
    /// Applying one mitigation policy failed.
    ApplyFailed(MitigationOperationError),

    /// Querying one mitigation policy failed.
    QueryFailed(MitigationOperationError),
}

impl fmt::Display for MitigationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MitigationError::ApplyFailed(e) => write!(f, "{}", e),
            MitigationError::QueryFailed(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for MitigationError {}

/// Mitigation operation error.
#[derive(Debug)]
pub struct MitigationOperationError {
    /// Operation that failed.
    pub operation: Cow<'static, str>,
    /// Policy name associated with the operation.
    pub policy: Cow<'static, str>,
    /// Optional process ID for process-specific operations.
    pub process_id: Option<u32>,
    /// Optional reason for failure.
    pub reason: Option<Cow<'static, str>>,
    /// Windows error code if available.
    pub error_code: Option<i32>,
}

impl MitigationOperationError {
    /// Create a new mitigation operation error.
    pub fn new(
        operation: impl Into<Cow<'static, str>>,
        policy: impl Into<Cow<'static, str>>,
    ) -> Self {
        MitigationOperationError {
            operation: operation.into(),
            policy: policy.into(),
            process_id: None,
            reason: None,
            error_code: None,
        }
    }

    /// Attach a process ID context.
    pub fn with_process_id(mut self, process_id: u32) -> Self {
        self.process_id = Some(process_id);
        self
    }

    /// Attach a reason string.
    pub fn with_reason(mut self, reason: impl Into<Cow<'static, str>>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Attach a Windows error code.
    pub fn with_code(mut self, error_code: i32) -> Self {
        self.error_code = Some(error_code);
        self
    }
}

impl fmt::Display for MitigationOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.process_id, &self.reason, self.error_code) {
            (Some(pid), Some(reason), Some(code)) => write!(
                f,
                "Mitigation {} failed for policy '{}' on process {}: {} (error code: 0x{:08X})",
                self.operation, self.policy, pid, reason, code
            ),
            (Some(pid), Some(reason), None) => write!(
                f,
                "Mitigation {} failed for policy '{}' on process {}: {}",
                self.operation, self.policy, pid, reason
            ),
            (Some(pid), None, Some(code)) => write!(
                f,
                "Mitigation {} failed for policy '{}' on process {} (error code: 0x{:08X})",
                self.operation, self.policy, pid, code
            ),
            (Some(pid), None, None) => write!(
                f,
                "Mitigation {} failed for policy '{}' on process {}",
                self.operation, self.policy, pid
            ),
            (None, Some(reason), Some(code)) => write!(
                f,
                "Mitigation {} failed for policy '{}': {} (error code: 0x{:08X})",
                self.operation, self.policy, reason, code
            ),
            (None, Some(reason), None) => write!(
                f,
                "Mitigation {} failed for policy '{}': {}",
                self.operation, self.policy, reason
            ),
            (None, None, Some(code)) => write!(
                f,
                "Mitigation {} failed for policy '{}' (error code: 0x{:08X})",
                self.operation, self.policy, code
            ),
            (None, None, None) => write!(
                f,
                "Mitigation {} failed for policy '{}'",
                self.operation, self.policy
            ),
        }
    }
}

impl std::error::Error for MitigationOperationError {}

#[cfg(test)]
mod tests {
    use super::{EtwConsumeError, EtwProviderError, EtwSessionError, MitigationOperationError};
    use std::borrow::Cow;

    #[test]
    fn etw_session_error_invalid_config_message_contains_field() {
        let err = EtwSessionError::invalid_config(
            Cow::Borrowed("MySession"),
            "providers",
            Cow::Borrowed("cannot mix kernel and user providers"),
        );

        assert_eq!(err.session_name, "MySession");
        assert!(err.reason.contains("Invalid providers"));
        assert!(err.reason.contains("cannot mix kernel and user providers"));
        assert!(err.error_code.is_none());
    }

    #[test]
    fn etw_provider_error_not_found_has_expected_code() {
        let err = EtwProviderError::not_found(Cow::Borrowed("{provider-guid}"));

        assert_eq!(err.provider, "{provider-guid}");
        assert_eq!(err.error_code, Some(0x00000490));
        assert!(err.reason.contains("Provider not registered"));
    }

    #[test]
    fn etw_consume_error_display_with_code_contains_hex() {
        let err = EtwConsumeError::with_code(Cow::Borrowed("OpenTraceW failed"), 0x57);
        let rendered = err.to_string();

        assert!(rendered.contains("OpenTraceW failed"));
        assert!(rendered.contains("0x00000057"));
    }

    #[test]
    fn mitigation_operation_error_display_includes_policy_pid_and_code() {
        let err = MitigationOperationError::new("apply", "dynamic_code")
            .with_process_id(1234)
            .with_reason("Access denied")
            .with_code(5);

        let rendered = err.to_string();
        assert!(rendered.contains("dynamic_code"));
        assert!(rendered.contains("1234"));
        assert!(rendered.contains("0x00000005"));
    }
}
