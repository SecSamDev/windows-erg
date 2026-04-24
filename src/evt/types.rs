//! Event Log types with optimized string handling.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use crate::types::{ProcessId, ThreadId};

/// Type-safe event ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EventId(u32);

impl EventId {
    /// Create a new event ID.
    pub fn new(id: u32) -> Self {
        EventId(id)
    }

    /// Get the raw event ID value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type-safe record ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordId(u64);

impl RecordId {
    /// Create a new record ID.
    pub fn new(id: u64) -> Self {
        RecordId(id)
    }

    /// Get the raw record ID value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for RecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Event severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventLevel {
    /// Audit successful
    AuditSuccess = 0,
    /// Audit failure
    AuditFailure = 1,
    /// Critical
    Critical = 2,
    /// Error
    Error = 3,
    /// Warning
    Warning = 4,
    /// Informational
    #[default]
    Informational = 5,
    /// Verbose (Debug)
    Verbose = 6,
}

impl EventLevel {
    /// Create from Windows Event Log level code.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(EventLevel::AuditSuccess),
            1 => Some(EventLevel::AuditFailure),
            2 => Some(EventLevel::Critical),
            3 => Some(EventLevel::Error),
            4 => Some(EventLevel::Warning),
            5 => Some(EventLevel::Informational),
            6 => Some(EventLevel::Verbose),
            _ => None,
        }
    }
}

impl std::fmt::Display for EventLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventLevel::AuditSuccess => write!(f, "AuditSuccess"),
            EventLevel::AuditFailure => write!(f, "AuditFailure"),
            EventLevel::Critical => write!(f, "Critical"),
            EventLevel::Error => write!(f, "Error"),
            EventLevel::Warning => write!(f, "Warning"),
            EventLevel::Informational => write!(f, "Informational"),
            EventLevel::Verbose => write!(f, "Verbose"),
        }
    }
}

/// Static string cache for provider and channel names.
///
/// Caches commonly-used provider and channel names as static `Cow<'static, str>`
/// to reduce allocations. All cached strings are compile-time constants.
struct StringCache {
    providers: HashMap<&'static str, Cow<'static, str>>,
    channels: HashMap<&'static str, Cow<'static, str>>,
}

impl StringCache {
    /// Initialize cache with common provider and channel names.
    fn new() -> Self {
        let mut cache = StringCache {
            providers: HashMap::new(),
            channels: HashMap::new(),
        };

        // Common providers - these are cached as static strings
        const COMMON_PROVIDERS: &[&str] = &[
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-WinRM/Operational",
            "Microsoft-Windows-DNS-Client/Operational",
            "Perflib",
            "Windows Defender",
            "Google Chrome",
        ];

        // Common channels
        const COMMON_CHANNELS: &[&str] = &[
            "Security",
            "System",
            "Application",
            "Operational",
            "Analytic",
            "Debug",
            "Setup",
            "Forwarded Events",
        ];

        for provider in COMMON_PROVIDERS {
            cache.providers.insert(provider, Cow::Borrowed(provider));
        }

        for channel in COMMON_CHANNELS {
            cache.channels.insert(channel, Cow::Borrowed(channel));
        }

        cache
    }

}

/// Static cache instance (lazy initialized).
static STRING_CACHE: OnceLock<StringCache> = OnceLock::new();

/// Get cached provider name.
///
/// Common provider names (Security, System, etc.) are cached as static strings.
/// Unknown names are returned as owned strings.
pub fn intern_provider(name: &str) -> Cow<'static, str> {
    let cache = STRING_CACHE.get_or_init(StringCache::new);
    if let Some(cached) = cache.providers.get(name) {
        return cached.clone();
    }
    Cow::Owned(name.to_string())
}

/// Get cached channel name.
///
/// Common channel names (Security, Operational, etc.) are cached as static strings.
/// Unknown names are returned as owned strings.
pub fn intern_channel(name: &str) -> Cow<'static, str> {
    let cache = STRING_CACHE.get_or_init(StringCache::new);
    if let Some(cached) = cache.channels.get(name) {
        return cached.clone();
    }
    Cow::Owned(name.to_string())
}

/// Intern common EventData field names to reduce allocations.
///
/// Common field names (Security events, Sysmon, PowerShell, etc.) are cached
/// as static strings. Unknown field names are allocated.
///
/// Performance: ~2-3ns per lookup for cached names (10M+ lookups/sec).
pub fn intern_field_name(name: &str) -> Cow<'static, str> {
    match name {
        // Security - Authentication
        "SubjectUserName" => Cow::Borrowed("SubjectUserName"),
        "SubjectDomainName" => Cow::Borrowed("SubjectDomainName"),
        "SubjectUserSid" => Cow::Borrowed("SubjectUserSid"),
        "SubjectLogonId" => Cow::Borrowed("SubjectLogonId"),
        "TargetUserName" => Cow::Borrowed("TargetUserName"),
        "TargetDomainName" => Cow::Borrowed("TargetDomainName"),
        "TargetUserSid" => Cow::Borrowed("TargetUserSid"),
        "TargetLogonId" => Cow::Borrowed("TargetLogonId"),
        "LogonType" => Cow::Borrowed("LogonType"),
        "IpAddress" => Cow::Borrowed("IpAddress"),
        "IpPort" => Cow::Borrowed("IpPort"),
        "WorkstationName" => Cow::Borrowed("WorkstationName"),
        "AuthenticationPackageName" => Cow::Borrowed("AuthenticationPackageName"),

        // Security - Process
        "ProcessName" => Cow::Borrowed("ProcessName"),
        "ProcessId" => Cow::Borrowed("ProcessId"),
        "CommandLine" => Cow::Borrowed("CommandLine"),
        "NewProcessName" => Cow::Borrowed("NewProcessName"),
        "NewProcessId" => Cow::Borrowed("NewProcessId"),
        "ParentProcessName" => Cow::Borrowed("ParentProcessName"),

        // Security - Object Access
        "ObjectName" => Cow::Borrowed("ObjectName"),
        "AccessList" => Cow::Borrowed("AccessList"),
        "PrivilegeList" => Cow::Borrowed("PrivilegeList"),

        // Sysmon - Process
        "Image" => Cow::Borrowed("Image"),
        "ImageLoaded" => Cow::Borrowed("ImageLoaded"),
        "ParentImage" => Cow::Borrowed("ParentImage"),
        "ParentCommandLine" => Cow::Borrowed("ParentCommandLine"),
        "ParentProcessId" => Cow::Borrowed("ParentProcessId"),
        "Hashes" => Cow::Borrowed("Hashes"),
        "User" => Cow::Borrowed("User"),
        "IntegrityLevel" => Cow::Borrowed("IntegrityLevel"),

        // Sysmon - Network
        "SourceIp" => Cow::Borrowed("SourceIp"),
        "SourcePort" => Cow::Borrowed("SourcePort"),
        "SourceHostname" => Cow::Borrowed("SourceHostname"),
        "DestinationIp" => Cow::Borrowed("DestinationIp"),
        "DestinationPort" => Cow::Borrowed("DestinationPort"),
        "DestinationHostname" => Cow::Borrowed("DestinationHostname"),
        "Protocol" => Cow::Borrowed("Protocol"),

        // Sysmon - File/Registry
        "TargetFilename" => Cow::Borrowed("TargetFilename"),
        "TargetObject" => Cow::Borrowed("TargetObject"),
        "Details" => Cow::Borrowed("Details"),

        // PowerShell
        "ScriptBlockText" => Cow::Borrowed("ScriptBlockText"),
        "Path" => Cow::Borrowed("Path"),
        "MessageNumber" => Cow::Borrowed("MessageNumber"),
        "MessageTotal" => Cow::Borrowed("MessageTotal"),

        // Common
        "EventID" => Cow::Borrowed("EventID"),
        "Level" => Cow::Borrowed("Level"),
        "Keywords" => Cow::Borrowed("Keywords"),
        "Message" => Cow::Borrowed("Message"),
        "Data" => Cow::Borrowed("Data"),

        // Not in cache - allocate
        _ => Cow::Owned(name.to_string()),
    }
}

/// A complete Windows Event Log record.
#[derive(Debug, Clone, Default)]
pub struct Event {
    /// Event ID (event type identifier)
    pub id: EventId,

    /// Event severity level
    pub level: EventLevel,

    /// Provider/source name (e.g., "Security", "System")
    pub provider: Cow<'static, str>,

    /// Channel name (e.g., "Security", "Operational")
    pub channel: Cow<'static, str>,

    /// Computer name where event occurred
    pub computer: String,

    /// Event timestamp (may be unavailable for corrupted events)
    pub timestamp: Option<SystemTime>,

    /// Event record ID (unique per log, may wrap)
    pub record_id: Option<RecordId>,

    /// Process ID that generated the event
    pub process_id: Option<ProcessId>,

    /// Thread ID that generated the event
    pub thread_id: Option<ThreadId>,

    /// User event data (key-value pairs with interned field names)
    pub data: Option<std::collections::HashMap<Cow<'static, str>, String>>,

    /// Formatted event message (available when parsed with `.with_message()`)
    pub formatted_message: Option<String>,
}

impl Event {
    /// Create an empty event with defaults.
    pub fn new() -> Self {
        Event {
            id: EventId(0),
            level: EventLevel::Informational,
            provider: Cow::Borrowed(""),
            channel: Cow::Borrowed(""),
            computer: String::new(),
            timestamp: None,
            record_id: None,
            process_id: None,
            thread_id: None,
            data: None,
            formatted_message: None,
        }
    }
}

/// Rendering format for events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderFormat {
    /// Render as individual property values (fastest, ~9 system fields)
    Values,
    /// Render as XML (complete, all fields)
    Xml,
}

/// Corrupted or unparseable event.
#[derive(Debug, Clone)]
pub struct CorruptedEvent {
    /// Record ID if available
    pub record_id: Option<u64>,
    /// Component that failed (e.g., "EvtRender_Xml")
    pub component: Cow<'static, str>,
    /// Error reason
    pub reason: Cow<'static, str>,
}

/// Channel filter for listing event log channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelFilter {
    /// All channels
    All,
    /// Operational channels only
    Operational,
    /// Admin and higher severity
    AdminOrHigher,
    /// Include analytic channels
    IncludeAnalytic,
}

/// Result of an event query.
#[derive(Debug, Clone, Default)]
pub struct EventQueryResult {
    /// Events returned by query
    pub events: Vec<Event>,
    /// Corrupted events encountered during query
    pub corrupted: Vec<CorruptedEvent>,
    /// Total events processed (including corrupted)
    pub total_processed: usize,
}

// ============================================================================
// Helper extraction functions for custom event parsing
// ============================================================================

use crate::error::{Error, Result};
use std::ffi::c_void;
use windows::Win32::System::EventLog::*;

/// Extract event ID from raw EVT_HANDLE.
///
/// Useful for lightweight custom parsing without full Event struct allocation.
pub fn extract_event_id(handle: EVT_HANDLE) -> Result<u32> {
    extract_variant_field(handle, 0).and_then(|v| {
        unsafe {
            if v.Type == 8u32 {
                // EvtVarTypeUInt32
                Ok(v.Anonymous.UInt32Val)
            } else {
                Err(Error::Other(crate::error::OtherError::new(
                    "EventID field is not UInt32",
                )))
            }
        }
    })
}

/// Extract provider name from raw EVT_HANDLE.
pub fn extract_provider(handle: EVT_HANDLE) -> Result<String> {
    extract_variant_field(handle, 2).and_then(|v| {
        unsafe {
            if v.Type == 21u32 {
                // EvtVarTypeString
                let pwstr = v.Anonymous.StringVal;
                if !pwstr.is_null() {
                    let len = (0..).take_while(|&i| *pwstr.0.offset(i) != 0).count();
                    let slice = std::slice::from_raw_parts(pwstr.0, len);
                    Ok(String::from_utf16_lossy(slice))
                } else {
                    Err(Error::Other(crate::error::OtherError::new(
                        "Provider field is null",
                    )))
                }
            } else {
                Err(Error::Other(crate::error::OtherError::new(
                    "Provider field is not string",
                )))
            }
        }
    })
}

/// Extract event level from raw EVT_HANDLE.
pub fn extract_level(handle: EVT_HANDLE) -> Result<u8> {
    extract_variant_field(handle, 1).and_then(|v| {
        unsafe {
            if v.Type == 2u32 {
                // EvtVarTypeByte
                Ok(v.Anonymous.ByteVal)
            } else {
                Err(Error::Other(crate::error::OtherError::new(
                    "Level field is not byte",
                )))
            }
        }
    })
}

/// Extract timestamp from raw EVT_HANDLE.
pub fn extract_timestamp(handle: EVT_HANDLE) -> Result<SystemTime> {
    extract_variant_field(handle, 5).and_then(|v| {
        unsafe {
            if v.Type == 17u32 {
                // EvtVarTypeFileTime
                let filetime = v.Anonymous.FileTimeVal;
                let intervals = filetime * 100;
                let duration = Duration::from_nanos(intervals);
                let epoch = UNIX_EPOCH - Duration::from_secs(11644473600); // Windows epoch
                Ok(epoch + duration)
            } else {
                Err(Error::Other(crate::error::OtherError::new(
                    "Timestamp field is not FILETIME",
                )))
            }
        }
    })
}

/// Extract record ID from raw EVT_HANDLE.
pub fn extract_record_id(handle: EVT_HANDLE) -> Result<u64> {
    extract_variant_field(handle, 6).and_then(|v| {
        unsafe {
            if v.Type == 10u32 {
                // EvtVarTypeUInt64
                Ok(v.Anonymous.UInt64Val)
            } else {
                Err(Error::Other(crate::error::OtherError::new(
                    "RecordID field is not UInt64",
                )))
            }
        }
    })
}

/// Internal helper to extract a single variant field from an event handle.
fn extract_variant_field(event_handle: EVT_HANDLE, field_index: usize) -> Result<EVT_VARIANT> {
    let mut buffer = vec![0u8; 8192];
    let mut buffer_used = 0u32;
    let mut prop_count = 0u32;

    let result = unsafe {
        EvtRender(
            EVT_HANDLE::default(),
            event_handle,
            EvtRenderEventValues.0,
            buffer.len() as u32,
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut buffer_used,
            &mut prop_count,
        )
    };

    if result.is_err() {
        return Err(Error::Other(crate::error::OtherError::new(
            "Failed to render event values",
        )));
    }

    let variant_ptr = buffer.as_ptr() as *const EVT_VARIANT;
    let variants = unsafe { std::slice::from_raw_parts(variant_ptr, prop_count as usize) };

    if field_index >= variants.len() {
        return Err(Error::Other(crate::error::OtherError::new(Cow::Owned(
            format!("Field index {} out of range", field_index),
        ))));
    }

    Ok(variants[field_index])
}
