//! ETW types and structures.

use super::decode::{DecodedEvent, EventField, decode_trace_event};
use crate::types::{ProcessId, ThreadId};
use std::time::SystemTime;
use windows::core::GUID;

/// System-level event sources for kernel tracing.
///
/// Each variant represents a category of events emitted by the Windows kernel.
/// Because these providers operate inside the kernel, they capture activity
/// from **all processes** on the machine without any instrumentation in the
/// target application.
///
/// # Privileges
///
/// Enabling any `SystemProvider` requires **Administrator** privileges. The
/// underlying trace session uses the `NT Kernel Logger` — a Windows-reserved
/// name for kernel providers — so only one kernel session can be active at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProvider {
    /// Process and thread creation/termination events.
    ///
    /// Emits an event whenever any process or thread starts or stops system-wide.
    Process,

    /// Registry key and value operations.
    ///
    /// Emits an event for every registry read, write, create, and delete
    /// across all processes. Can be high-volume on busy systems.
    Registry,

    /// TCP/IP network connections and data transfer.
    ///
    /// Emits events for TCP connections, UDP sends/receives, and connection
    /// failures. Covers both IPv4 and IPv6.
    Network,

    /// File I/O operations (create, read, write, delete).
    ///
    /// Emits an event for every file system operation. Very high volume —
    /// consider using `next_batch_with_filter` to focus on relevant paths.
    FileIo,

    /// DLL and EXE image load/unload events.
    ///
    /// Emits an event whenever any executable or library is mapped into or
    /// unmapped from a process. Useful for detecting code injection.
    ImageLoad,
}

impl SystemProvider {
    /// Get the `EVENT_TRACE_FLAG` bitmask for this provider.
    pub(crate) fn trace_flags(self) -> u32 {
        use windows::Win32::System::Diagnostics::Etw::*;
        match self {
            SystemProvider::Process => (EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_THREAD).0,
            SystemProvider::Registry => EVENT_TRACE_FLAG_REGISTRY.0,
            SystemProvider::Network => EVENT_TRACE_FLAG_NETWORK_TCPIP.0,
            SystemProvider::FileIo => (EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT).0,
            SystemProvider::ImageLoad => EVENT_TRACE_FLAG_IMAGE_LOAD.0,
        }
    }
}

/// Verbosity level for a trace session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TraceLevel {
    /// Critical events only.
    Critical = 1,
    /// Error events.
    Error = 2,
    /// Warning events.
    Warning = 3,
    /// Informational events.
    Info = 4,
    /// Verbose / debug events.
    Verbose = 5,
}

/// Optional per-event thread metadata enrichment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadContext {
    /// Process ID associated with the event's thread.
    pub process_id: ProcessId,
    /// Thread ID that emitted the event.
    pub thread_id: ThreadId,
}

impl ThreadContext {
    /// Create a new thread context value.
    pub fn new(process_id: ProcessId, thread_id: ThreadId) -> Self {
        Self {
            process_id,
            thread_id,
        }
    }
}

/// Optional per-event stack trace enrichment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackTrace {
    /// Correlation identifier for matching stack begin/end context.
    pub match_id: u64,
    /// Captured instruction pointer frames (normalized as 64-bit addresses).
    pub frames: Vec<u64>,
}

impl StackTrace {
    /// Create a new stack trace enrichment payload.
    pub fn new(match_id: u64, frames: Vec<u64>) -> Self {
        Self { match_id, frames }
    }
}

/// Optional per-event CPU sampling enrichment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuSample {
    /// Logical processor number that emitted the event.
    pub processor_number: u8,
}

impl CpuSample {
    /// Create a new CPU sample enrichment payload.
    pub fn new(processor_number: u8) -> Self {
        Self { processor_number }
    }
}

/// A single event captured from a kernel trace session.
///
/// Each `TraceEvent` is emitted by one of the active [`SystemProvider`]s.
/// The `id` and `opcode` fields identify the specific operation; the `data`
/// field contains the raw binary payload whose layout depends on the provider
/// and event ID.
#[derive(Debug, Clone)]
pub struct TraceEvent {
    /// Event ID — identifies the event type within the provider.
    pub id: u16,

    /// Event version.
    pub version: u8,

    /// Opcode — identifies the operation phase (start, stop, info, etc.).
    pub opcode: u8,

    /// Severity level of this event.
    pub level: u8,

    /// GUID of the provider that emitted this event.
    pub provider_guid: GUID,

    /// ID of the process that triggered the event.
    pub process_id: ProcessId,

    /// ID of the thread that triggered the event.
    pub thread_id: ThreadId,

    /// When the event was recorded.
    pub timestamp: SystemTime,

    /// Raw binary payload. Layout depends on the provider and event ID.
    pub data: Vec<u8>,

    /// Optional thread context enrichment (enabled by `with_thread_context`).
    pub thread_context: Option<ThreadContext>,

    /// Optional stack trace enrichment (enabled by `with_stack_traces`).
    pub stack_trace: Option<StackTrace>,

    /// Optional CPU sampling enrichment (enabled by `with_cpu_samples`).
    pub cpu_sample: Option<CpuSample>,

    /// Optional schema-parsed fields (available when detailed event parsing is enabled).
    fields: Option<Vec<EventField>>,
}

impl TraceEvent {
    /// Build a `TraceEvent` from a raw `EVENT_RECORD`.
    ///
    /// Used by the ProcessTrace callback pipeline in `session.rs`.
    pub fn from_event_record(
        record: &windows::Win32::System::Diagnostics::Etw::EVENT_RECORD,
    ) -> Self {
        Self::from_event_record_with_fields(record, None)
    }

    /// Build a `TraceEvent` from a raw `EVENT_RECORD` with optional pre-parsed fields.
    pub(crate) fn from_event_record_with_fields(
        record: &windows::Win32::System::Diagnostics::Etw::EVENT_RECORD,
        fields: Option<Vec<EventField>>,
    ) -> Self {
        let header = &record.EventHeader;
        let desc = &header.EventDescriptor;

        let timestamp = filetime_to_systemtime(header.TimeStamp);

        let data = if record.UserDataLength > 0 && !record.UserData.is_null() {
            unsafe {
                std::slice::from_raw_parts(
                    record.UserData as *const u8,
                    record.UserDataLength as usize,
                )
                .to_vec()
            }
        } else {
            Vec::new()
        };

        TraceEvent {
            id: desc.Id,
            version: desc.Version,
            opcode: desc.Opcode,
            level: desc.Level,
            provider_guid: header.ProviderId,
            process_id: ProcessId::new(header.ProcessId),
            thread_id: ThreadId::new(header.ThreadId),
            timestamp,
            data,
            thread_context: None,
            stack_trace: None,
            cpu_sample: None,
            fields,
        }
    }

    /// Decode this event into a typed representation when a known kernel
    /// layout is available.
    ///
    /// Returns [`DecodedEvent::Unknown`] when no direct decoder matches the
    /// provider, version, and opcode combination.
    pub fn decode(&self) -> DecodedEvent {
        decode_trace_event(self)
    }

    /// Returns schema-parsed fields when detailed event parsing is enabled.
    pub fn fields(&self) -> Option<&[EventField]> {
        self.fields.as_deref()
    }
}

/// Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to `SystemTime`.
fn filetime_to_systemtime(filetime: i64) -> SystemTime {
    // Number of 100-ns intervals between 1601-01-01 and 1970-01-01.
    const FILETIME_TO_UNIX_EPOCH: i64 = 116_444_736_000_000_000;
    const NANOS_PER_100NS: u32 = 100;

    let intervals_since_unix = filetime.saturating_sub(FILETIME_TO_UNIX_EPOCH);
    let seconds = (intervals_since_unix / 10_000_000) as u64;
    let nanos = ((intervals_since_unix % 10_000_000) * NANOS_PER_100NS as i64) as u32;

    SystemTime::UNIX_EPOCH + std::time::Duration::new(seconds, nanos)
}

#[cfg(test)]
mod tests {
    use super::{DecodedEvent, TraceEvent};
    use crate::etw::{
        EventField, EventFieldValue, FileIoOperation, RegistryOperation, TcpOperation,
    };
    use crate::types::{ProcessId, ThreadId};
    use std::time::SystemTime;
    use windows::Win32::System::Diagnostics::Etw::{
        FileIoGuid, ImageLoadGuid, ProcessGuid, RegistryGuid, TcpIpGuid,
    };

    #[test]
    fn decode_process_v0_start_event() {
        let event = TraceEvent {
            id: 0,
            version: 0,
            opcode: 1,
            level: 0,
            provider_guid: ProcessGuid,
            process_id: ProcessId::new(672),
            thread_id: ThreadId::new(0),
            timestamp: SystemTime::UNIX_EPOCH,
            data: vec![
                160, 2, 0, 0, 220, 7, 0, 0, 0, 0, 0, 0, 96, 140, 79, 210, 6, 180, 255, 255, 0, 0,
                0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 54, 245, 194, 143, 120, 21,
                213, 94, 151, 105, 93, 135, 89, 4, 0, 0, 99, 109, 100, 46, 101, 120, 101, 0, 0, 0,
                0, 0,
            ],
            thread_context: None,
            stack_trace: None,
            cpu_sample: None,
            fields: None,
        };

        match event.decode() {
            DecodedEvent::ProcessStart(decoded) => {
                assert_eq!(decoded.process_id, ProcessId::new(672));
                assert_eq!(decoded.parent_process_id, ProcessId::new(2012));
                assert_eq!(decoded.image_file_name, "cmd.exe");
            }
            other => panic!("unexpected decode result: {other:?}"),
        }
    }

    #[test]
    fn decode_image_v2_v3_v4_load_event() {
        let event = TraceEvent {
            id: 0,
            version: 3,
            opcode: 10,
            level: 0,
            provider_guid: ImageLoadGuid,
            process_id: ProcessId::new(3996),
            thread_id: ThreadId::new(0),
            timestamp: SystemTime::UNIX_EPOCH,
            data: vec![
                0, 0, 8, 72, 251, 127, 0, 0, 0, 32, 8, 0, 0, 0, 0, 0, 156, 15, 0, 0, 70, 110, 8, 0,
                255, 233, 215, 246, 12, 1, 0, 0, 0, 0, 8, 72, 251, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 92, 0, 68, 0, 101, 0, 118, 0, 105, 0, 99, 0, 101, 0, 92,
                0, 72, 0, 97, 0, 114, 0, 100, 0, 100, 0, 105, 0, 115, 0, 107, 0, 86, 0, 111, 0,
                108, 0, 117, 0, 109, 0, 101, 0, 50, 0, 92, 0, 87, 0, 105, 0, 110, 0, 100, 0, 111,
                0, 119, 0, 115, 0, 92, 0, 83, 0, 121, 0, 115, 0, 116, 0, 101, 0, 109, 0, 51, 0, 50,
                0, 92, 0, 98, 0, 99, 0, 114, 0, 121, 0, 112, 0, 116, 0, 112, 0, 114, 0, 105, 0,
                109, 0, 105, 0, 116, 0, 105, 0, 118, 0, 101, 0, 115, 0, 46, 0, 100, 0, 108, 0, 108,
                0, 0, 0,
            ],
            thread_context: None,
            stack_trace: None,
            cpu_sample: None,
            fields: None,
        };

        for version in [2u8, 3u8, 4u8] {
            let mut candidate = event.clone();
            candidate.version = version;

            match candidate.decode() {
                DecodedEvent::ImageLoad(decoded) => {
                    assert_eq!(decoded.process_id, ProcessId::new(3996));
                    assert!(decoded.file_name.ends_with("bcryptprimitives.dll"));
                    assert_eq!(decoded.version, version);
                }
                other => panic!("unexpected decode result for version {version}: {other:?}"),
            }
        }
    }

    #[test]
    fn decode_generic_from_preparsed_fields() {
        let event = TraceEvent {
            id: 999,
            version: 1,
            opcode: 42,
            level: 4,
            provider_guid: windows::core::GUID::from_u128(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa),
            process_id: ProcessId::new(1),
            thread_id: ThreadId::new(1),
            timestamp: SystemTime::UNIX_EPOCH,
            data: Vec::new(),
            thread_context: None,
            stack_trace: None,
            cpu_sample: None,
            fields: Some(vec![EventField {
                name: "Example".to_string(),
                value: EventFieldValue::U32(7),
            }]),
        };

        match event.decode() {
            DecodedEvent::Generic(fields) => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].name, "Example");
            }
            other => panic!("unexpected decode result: {other:?}"),
        }
    }

    #[test]
    fn decode_typed_tcp_from_preparsed_fields() {
        let event = TraceEvent {
            id: 10,
            version: 2,
            opcode: 10,
            level: 4,
            provider_guid: TcpIpGuid,
            process_id: ProcessId::new(1234),
            thread_id: ThreadId::new(1),
            timestamp: SystemTime::UNIX_EPOCH,
            data: Vec::new(),
            thread_context: None,
            stack_trace: None,
            cpu_sample: None,
            fields: Some(vec![
                EventField {
                    name: "PID".to_string(),
                    value: EventFieldValue::U32(1234),
                },
                EventField {
                    name: "saddr".to_string(),
                    value: EventFieldValue::String("10.0.0.10".to_string()),
                },
                EventField {
                    name: "sport".to_string(),
                    value: EventFieldValue::U16(5050),
                },
                EventField {
                    name: "daddr".to_string(),
                    value: EventFieldValue::String("1.1.1.1".to_string()),
                },
                EventField {
                    name: "dport".to_string(),
                    value: EventFieldValue::U16(443),
                },
            ]),
        };

        match event.decode() {
            DecodedEvent::Tcp(tcp) => {
                assert_eq!(tcp.operation, TcpOperation::Send);
                assert_eq!(tcp.process_id, Some(ProcessId::new(1234)));
                assert_eq!(tcp.destination_port, Some(443));
            }
            other => panic!("unexpected decode result: {other:?}"),
        }
    }

    #[test]
    fn decode_typed_registry_from_preparsed_fields() {
        let event = TraceEvent {
            id: 14,
            version: 1,
            opcode: 14,
            level: 4,
            provider_guid: RegistryGuid,
            process_id: ProcessId::new(5678),
            thread_id: ThreadId::new(1),
            timestamp: SystemTime::UNIX_EPOCH,
            data: Vec::new(),
            thread_context: None,
            stack_trace: None,
            cpu_sample: None,
            fields: Some(vec![
                EventField {
                    name: "ProcessId".to_string(),
                    value: EventFieldValue::U32(5678),
                },
                EventField {
                    name: "KeyName".to_string(),
                    value: EventFieldValue::String("\\Registry\\Machine\\SOFTWARE".to_string()),
                },
                EventField {
                    name: "ValueName".to_string(),
                    value: EventFieldValue::String("TestValue".to_string()),
                },
                EventField {
                    name: "Status".to_string(),
                    value: EventFieldValue::U32(0),
                },
            ]),
        };

        match event.decode() {
            DecodedEvent::Registry(reg) => {
                assert_eq!(reg.operation, RegistryOperation::SetValue);
                assert_eq!(reg.process_id, Some(ProcessId::new(5678)));
                assert_eq!(reg.value_name.as_deref(), Some("TestValue"));
            }
            other => panic!("unexpected decode result: {other:?}"),
        }
    }

    #[test]
    fn decode_typed_fileio_from_preparsed_fields() {
        let event = TraceEvent {
            id: 32,
            version: 1,
            opcode: 32,
            level: 4,
            provider_guid: FileIoGuid,
            process_id: ProcessId::new(2222),
            thread_id: ThreadId::new(1),
            timestamp: SystemTime::UNIX_EPOCH,
            data: Vec::new(),
            thread_context: None,
            stack_trace: None,
            cpu_sample: None,
            fields: Some(vec![
                EventField {
                    name: "ProcessId".to_string(),
                    value: EventFieldValue::U32(2222),
                },
                EventField {
                    name: "OpenPath".to_string(),
                    value: EventFieldValue::String("C:\\Temp\\test.txt".to_string()),
                },
                EventField {
                    name: "FileObject".to_string(),
                    value: EventFieldValue::U64(0x1000),
                },
                EventField {
                    name: "IrpPtr".to_string(),
                    value: EventFieldValue::Pointer(0x2000),
                },
                EventField {
                    name: "CreateOptions".to_string(),
                    value: EventFieldValue::U32(0x20),
                },
            ]),
        };

        match event.decode() {
            DecodedEvent::FileIo(file) => {
                assert_eq!(file.operation, FileIoOperation::Create);
                assert_eq!(file.process_id, Some(ProcessId::new(2222)));
                assert_eq!(file.open_path.as_deref(), Some("C:\\Temp\\test.txt"));
                assert_eq!(file.file_object, Some(0x1000));
                assert_eq!(file.irp_ptr, Some(0x2000));
            }
            other => panic!("unexpected decode result: {other:?}"),
        }
    }
}
