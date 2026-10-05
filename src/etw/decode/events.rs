#![allow(missing_docs)]

use crate::types::ProcessId;
use std::net::IpAddr;

/// A decoded ETW event with typed fields.
#[derive(Debug, Clone)]
pub enum DecodedEvent {
    /// Process start event (opcode 1).
    ProcessStart(ProcessStartEvent),
    /// Process end event (opcode 2).
    ProcessEnd(ProcessEndEvent),
    /// Image load event (opcode 10).
    ImageLoad(ImageLoadEvent),
    /// Image unload event (opcode 2).
    ImageUnload(ImageUnloadEvent),
    /// TCP/IP kernel event.
    Tcp(TcpEvent),
    /// Registry kernel event.
    Registry(RegistryEvent),
    /// File I/O kernel event.
    FileIo(FileIoEvent),
    /// Generic schema-decoded fields (typically from TDH parsing).
    Generic(Vec<EventField>),
    /// Event was not recognized by the direct decoders.
    Unknown,
}

/// A named field decoded from ETW payload data.
#[derive(Debug, Clone)]
pub struct EventField {
    pub name: String,
    pub value: EventFieldValue,
}

/// Typed value for a schema-decoded ETW field.
#[derive(Debug, Clone)]
pub enum EventFieldValue {
    /// UTF-8 string value.
    String(String),
    /// IP address value (IPv4 or IPv6).
    IpAddr(IpAddr),
    /// Unsigned 8-bit integer.
    U8(u8),
    /// Unsigned 16-bit integer.
    U16(u16),
    /// Unsigned 32-bit integer.
    U32(u32),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Signed 32-bit integer.
    I32(i32),
    /// Signed 64-bit integer.
    I64(i64),
    /// Boolean value.
    Bool(bool),
    /// GUID value.
    Guid(windows::core::GUID),
    /// Opaque binary payload.
    Binary(Vec<u8>),
    /// Pointer-sized address represented as u64.
    Pointer(u64),
}

/// Decoded operation kind for TCP kernel provider events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOperation {
    /// Outbound data send.
    Send,
    /// Inbound data receive.
    Receive,
    /// Connection establishment.
    Connect,
    /// Connection teardown.
    Disconnect,
    /// Retransmitted segment.
    Retransmit,
    /// Accepted incoming connection.
    Accept,
    /// Reconnect attempt or completion.
    Reconnect,
    /// Data copy operation.
    Copy,
    /// Opcode did not match a known TCP operation.
    Unknown,
}

/// Typed representation of a decoded TCP event.
#[derive(Debug, Clone)]
pub struct TcpEvent {
    pub operation: TcpOperation,
    pub process_id: Option<ProcessId>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: Option<u16>,
    pub size: Option<u32>,
    pub sequence_number: Option<u32>,
}

/// Decoded operation kind for Registry kernel provider events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryOperation {
    /// Create key operation.
    Create,
    /// Open key operation.
    Open,
    /// Delete key operation.
    DeleteKey,
    /// Query key metadata.
    QueryKey,
    /// Set value data.
    SetValue,
    /// Delete value data.
    DeleteValue,
    /// Query value data.
    QueryValue,
    /// Enumerate subkeys.
    EnumerateKey,
    /// Enumerate values.
    EnumerateValue,
    /// Set key information metadata.
    SetInformation,
    /// Opcode did not match a known registry operation.
    Unknown,
}

/// Typed representation of a decoded Registry event.
#[derive(Debug, Clone)]
pub struct RegistryEvent {
    pub operation: RegistryOperation,
    pub process_id: Option<ProcessId>,
    pub key_name: Option<String>,
    pub relative_name: Option<String>,
    pub value_name: Option<String>,
    pub status: Option<u32>,
    pub key_handle: Option<u64>,
}

/// Decoded operation kind for File I/O kernel provider events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileIoOperation {
    /// File name event (type 0): maps a `file_key` to `file_name`.
    Name,
    /// File create/open operation (type 64). Carries `open_path`.
    Create,
    /// Name event emitted when a file is created (type 32): `file_key` and
    /// `file_name`, not an operation.
    NameCreate,
    /// Name event emitted when a file is deleted (type 35): `file_key` and
    /// `file_name` of the deleted file, not an operation.
    NameDelete,
    /// File rundown event (type 36).
    Rundown,
    /// Cleanup when the last handle is released (type 65).
    Cleanup,
    /// Close when file object is freed (type 66).
    Close,
    /// Set file information (type 69).
    SetInformation,
    /// Directory enumeration (type 72).
    DirectoryEnumeration,
    /// File buffer flush (type 73).
    Flush,
    /// Query file information (type 74).
    QueryInformation,
    /// File system control operation (type 75).
    FileSystemControl,
    /// End-of-operation event (type 76).
    OperationEnd,
    /// Directory change notification (type 77).
    DirectoryNotification,
    /// File read operation (type 67).
    Read,
    /// File write operation (type 68).
    Write,
    /// File delete operation (type 70). Carries no path; see `DeletePath`.
    Delete,
    /// File rename operation (type 71). Carries no path; see `RenamePath`.
    Rename,
    /// Delete with the file's path in `file_name` (type 79).
    DeletePath,
    /// Rename with the *new* name in `file_name` (type 80).
    RenamePath,
    /// Hard-link creation with the link's path in `file_name` (type 81).
    SetLinkPath,
    /// Opcode did not match a known File I/O operation.
    Unknown,
}

/// Typed representation of a decoded File I/O event.
#[derive(Debug, Clone)]
pub struct FileIoEvent {
    pub operation: FileIoOperation,
    /// Only set when the schema has a `PID`/`ProcessId` field. Kernel File I/O
    /// schemas carry `TTID` (a thread id) instead; use `thread_id` or the
    /// event header's process id.
    pub process_id: Option<ProcessId>,
    /// Issuing thread (`TTID`).
    pub thread_id: Option<u32>,
    pub file_object: Option<u64>,
    pub irp_ptr: Option<u64>,
    pub file_key: Option<u64>,
    /// Path on create events (`OpenPath`).
    pub open_path: Option<String>,
    /// Path on name events and path operations (`FileName`): the deleted
    /// file for `NameDelete`/`DeletePath`, the new name for `RenamePath`.
    pub file_name: Option<String>,
    pub create_options: Option<u32>,
    pub file_attributes: Option<u32>,
    pub share_access: Option<u32>,
    /// `FILE_INFORMATION_CLASS` on set/query/delete/rename/path events.
    pub info_class: Option<u32>,
    /// Class-specific extra data on the same events.
    pub extra_info: Option<u64>,
    /// Bytes transferred on read/write events (needs `SystemProvider::FileIo`).
    pub io_size: Option<u32>,
    /// File offset on read/write events.
    pub offset: Option<u64>,
}

/// Typed representation of a decoded process start event.
#[derive(Debug, Clone)]
pub struct ProcessStartEvent {
    pub process_id: ProcessId,
    pub parent_process_id: ProcessId,
    pub session_id: Option<u32>,
    pub exit_status: Option<u32>,
    pub unique_process_key: Option<u64>,
    pub directory_table_base: Option<u64>,
    pub image_file_name: String,
    pub command_line: Option<String>,
    pub user_sid: Option<String>,
    pub version: u8,
}

/// Typed representation of a decoded process end event.
#[derive(Debug, Clone)]
pub struct ProcessEndEvent {
    pub process_id: ProcessId,
    pub parent_process_id: ProcessId,
    pub session_id: Option<u32>,
    pub exit_status: Option<u32>,
    pub unique_process_key: Option<u64>,
    pub directory_table_base: Option<u64>,
    pub image_file_name: String,
    pub command_line: Option<String>,
    pub user_sid: Option<String>,
    pub version: u8,
}

/// Typed representation of a decoded image load event.
#[derive(Debug, Clone)]
pub struct ImageLoadEvent {
    pub process_id: ProcessId,
    pub image_base: u64,
    pub image_size: u64,
    pub checksum: u32,
    pub timestamp: u32,
    pub default_base: u64,
    pub file_name: String,
    pub version: u8,
}

/// Typed representation of a decoded image unload event.
#[derive(Debug, Clone)]
pub struct ImageUnloadEvent {
    pub process_id: ProcessId,
    pub image_base: u64,
    pub image_size: u64,
    pub checksum: u32,
    pub timestamp: u32,
    pub default_base: u64,
    pub file_name: String,
    pub version: u8,
}
