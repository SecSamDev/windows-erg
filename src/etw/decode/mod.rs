mod events;
mod generic_map;
mod helpers;
mod image;
mod process;

pub use events::{
    DecodedEvent, EventField, EventFieldValue, FileIoEvent, FileIoOperation, ImageLoadEvent,
    ImageUnloadEvent, ProcessEndEvent, ProcessStartEvent, RegistryEvent, RegistryOperation,
    TcpEvent, TcpOperation,
};

use super::types::TraceEvent;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER, ImageLoadGuid, ProcessGuid,
};
use windows::core::GUID;

/// Size in bytes of pointer-sized payload fields, from `EVENT_HEADER.Flags`.
///
/// This is the pointer width of the session that logged the event, which
/// differs from the consumer's when a 32-bit process reads 64-bit kernel
/// events under WoW64. Falls back to the consumer's width when neither flag
/// is set.
pub(crate) fn pointer_size_from_header_flags(flags: u16) -> usize {
    let flags = u32::from(flags);
    if flags & EVENT_HEADER_FLAG_64_BIT_HEADER != 0 {
        8
    } else if flags & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
        4
    } else {
        size_of::<usize>()
    }
}

/// Decode a captured [`TraceEvent`] into a typed [`DecodedEvent`].
///
/// This dispatches to provider-specific decoders first, then falls back to
/// schema-backed generic decoding when parsed fields are available.
pub(crate) fn decode_trace_event(event: &TraceEvent) -> DecodedEvent {
    decode_from_record_parts(
        event.provider_guid,
        event.version,
        event.opcode,
        event.pointer_size,
        &event.data,
        event.fields(),
    )
}

/// Decode an event payload from raw provider metadata and bytes.
///
/// Dispatch order:
/// - process provider direct decoder
/// - image-load provider direct decoder
/// - generic field-based decoder (TCP/Registry/File I/O)
/// - fallback to [`DecodedEvent::Unknown`]
pub(crate) fn decode_from_record_parts(
    provider_guid: GUID,
    version: u8,
    opcode: u8,
    pointer_size: usize,
    data: &[u8],
    fields: Option<&[EventField]>,
) -> DecodedEvent {
    if provider_guid == ProcessGuid
        && let Some(decoded) = process::decode_process_parts(version, opcode, pointer_size, data)
    {
        return decoded;
    }

    if provider_guid == ImageLoadGuid
        && let Some(decoded) = image::decode_image_parts(version, opcode, pointer_size, data)
    {
        return decoded;
    }

    if let Some(fields) = fields {
        if let Some(decoded) = generic_map::decode_from_generic(provider_guid, opcode, fields) {
            return decoded;
        }
        return DecodedEvent::Generic(fields.to_vec());
    }

    DecodedEvent::Unknown
}
