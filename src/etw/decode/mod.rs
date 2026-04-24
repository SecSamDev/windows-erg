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
use windows::Win32::System::Diagnostics::Etw::{ImageLoadGuid, ProcessGuid};
use windows::core::GUID;

/// Decode a captured [`TraceEvent`] into a typed [`DecodedEvent`].
///
/// This dispatches to provider-specific decoders first, then falls back to
/// schema-backed generic decoding when parsed fields are available.
pub(crate) fn decode_trace_event(event: &TraceEvent) -> DecodedEvent {
    decode_from_record_parts(
        event.provider_guid,
        event.version,
        event.opcode,
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
    data: &[u8],
    fields: Option<&[EventField]>,
) -> DecodedEvent {
    if provider_guid == ProcessGuid
        && let Some(decoded) = process::decode_process_parts(version, opcode, data) {
            return decoded;
        }

    if provider_guid == ImageLoadGuid
        && let Some(decoded) = image::decode_image_parts(version, opcode, data) {
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
