use super::events::{DecodedEvent, ImageLoadEvent, ImageUnloadEvent};
use super::helpers::{extract_pointer_from_buffer, extract_value_from_buffer, utf16_until_null};
use crate::types::ProcessId;

const IMAGE_LOAD: u8 = 10;
const IMAGE_UNLOAD: u8 = 2;

const fn required_size_v3(pointer_size: usize) -> usize {
    12 * 4 + 4 * pointer_size
}

#[derive(Debug, Clone)]
struct ImageCommon {
    process_id: ProcessId,
    image_base: u64,
    image_size: u64,
    checksum: u32,
    timestamp: u32,
    default_base: u64,
    file_name: String,
}

/// Decode image provider payload bytes into typed load/unload events.
///
/// Currently supports image payload versions 2, 3, and 4 and returns `None`
/// for unsupported versions, opcodes, or truncated payloads. `pointer_size`
/// is the width of pointer-sized fields in `data` (4 or 8), as recorded in
/// the event header.
pub(crate) fn decode_image_parts(
    version: u8,
    opcode: u8,
    pointer_size: usize,
    data: &[u8],
) -> Option<DecodedEvent> {
    let parsed = match version {
        2..=4 => parse_v3(data, pointer_size),
        _ => None,
    }?;

    match opcode {
        IMAGE_LOAD => Some(DecodedEvent::ImageLoad(ImageLoadEvent {
            process_id: parsed.process_id,
            image_base: parsed.image_base,
            image_size: parsed.image_size,
            checksum: parsed.checksum,
            timestamp: parsed.timestamp,
            default_base: parsed.default_base,
            file_name: parsed.file_name,
            version,
        })),
        IMAGE_UNLOAD => Some(DecodedEvent::ImageUnload(ImageUnloadEvent {
            process_id: parsed.process_id,
            image_base: parsed.image_base,
            image_size: parsed.image_size,
            checksum: parsed.checksum,
            timestamp: parsed.timestamp,
            default_base: parsed.default_base,
            file_name: parsed.file_name,
            version,
        })),
        _ => None,
    }
}

fn parse_v3(data: &[u8], pointer_size: usize) -> Option<ImageCommon> {
    if data.len() < required_size_v3(pointer_size) {
        return None;
    }

    let (image_base, data) = extract_pointer_from_buffer(data, pointer_size)?;
    let (image_size, data) = extract_pointer_from_buffer(data, pointer_size)?;
    let (process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (checksum, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (timestamp, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (default_base, data) = extract_pointer_from_buffer(data, pointer_size)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (file_name, _) = utf16_until_null(data)?;

    Some(ImageCommon {
        process_id: ProcessId::new(process_id),
        image_base,
        image_size,
        checksum,
        timestamp,
        default_base,
        file_name,
    })
}
