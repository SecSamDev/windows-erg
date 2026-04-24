use super::events::{DecodedEvent, ImageLoadEvent, ImageUnloadEvent};
use super::helpers::{extract_value_from_buffer, utf16_until_null};
use crate::types::ProcessId;

const IMAGE_LOAD: u8 = 10;
const IMAGE_UNLOAD: u8 = 2;

#[cfg(target_pointer_width = "32")]
const POINTER_SIZE: usize = 4;

#[cfg(target_pointer_width = "64")]
const POINTER_SIZE: usize = 8;

const REQUIRED_SIZE_V3: usize = 12 * 4 + 4 * POINTER_SIZE;

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
/// for unsupported versions, opcodes, or truncated payloads.
pub(crate) fn decode_image_parts(version: u8, opcode: u8, data: &[u8]) -> Option<DecodedEvent> {
    let parsed = match version {
        2..=4 => parse_v3(data),
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

fn parse_v3(data: &[u8]) -> Option<ImageCommon> {
    if data.len() < REQUIRED_SIZE_V3 {
        return None;
    }

    let (image_base, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (image_size, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (checksum, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (timestamp, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (default_base, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (file_name, _) = utf16_until_null(data)?;

    Some(ImageCommon {
        process_id: ProcessId::new(process_id),
        image_base: image_base as u64,
        image_size: image_size as u64,
        checksum,
        timestamp,
        default_base: default_base as u64,
        file_name,
    })
}
