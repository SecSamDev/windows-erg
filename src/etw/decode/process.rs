use super::events::{DecodedEvent, ProcessEndEvent, ProcessStartEvent};
use super::helpers::{
    ascii_string_until_null, extract_value_from_buffer, sid_to_string_with_size, utf16_until_null,
};
use crate::types::ProcessId;

const PROCESS_START: u8 = 1;
const PROCESS_END: u8 = 2;

#[cfg(target_pointer_width = "32")]
const POINTER_SIZE: usize = 4;

#[cfg(target_pointer_width = "64")]
const POINTER_SIZE: usize = 8;

const REQUIRED_SIZE_V0: usize = 10 + 2 * POINTER_SIZE;
const REQUIRED_SIZE_V1_TO_V4: usize = 11 * 4 + 4 * POINTER_SIZE;

#[derive(Debug, Clone)]
struct ProcessCommon {
    process_id: ProcessId,
    parent_process_id: ProcessId,
    session_id: Option<u32>,
    exit_status: Option<u32>,
    unique_process_key: Option<u64>,
    directory_table_base: Option<u64>,
    image_file_name: String,
    command_line: Option<String>,
    user_sid: Option<String>,
}

/// Decode process provider payload bytes into typed process start/end events.
///
/// Supports process payload layouts for versions 0 through 4 and returns
/// `None` when the opcode/version combination is not recognized or when the
/// payload is truncated.
pub(crate) fn decode_process_parts(version: u8, opcode: u8, data: &[u8]) -> Option<DecodedEvent> {
    if opcode != PROCESS_START && opcode != PROCESS_END {
        return None;
    }

    let parsed = match version {
        0 => parse_v0(data),
        1 => parse_v1(data),
        2 => parse_v2(data),
        3 | 4 => parse_v3_v4(data),
        _ => None,
    }?;

    Some(match opcode {
        PROCESS_START => DecodedEvent::ProcessStart(ProcessStartEvent {
            process_id: parsed.process_id,
            parent_process_id: parsed.parent_process_id,
            session_id: parsed.session_id,
            exit_status: parsed.exit_status,
            unique_process_key: parsed.unique_process_key,
            directory_table_base: parsed.directory_table_base,
            image_file_name: parsed.image_file_name,
            command_line: parsed.command_line,
            user_sid: parsed.user_sid,
            version,
        }),
        PROCESS_END => DecodedEvent::ProcessEnd(ProcessEndEvent {
            process_id: parsed.process_id,
            parent_process_id: parsed.parent_process_id,
            session_id: parsed.session_id,
            exit_status: parsed.exit_status,
            unique_process_key: parsed.unique_process_key,
            directory_table_base: parsed.directory_table_base,
            image_file_name: parsed.image_file_name,
            command_line: parsed.command_line,
            user_sid: parsed.user_sid,
            version,
        }),
        _ => return None,
    })
}

fn parse_v0(data: &[u8]) -> Option<ProcessCommon> {
    if data.len() < REQUIRED_SIZE_V0 {
        return None;
    }

    let (process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (parent_process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;

    let (user_sid, sid_size) = sid_to_string_with_size(data)?;
    let data = &data[sid_size..];
    let (image_file_name, _) = ascii_string_until_null(data)?;

    Some(ProcessCommon {
        process_id: ProcessId::new(process_id),
        parent_process_id: ProcessId::new(parent_process_id),
        session_id: None,
        exit_status: None,
        unique_process_key: None,
        directory_table_base: None,
        image_file_name,
        command_line: None,
        user_sid: Some(user_sid),
    })
}

fn parse_v1(data: &[u8]) -> Option<ProcessCommon> {
    if data.len() < REQUIRED_SIZE_V1_TO_V4 {
        return None;
    }

    let (directory_table_base, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (parent_process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (session_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (exit_status, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;

    let (user_sid, sid_size) = sid_to_string_with_size(data)?;
    let data = &data[sid_size..];
    let (image_file_name, name_size) = ascii_string_until_null(data)?;
    let data = &data[name_size..];
    let (command_line, _) = utf16_until_null(data)?;

    Some(ProcessCommon {
        process_id: ProcessId::new(process_id),
        parent_process_id: ProcessId::new(parent_process_id),
        session_id: Some(session_id),
        exit_status: Some(exit_status),
        unique_process_key: None,
        directory_table_base: Some(directory_table_base as u64),
        image_file_name,
        command_line: Some(command_line),
        user_sid: Some(user_sid),
    })
}

fn parse_v2(data: &[u8]) -> Option<ProcessCommon> {
    if data.len() < REQUIRED_SIZE_V1_TO_V4 {
        return None;
    }

    let (unique_process_key, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (parent_process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (session_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (exit_status, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;

    let (user_sid, sid_size) = sid_to_string_with_size(data)?;
    let data = &data[sid_size..];
    let (image_file_name, name_size) = ascii_string_until_null(data)?;
    let data = &data[name_size..];
    let (command_line, _) = utf16_until_null(data)?;

    Some(ProcessCommon {
        process_id: ProcessId::new(process_id),
        parent_process_id: ProcessId::new(parent_process_id),
        session_id: Some(session_id),
        exit_status: Some(exit_status),
        unique_process_key: Some(unique_process_key as u64),
        directory_table_base: None,
        image_file_name,
        command_line: Some(command_line),
        user_sid: Some(user_sid),
    })
}

fn parse_v3_v4(data: &[u8]) -> Option<ProcessCommon> {
    if data.len() < REQUIRED_SIZE_V1_TO_V4 {
        return None;
    }

    let (unique_process_key, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (parent_process_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (session_id, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (exit_status, data): (u32, &[u8]) = extract_value_from_buffer(data)?;
    let (directory_table_base, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (usize, &[u8]) = extract_value_from_buffer(data)?;
    let (_, data): (u32, &[u8]) = extract_value_from_buffer(data)?;

    let (user_sid, sid_size) = sid_to_string_with_size(data)?;
    let data = &data[sid_size..];
    let (image_file_name, name_size) = ascii_string_until_null(data)?;
    let data = &data[name_size..];
    let (command_line, _) = utf16_until_null(data)?;

    Some(ProcessCommon {
        process_id: ProcessId::new(process_id),
        parent_process_id: ProcessId::new(parent_process_id),
        session_id: Some(session_id),
        exit_status: Some(exit_status),
        unique_process_key: Some(unique_process_key as u64),
        directory_table_base: Some(directory_table_base as u64),
        image_file_name,
        command_line: Some(command_line),
        user_sid: Some(user_sid),
    })
}
