//! Event rendering with publisher metadata caching.

#![allow(dead_code)] // Some helpers may be used in future implementations

use super::types::{
    CorruptedEvent, Event, EventId, EventLevel, ProcessId, RecordId, RenderFormat, ThreadId,
    intern_channel, intern_field_name, intern_provider,
};
use crate::error::Result;
use quick_xml::Reader;
use quick_xml::events::Event as XmlEvent;
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows::Win32::System::EventLog::*;
use windows::core::PWSTR;

// Static cache for publisher metadata handles to avoid repeated opens
// Maps provider name -> EVT_HANDLE for metadata
static PUBLISHER_METADATA_CACHE: OnceLock<Arc<RwLock<HashMap<String, EvtPublisherHandle>>>> =
    OnceLock::new();

// Wrapper for EVT_HANDLE that implements Drop for cleanup
#[derive(Clone)]
struct EvtPublisherHandle(EVT_HANDLE);

impl Drop for EvtPublisherHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = EvtClose(self.0);
            }
        }
    }
}

/// Get or create cached publisher metadata handle.
#[allow(dead_code)] // Used in format_message which is WIP
fn get_publisher_metadata(provider_name: &str) -> Result<Option<EvtPublisherHandle>> {
    let cache = PUBLISHER_METADATA_CACHE.get_or_init(|| Arc::new(RwLock::new(HashMap::new())));

    // Fast path - read lock (concurrent reads)
    {
        // Lock cannot be poisoned - allocations abort on OOM rather than panic
        let map = cache.read().unwrap();
        if let Some(handle) = map.get(provider_name) {
            return Ok(Some(handle.clone()));
        }
    }

    // Slow path - open metadata and cache with write lock
    let provider_wide: Vec<u16> = provider_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        EvtOpenPublisherMetadata(
            EVT_HANDLE::default(), // Local computer
            PWSTR(provider_wide.as_ptr() as *mut u16),
            PWSTR::null(), // Local publisher
            0,             // Default locale
            0,             // Flags
        )
    };

    match handle {
        Ok(h) => {
            let wrapped = EvtPublisherHandle(h);
            // Lock cannot be poisoned - allocations abort on OOM rather than panic
            cache
                .write()
                .unwrap()
                .insert(provider_name.to_string(), wrapped.clone());
            Ok(Some(wrapped))
        }
        Err(_) => {
            // Provider metadata not available (DLL missing, manifest unregistered, etc.)
            // Return None for graceful degradation
            Ok(None)
        }
    }
}

/// Render an event from a handle with selected format.
pub fn render_event(
    event_handle: EVT_HANDLE,
    format: RenderFormat,
    include_event_data: bool,
    parse_message: bool,
) -> std::result::Result<Event, CorruptedEvent> {
    let mut event = match format {
        RenderFormat::Values => render_event_values(event_handle)?,
        RenderFormat::Xml => render_event_xml(event_handle)?,
    };

    // Extract EventData fields if requested (works best with XML format)
    if include_event_data && format == RenderFormat::Xml {
        // Re-render as XML to extract EventData
        // (We already have the event from XML rendering above, just need to extract data fields)
        // This is a small optimization opportunity - could cache the XML string
        let mut buffer = vec![0u8; 16384];
        let mut buffer_used = 0u32;
        let mut prop_count = 0u32;

        let result = unsafe {
            EvtRender(
                EVT_HANDLE::default(),
                event_handle,
                EvtRenderEventXml.0,
                buffer.len() as u32,
                Some(buffer.as_mut_ptr() as *mut c_void),
                &mut buffer_used,
                &mut prop_count,
            )
        };

        if result.is_ok() {
            let xml_bytes = &buffer[..buffer_used as usize];
            let xml_str = String::from_utf16_lossy(unsafe {
                std::slice::from_raw_parts(xml_bytes.as_ptr() as *const u16, xml_bytes.len() / 2)
            });

            event.data = extract_event_data_from_xml(&xml_str);
        }
    }

    // Format message if requested
    if parse_message {
        event.formatted_message = format_message(event_handle, event.provider.as_ref())
            .ok()
            .flatten();
    }

    Ok(event)
}

/// Render event as individual values using EVT_RENDER_EVENT_VALUES.
///
/// This retrieves system and event data fields efficiently.
fn render_event_values(event_handle: EVT_HANDLE) -> std::result::Result<Event, CorruptedEvent> {
    let mut buffer = vec![0u8; 8192]; // Larger buffer for complete event data
    let mut buffer_used = 0u32;
    let mut prop_count = 0u32;

    // Render event with system context to extract individual values
    let result = unsafe {
        EvtRender(
            EVT_HANDLE::default(), // System context
            event_handle,
            EvtRenderEventValues.0,
            buffer.len() as u32,
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut buffer_used,
            &mut prop_count,
        )
    };

    if result.is_err() {
        return Err(CorruptedEvent {
            record_id: None,
            component: "EvtRender_Values".into(),
            reason: "Failed to render event values".into(),
        });
    }

    // Cast buffer to EVT_VARIANT array for property access
    let variant_ptr = buffer.as_ptr() as *const EVT_VARIANT;
    let variants = unsafe { std::slice::from_raw_parts(variant_ptr, prop_count as usize) };

    // Extract properties from variants following Event Log schema order
    // System properties are in fixed positions (0-9 are standard system fields)
    let mut event = Event::default();

    if !variants.is_empty() {
        // Event ID (System/EventID)
        if !variants.is_empty() {
            let variant = &variants[0];
            event.id = EventId::new(extract_u32_from_variant(variant).unwrap_or(0));
        }

        // Qualifiers/Event Level (System/Level)
        if variants.len() > 1 {
            let variant = &variants[1];
            let level_val = extract_u8_from_variant(variant).unwrap_or(4);
            event.level = EventLevel::from_code(level_val).unwrap_or(EventLevel::Verbose);
        }

        // Provider Name (System/Provider/@Name)
        if variants.len() > 2 {
            let variant = &variants[2];
            if let Some(provider) = extract_string_from_variant(variant) {
                event.provider = intern_provider(&provider);
            }
        }

        // Channel (System/Channel)
        if variants.len() > 3 {
            let variant = &variants[3];
            if let Some(channel) = extract_string_from_variant(variant) {
                event.channel = intern_channel(&channel);
            }
        }

        // Computer (System/Computer)
        if variants.len() > 4 {
            let variant = &variants[4];
            if let Some(computer) = extract_string_from_variant(variant) {
                event.computer = computer;
            }
        }

        // Timestamp (System/TimeCreated/@SystemTime)
        if variants.len() > 5 {
            let variant = &variants[5];
            if let Some(timestamp) = extract_systemtime_from_variant(variant) {
                event.timestamp = Some(timestamp);
            }
        }

        // Record ID (System/EventRecordID)
        if variants.len() > 6 {
            let variant = &variants[6];
            if let Some(rid) = extract_u64_from_variant(variant) {
                event.record_id = Some(RecordId::new(rid));
            }
        }

        // Process ID (System/Execution/@ProcessID)
        if variants.len() > 7 {
            let variant = &variants[7];
            if let Some(pid) = extract_u32_from_variant(variant) {
                event.process_id = Some(ProcessId::new(pid));
            }
        }

        // Thread ID (System/Execution/@ThreadID)
        if variants.len() > 8 {
            let variant = &variants[8];
            if let Some(tid) = extract_u32_from_variant(variant) {
                event.thread_id = Some(ThreadId::new(tid));
            }
        }

        // Extract event data (user fields) if present
        if variants.len() > 9 {
            event.data = Some(HashMap::new());
        }
    }

    Ok(event)
}

/// Render complete event as XML using quick-xml for robust parsing.
///
/// This includes all fields as an XML string for flexible parsing.
fn render_event_xml(event_handle: EVT_HANDLE) -> std::result::Result<Event, CorruptedEvent> {
    let mut buffer = vec![0u8; 16384]; // Larger buffer for complete XML
    let mut buffer_used = 0u32;
    let mut prop_count = 0u32;

    let result = unsafe {
        EvtRender(
            EVT_HANDLE::default(),
            event_handle,
            EvtRenderEventXml.0,
            buffer.len() as u32,
            Some(buffer.as_mut_ptr() as *mut c_void),
            &mut buffer_used,
            &mut prop_count,
        )
    };

    if result.is_err() {
        return Err(CorruptedEvent {
            record_id: None,
            component: Cow::Borrowed("EvtRender_Xml"),
            reason: Cow::Borrowed("Failed to render event as XML"),
        });
    }

    // Convert buffer to XML string
    let xml_bytes = &buffer[..buffer_used as usize];
    let xml_str = String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(xml_bytes.as_ptr() as *const u16, xml_bytes.len() / 2)
    });

    // Parse using quick-xml for robust, standards-compliant parsing
    parse_event_xml_with_quick_xml(&xml_str)
}

/// Parse Windows Event XML using quick-xml Reader API.
///
/// Robust event-driven parsing that handles edge cases properly.
fn parse_event_xml_with_quick_xml(xml_str: &str) -> std::result::Result<Event, CorruptedEvent> {
    let mut reader = Reader::from_str(xml_str);
    reader.config_mut().trim_text(true);

    let mut event = Event::default();
    let mut buf = Vec::new();
    let mut current_tag = String::new();
    let mut in_system = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).into_owned();

                if tag_name == "System" {
                    in_system = true;
                } else if in_system {
                    current_tag = tag_name.clone();

                    // Handle elements with attributes
                    if tag_name == "Provider" {
                        for attr in e.attributes() {
                            if let Ok(attr) = attr
                                && attr.key.as_ref() == b"Name"
                                    && let Ok(value) = String::from_utf8(attr.value.to_vec()) {
                                        event.provider = intern_provider(&value);
                                    }
                        }
                    } else if tag_name == "TimeCreated" {
                        for attr in e.attributes() {
                            if let Ok(attr) = attr
                                && attr.key.as_ref() == b"SystemTime"
                                    && let Ok(value) = String::from_utf8(attr.value.to_vec()) {
                                        event.timestamp = parse_iso8601_timestamp(&value);
                                    }
                        }
                    }
                }
            }
            Ok(XmlEvent::End(e)) => {
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if tag_name == "System" {
                    in_system = false;
                }
                current_tag.clear();
            }
            Ok(XmlEvent::Text(e)) => {
                if in_system && !current_tag.is_empty() {
                    let value = String::from_utf8_lossy(e.as_ref()).into_owned();

                    match current_tag.as_str() {
                        "EventID" => {
                            event.id = EventId::new(value.parse().unwrap_or(0));
                        }
                        "Level" => {
                            let level_val: u8 = value.parse().unwrap_or(4);
                            event.level =
                                EventLevel::from_code(level_val).unwrap_or(EventLevel::Verbose);
                        }
                        "Channel" => {
                            event.channel = intern_channel(&value);
                        }
                        "Computer" => {
                            event.computer = value;
                        }
                        "EventRecordID" => {
                            if let Ok(rid) = value.parse::<u64>() {
                                event.record_id = Some(RecordId::new(rid));
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(XmlEvent::Empty(e)) => {
                // Handle self-closing tags like <Execution ProcessID="1234" ThreadID="5678"/>
                let tag_name = String::from_utf8_lossy(e.name().as_ref()).into_owned();

                if in_system && tag_name == "Execution" {
                    for attr in e.attributes().flatten() {
                        let attr_name = String::from_utf8_lossy(attr.key.as_ref());
                        if let Ok(value) = String::from_utf8(attr.value.to_vec()) {
                            match attr_name.as_ref() {
                                "ProcessID" => {
                                    if let Ok(pid) = value.parse::<u32>() {
                                        event.process_id = Some(ProcessId::new(pid));
                                    }
                                }
                                "ThreadID" => {
                                    if let Ok(tid) = value.parse::<u32>() {
                                        event.thread_id = Some(ThreadId::new(tid));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => {
                return Err(CorruptedEvent {
                    record_id: event.record_id.map(|r| r.as_u64()),
                    component: Cow::Borrowed("quick-xml"),
                    reason: Cow::Borrowed("XML parsing error"),
                });
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(event)
}

/// Extract EventData fields from XML using quick-xml Reader API.
///
/// Returns HashMap with interned field names for performance.
/// Silently skips malformed fields for defensive parsing.
fn extract_event_data_from_xml(xml: &str) -> Option<HashMap<Cow<'static, str>, String>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut data_fields = HashMap::new();
    let mut buf = Vec::new();
    let mut in_event_data = false;
    let mut current_field_name: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) if e.name().as_ref() == b"EventData" => {
                in_event_data = true;
            }
            Ok(XmlEvent::End(e)) if e.name().as_ref() == b"EventData" => {
                in_event_data = false;
            }
            Ok(XmlEvent::Start(e)) if in_event_data && e.name().as_ref() == b"Data" => {
                // Extract Name attribute
                current_field_name = e
                    .attributes()
                    .filter_map(|a| a.ok())
                    .find(|attr| attr.key.as_ref() == b"Name")
                    .and_then(|attr| String::from_utf8(attr.value.to_vec()).ok());
            }
            Ok(XmlEvent::Text(e)) if in_event_data && current_field_name.is_some() => {
                // Extract value and intern field name
                let value = String::from_utf8_lossy(e.as_ref()).into_owned();
                let field_name = current_field_name.take().unwrap();
                data_fields.insert(intern_field_name(&field_name), value);
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => break, // Silently skip on parse error
            _ => {}
        }
        buf.clear();
    }

    if data_fields.is_empty() {
        None
    } else {
        Some(data_fields)
    }
}

/// Parse Windows FILETIME string (ISO 8601 format) to SystemTime.
///
/// Parses format: "2024-01-15T10:30:45.123456Z"
fn parse_iso8601_timestamp(time_str: &str) -> Option<SystemTime> {
    // Ensure minimum length
    if time_str.len() < 20 {
        return None;
    }

    // Extract components (2024-01-15T10:30:45.123456Z)
    let year: i32 = time_str.get(0..4)?.parse().ok()?;
    let month: u32 = time_str.get(5..7)?.parse().ok()?;
    let day: u32 = time_str.get(8..10)?.parse().ok()?;
    let hour: u32 = time_str.get(11..13)?.parse().ok()?;
    let minute: u32 = time_str.get(14..16)?.parse().ok()?;
    let second: u32 = time_str.get(17..19)?.parse().ok()?;

    // Extract microseconds if present
    let microseconds: u32 = if time_str.len() > 20 && time_str.as_bytes()[19] == b'.' {
        time_str.get(20..26)?.parse().ok().unwrap_or(0)
    } else {
        0
    };

    // Calculate days since Unix epoch (1970-01-01)
    let mut days_since_epoch: i64 = 0;

    // Add days for complete years
    for y in 1970..year {
        days_since_epoch += if is_leap_year(y) { 366 } else { 365 };
    }

    // Add days for complete months in current year
    const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days_since_epoch += DAYS_IN_MONTH[(m - 1) as usize] as i64;
        // Add leap day if February and leap year
        if m == 2 && is_leap_year(year) {
            days_since_epoch += 1;
        }
    }

    // Add remaining days
    days_since_epoch += (day - 1) as i64;

    // Calculate total seconds
    let total_seconds =
        days_since_epoch * 86400 + (hour as i64 * 3600) + (minute as i64 * 60) + second as i64;

    // Build SystemTime
    let duration =
        Duration::from_secs(total_seconds as u64) + Duration::from_micros(microseconds as u64);
    Some(UNIX_EPOCH + duration)
}

/// Check if a year is a leap year.
fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// Helper functions for variant extraction
#[allow(dead_code)]
fn extract_u8_from_variant(variant: &EVT_VARIANT) -> Option<u8> {
    unsafe {
        if variant.Type == 2u32 {
            // EvtVarTypeByte
            Some(variant.Anonymous.ByteVal)
        } else {
            None
        }
    }
}

fn extract_u16_from_variant(variant: &EVT_VARIANT) -> Option<u16> {
    unsafe {
        if variant.Type == 6u32 {
            // EvtVarTypeUInt16
            Some(variant.Anonymous.UInt16Val)
        } else {
            None
        }
    }
}

fn extract_u32_from_variant(variant: &EVT_VARIANT) -> Option<u32> {
    unsafe {
        if variant.Type == 8u32 {
            // EvtVarTypeUInt32
            Some(variant.Anonymous.UInt32Val)
        } else {
            None
        }
    }
}

fn extract_u64_from_variant(variant: &EVT_VARIANT) -> Option<u64> {
    unsafe {
        if variant.Type == 10u32 {
            // EvtVarTypeUInt64
            Some(variant.Anonymous.UInt64Val)
        } else {
            None
        }
    }
}

fn extract_string_from_variant(variant: &EVT_VARIANT) -> Option<String> {
    unsafe {
        if variant.Type == 21u32 {
            // EvtVarTypeString
            let pwstr = variant.Anonymous.StringVal;
            if !pwstr.is_null() {
                let len = (0..).take_while(|&i| *pwstr.0.offset(i) != 0).count();
                let slice = std::slice::from_raw_parts(pwstr.0, len);
                return Some(String::from_utf16_lossy(slice).to_string());
            }
        }
        None
    }
}

fn extract_systemtime_from_variant(variant: &EVT_VARIANT) -> Option<SystemTime> {
    unsafe {
        if variant.Type == 29u32 {
            // EvtVarTypeFileTime
            let filetime = variant.Anonymous.FileTimeVal;
            // Windows FILETIME is 100-nanosecond intervals since 1601-01-01
            // Convert to SystemTime (Unix epoch)
            const FILETIME_EPOCH_DIFF: u64 = 116444736000000000; // 100-nanosecond intervals from 1601 to 1970

            if filetime > FILETIME_EPOCH_DIFF {
                let unix_time_100ns = filetime - FILETIME_EPOCH_DIFF;
                let seconds = unix_time_100ns / 10_000_000;
                let nanos = (unix_time_100ns % 10_000_000) * 100;

                return Some(UNIX_EPOCH + std::time::Duration::new(seconds, nanos as u32));
            }
        }
        None
    }
}

/// Format a message for an event using provider metadata.
///
/// This is optional and can be expensive if metadata isn't cached.
/// Call only when message rendering is needed.
pub fn format_message(event_handle: EVT_HANDLE, provider_name: &str) -> Result<Option<String>> {
    // Get or cache the publisher metadata
    let metadata = get_publisher_metadata(provider_name)?;

    // Return None if metadata unavailable (graceful degradation)
    let Some(metadata_handle) = metadata else {
        return Ok(None);
    };

    // Use EvtFormatMessage to get the formatted message
    let mut buffer_size = 4096u32;
    let mut buffer: Vec<u16>;

    loop {
        buffer = vec![0u16; (buffer_size / 2) as usize];
        let mut buffer_used = 0u32;

        let result = unsafe {
            EvtFormatMessage(
                metadata_handle.0,
                event_handle,
                0,                       // No message ID (use event's own message)
                None,                    // No values array
                EvtFormatMessageEvent.0, // Format the event message
                Some(&mut buffer[..]),
                &mut buffer_used,
            )
        };

        if result.is_ok() {
            // Success - convert to string
            let len = if buffer_used > 0 {
                (buffer_used / 2) as usize
            } else {
                0
            };
            if len > 0 && len <= buffer.len() {
                // Trim null terminator
                let actual_len = if len > 0 && buffer[len - 1] == 0 {
                    len - 1
                } else {
                    len
                };
                let message = String::from_utf16_lossy(&buffer[..actual_len]);
                return Ok(Some(message));
            }
            return Ok(None);
        }

        // Check error code
        let error = unsafe { windows::Win32::Foundation::GetLastError() };
        if error.0 == 122 {
            // ERROR_INSUFFICIENT_BUFFER
            // Resize and try again
            buffer_size = buffer_used;
            if buffer_size > 1048576 {
                // 1MB limit
                return Ok(None); // Message too large, give up
            }
            continue;
        } else {
            // Other error - metadata might be unavailable or event has no message
            return Ok(None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_publisher_metadata_cache_initialization() {
        // Ensure cache initializes properly
        let cache = PUBLISHER_METADATA_CACHE.get_or_init(|| Arc::new(RwLock::new(HashMap::new())));

        let map = cache.read().unwrap();
        assert!(map.is_empty());
    }
}
