use super::decode::{EventField, EventFieldValue};
use crate::utils::to_utf16_nul;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::System::Diagnostics::Etw::{
    self, EVENT_MAP_ENTRY, EVENT_MAP_INFO, EVENT_PROPERTY_INFO, EVENT_RECORD,
    EVENTMAP_ENTRY_VALUETYPE_STRING, EVENTMAP_ENTRY_VALUETYPE_ULONG,
    EVENTMAP_INFO_FLAG_MANIFEST_BITMAP, EVENTMAP_INFO_FLAG_MANIFEST_PATTERNMAP,
    EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP, EVENTMAP_INFO_FLAG_WBEM_BITMAP,
    EVENTMAP_INFO_FLAG_WBEM_FLAG, EVENTMAP_INFO_FLAG_WBEM_VALUEMAP, PropertyParamCount,
    PropertyParamFixedCount, PropertyParamFixedLength, PropertyParamLength, PropertyStruct,
    TDH_INTYPE_ANSISTRING, TDH_INTYPE_BOOLEAN, TDH_INTYPE_GUID, TDH_INTYPE_INT32, TDH_INTYPE_INT64,
    TDH_INTYPE_POINTER, TDH_INTYPE_UINT8, TDH_INTYPE_UINT16, TDH_INTYPE_UINT32, TDH_INTYPE_UINT64,
    TDH_INTYPE_UNICODESTRING, TDH_OUTTYPE_BOOLEAN, TDH_OUTTYPE_HEXINT8, TDH_OUTTYPE_HEXINT16,
    TDH_OUTTYPE_HEXINT32, TDH_OUTTYPE_HEXINT64, TDH_OUTTYPE_HRESULT, TDH_OUTTYPE_IPV4,
    TDH_OUTTYPE_IPV6, TDH_OUTTYPE_JSON, TDH_OUTTYPE_NTSTATUS, TDH_OUTTYPE_PID, TDH_OUTTYPE_PORT,
    TDH_OUTTYPE_REDUCEDSTRING, TDH_OUTTYPE_SOCKETADDRESS, TDH_OUTTYPE_STRING, TDH_OUTTYPE_TID,
    TDH_OUTTYPE_UTF8, TDH_OUTTYPE_WIN32ERROR, TDH_OUTTYPE_XML, TRACE_EVENT_INFO,
};
use windows::core::{GUID, PCWSTR};

const TDH_INTYPE_IPV4_VALUE: i32 = 19;
const TDH_INTYPE_IPV6_VALUE: i32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SchemaKey {
    provider: GUID,
    id: u16,
    opcode: u8,
    version: u8,
    level: u8,
}

impl SchemaKey {
    fn from_record(record: &EVENT_RECORD) -> Self {
        let desc = record.EventHeader.EventDescriptor;
        Self {
            provider: record.EventHeader.ProviderId,
            id: desc.Id,
            opcode: desc.Opcode,
            version: desc.Version,
            level: desc.Level,
        }
    }
}

#[derive(Debug, Clone)]
struct PropertyMeta {
    name: String,
    in_type: i32,
    out_type: i32,
    length: u16,
    count: u16,
    count_property_index: Option<usize>,
    length_property_index: Option<usize>,
    map_name: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedSchema {
    props: Vec<PropertyMeta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MapKind {
    Value,
    Bitmap,
}

#[derive(Debug, Clone)]
struct MapDefinition {
    kind: MapKind,
    entries: Vec<MapEntry>,
}

#[derive(Debug, Clone)]
struct MapEntry {
    key: MapKey,
    label: String,
}

#[derive(Debug, Clone)]
enum MapKey {
    Numeric(u64),
    Text(String),
}

/// Per-session cache of TDH schema metadata used to parse event payloads.
#[derive(Debug, Default)]
pub(crate) struct SchemaCache {
    cache: HashMap<SchemaKey, CachedSchema>,
    map_cache: HashMap<String, MapDefinition>,
}

impl SchemaCache {
    pub(crate) fn new() -> Self {
        Self {
            cache: HashMap::new(),
            map_cache: HashMap::new(),
        }
    }

    pub(crate) fn parse_event_fields(&mut self, record: &EVENT_RECORD) -> Option<Vec<EventField>> {
        let key = SchemaKey::from_record(record);
        if let std::collections::hash_map::Entry::Vacant(e) = self.cache.entry(key) {
            let schema = build_schema(record)?;
            e.insert(schema);
        }

        let schema = self.cache.get(&key)?.clone();
        let data = if record.UserDataLength > 0 && !record.UserData.is_null() {
            unsafe {
                std::slice::from_raw_parts(
                    record.UserData as *const u8,
                    record.UserDataLength as usize,
                )
            }
        } else {
            &[]
        };

        let mut fields = parse_values(&schema, data);
        self.apply_map_values(record, &schema, &mut fields);
        Some(fields)
    }

    fn apply_map_values(
        &mut self,
        record: &EVENT_RECORD,
        schema: &CachedSchema,
        fields: &mut [EventField],
    ) {
        for (idx, field) in fields.iter_mut().enumerate() {
            let Some(prop) = schema.props.get(idx) else {
                break;
            };
            let Some(map_name) = &prop.map_name else {
                continue;
            };

            let Some(map) = self.get_or_load_map(record, map_name) else {
                continue;
            };

            let mapped = extract_numeric_value(&field.value)
                .and_then(|v| map.render_numeric(v))
                .or_else(|| extract_text_value(&field.value).and_then(|v| map.render_text(v)));

            if let Some(mapped) = mapped {
                field.value = EventFieldValue::String(mapped);
            }
        }
    }

    fn get_or_load_map(&mut self, record: &EVENT_RECORD, map_name: &str) -> Option<MapDefinition> {
        if let Some(existing) = self.map_cache.get(map_name) {
            return Some(existing.clone());
        }

        let map = load_event_map(record, map_name)?;
        self.map_cache.insert(map_name.to_string(), map.clone());
        Some(map)
    }
}

impl MapDefinition {
    fn render_numeric(&self, value: u64) -> Option<String> {
        match self.kind {
            MapKind::Value => self.entries.iter().find_map(|entry| match &entry.key {
                MapKey::Numeric(k) if *k == value => Some(entry.label.clone()),
                _ => None,
            }),
            MapKind::Bitmap => {
                let mut labels = Vec::new();
                for entry in &self.entries {
                    if let MapKey::Numeric(bit) = entry.key
                        && bit != 0
                        && (value & bit) == bit
                    {
                        labels.push(entry.label.clone());
                    }
                }
                if labels.is_empty() {
                    self.entries.iter().find_map(|entry| match &entry.key {
                        MapKey::Numeric(k) if *k == value => Some(entry.label.clone()),
                        _ => None,
                    })
                } else {
                    Some(labels.join("|"))
                }
            }
        }
    }

    fn render_text(&self, value: &str) -> Option<String> {
        self.entries.iter().find_map(|entry| match &entry.key {
            MapKey::Text(k) if k.eq_ignore_ascii_case(value) => Some(entry.label.clone()),
            _ => None,
        })
    }
}

fn load_event_map(record: &EVENT_RECORD, map_name: &str) -> Option<MapDefinition> {
    let wide_name = to_utf16_nul(map_name);
    let mut size = 0u32;
    let first = unsafe {
        Etw::TdhGetEventMapInformation(record, PCWSTR(wide_name.as_ptr()), None, &mut size)
    };
    if first != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
        return None;
    }

    let mut buffer = vec![0u8; size as usize];
    let second = unsafe {
        Etw::TdhGetEventMapInformation(
            record,
            PCWSTR(wide_name.as_ptr()),
            Some(buffer.as_mut_ptr() as *mut EVENT_MAP_INFO),
            &mut size,
        )
    };
    if second != 0 {
        return None;
    }

    let map_info = unsafe { &*(buffer.as_ptr() as *const EVENT_MAP_INFO) };
    let entry_count = map_info.EntryCount as usize;
    let first_entry_ptr = std::ptr::addr_of!(map_info.MapEntryArray) as *const EVENT_MAP_ENTRY;
    let entries = unsafe { std::slice::from_raw_parts(first_entry_ptr, entry_count) };

    let value_type = unsafe { map_info.Anonymous.MapEntryValueType.0 };
    let is_numeric_value_type = value_type == EVENTMAP_ENTRY_VALUETYPE_ULONG.0;
    let is_string_value_type = value_type == EVENTMAP_ENTRY_VALUETYPE_STRING.0;
    if !is_numeric_value_type && !is_string_value_type {
        return None;
    }

    let flag = map_info.Flag.0;
    let is_bitmap = flag == EVENTMAP_INFO_FLAG_MANIFEST_BITMAP.0
        || flag == EVENTMAP_INFO_FLAG_WBEM_BITMAP.0
        || flag == EVENTMAP_INFO_FLAG_WBEM_FLAG.0;
    let is_valuemap = flag == EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP.0
        || flag == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP.0
        || flag == EVENTMAP_INFO_FLAG_MANIFEST_PATTERNMAP.0;
    let kind = if is_bitmap {
        MapKind::Bitmap
    } else if is_valuemap {
        MapKind::Value
    } else {
        return None;
    };

    let mut mapped_entries = Vec::new();
    for entry in entries {
        let key = if is_numeric_value_type {
            MapKey::Numeric(unsafe { entry.Anonymous.Value as u64 })
        } else {
            let text =
                read_utf16_cstr_at(&buffer, unsafe { entry.Anonymous.InputOffset } as usize)?;
            MapKey::Text(text)
        };
        let label = read_utf16_cstr_at(&buffer, entry.OutputOffset as usize)?;
        mapped_entries.push(MapEntry { key, label });
    }

    Some(MapDefinition {
        kind,
        entries: mapped_entries,
    })
}

fn build_schema(record: &EVENT_RECORD) -> Option<CachedSchema> {
    let mut buffer_size = 0u32;
    let rc = unsafe { Etw::TdhGetEventInformation(record, None, None, &mut buffer_size) };
    if rc != ERROR_INSUFFICIENT_BUFFER.0 {
        return None;
    }

    let mut buffer = vec![0u8; buffer_size as usize];
    let rc = unsafe {
        Etw::TdhGetEventInformation(
            record,
            None,
            Some(buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO),
            &mut buffer_size,
        )
    };
    if rc != 0 {
        return None;
    }

    let info = unsafe { &*(buffer.as_ptr() as *const TRACE_EVENT_INFO) };
    let prop_count = info.PropertyCount as usize;
    let first_prop =
        std::mem::size_of::<TRACE_EVENT_INFO>() - std::mem::size_of::<EVENT_PROPERTY_INFO>();

    let mut props = Vec::with_capacity(prop_count);

    for i in 0..prop_count {
        let offset = first_prop + i * std::mem::size_of::<EVENT_PROPERTY_INFO>();
        if offset + std::mem::size_of::<EVENT_PROPERTY_INFO>() > buffer.len() {
            break;
        }

        let prop = unsafe { &*(buffer[offset..].as_ptr() as *const EVENT_PROPERTY_INFO) };
        let name = read_utf16_cstr_at(&buffer, prop.NameOffset as usize).unwrap_or_default();

        let (in_type, out_type, length) = unsafe {
            (
                prop.Anonymous1.nonStructType.InType as i32,
                prop.Anonymous1.nonStructType.OutType as i32,
                prop.Anonymous3.length,
            )
        };

        let flags = prop.Flags.0 as u32;
        let has_struct = flags & (PropertyStruct.0 as u32) != 0;
        let has_param_count = flags & (PropertyParamCount.0 as u32) != 0;
        let has_fixed_count = flags & (PropertyParamFixedCount.0 as u32) != 0;
        let has_param_length = flags & (PropertyParamLength.0 as u32) != 0;
        let has_fixed_length = flags & (PropertyParamFixedLength.0 as u32) != 0;

        let count = if has_param_count && has_fixed_count {
            unsafe { prop.Anonymous2.count.max(1) }
        } else {
            1
        };

        let count_property_index = if has_param_count && !has_fixed_count {
            Some(unsafe { prop.Anonymous2.countPropertyIndex as usize })
        } else {
            None
        };

        let length_property_index = if has_param_length && !has_fixed_length {
            Some(unsafe { prop.Anonymous3.lengthPropertyIndex as usize })
        } else {
            None
        };

        props.push(PropertyMeta {
            name,
            in_type,
            out_type,
            length,
            count,
            count_property_index,
            length_property_index,
            map_name: if !has_struct && unsafe { prop.Anonymous1.nonStructType.MapNameOffset } > 0 {
                read_utf16_cstr_at(
                    &buffer,
                    unsafe { prop.Anonymous1.nonStructType.MapNameOffset } as usize,
                )
            } else {
                None
            },
        });
    }

    Some(CachedSchema { props })
}

fn parse_values(schema: &CachedSchema, data: &[u8]) -> Vec<EventField> {
    let mut fields = Vec::new();
    let mut offset = 0usize;
    let mut parsed_numeric: Vec<Option<u64>> = vec![None; schema.props.len()];

    for (idx, prop) in schema.props.iter().enumerate() {
        if offset >= data.len() {
            break;
        }

        let resolved_count = resolve_count(prop, &parsed_numeric);
        let resolved_length = resolve_length(prop, &parsed_numeric);

        let mut runtime_prop = prop.clone();
        runtime_prop.length = resolved_length;

        let parsed = if resolved_count > 1 {
            parse_counted_value(&runtime_prop, resolved_count, &data[offset..])
        } else {
            parse_one_value(&runtime_prop, &data[offset..])
        };

        if let Some((value, consumed)) = parsed {
            parsed_numeric[idx] = extract_numeric_value(&value);
            fields.push(EventField {
                name: prop.name.clone(),
                value,
            });
            offset = offset.saturating_add(consumed);
        } else {
            break;
        }
    }

    fields
}

fn resolve_count(prop: &PropertyMeta, parsed_numeric: &[Option<u64>]) -> u16 {
    if let Some(idx) = prop.count_property_index {
        return parsed_numeric
            .get(idx)
            .and_then(|v| *v)
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(1)
            .max(1);
    }
    prop.count.max(1)
}

fn resolve_length(prop: &PropertyMeta, parsed_numeric: &[Option<u64>]) -> u16 {
    if let Some(idx) = prop.length_property_index {
        return parsed_numeric
            .get(idx)
            .and_then(|v| *v)
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(prop.length);
    }
    prop.length
}

fn parse_counted_value(
    prop: &PropertyMeta,
    count: u16,
    data: &[u8],
) -> Option<(EventFieldValue, usize)> {
    let count = count as usize;
    if count == 0 {
        return Some((EventFieldValue::Binary(Vec::new()), 0));
    }

    if prop.length > 0 {
        let declared_len = prop.length as usize;
        let bytes_to_take = if declared_len >= count {
            declared_len
        } else {
            declared_len.saturating_mul(count)
        };
        if bytes_to_take > 0 && bytes_to_take <= data.len() {
            return Some((
                EventFieldValue::Binary(data[..bytes_to_take].to_vec()),
                bytes_to_take,
            ));
        }
    }

    let element_size = element_size_hint(prop)?;
    let bytes_to_take = element_size.checked_mul(count)?;
    if bytes_to_take > data.len() {
        return None;
    }

    Some((
        EventFieldValue::Binary(data[..bytes_to_take].to_vec()),
        bytes_to_take,
    ))
}

fn element_size_hint(prop: &PropertyMeta) -> Option<usize> {
    if prop.out_type == TDH_OUTTYPE_IPV4.0 {
        return Some(4);
    }
    if prop.out_type == TDH_OUTTYPE_IPV6.0 {
        return Some(16);
    }

    match prop.in_type {
        t if t == TDH_INTYPE_UINT8.0 => Some(1),
        t if t == TDH_INTYPE_UINT16.0 => Some(2),
        t if t == TDH_INTYPE_UINT32.0 => Some(4),
        t if t == TDH_INTYPE_UINT64.0 => Some(8),
        t if t == TDH_INTYPE_INT32.0 => Some(4),
        t if t == TDH_INTYPE_INT64.0 => Some(8),
        t if t == TDH_INTYPE_BOOLEAN.0 => Some(4),
        t if t == TDH_INTYPE_GUID.0 => Some(16),
        t if t == TDH_INTYPE_POINTER.0 => Some(8),
        t if t == TDH_INTYPE_UNICODESTRING.0 => None,
        t if t == TDH_INTYPE_ANSISTRING.0 => None,
        t if t == TDH_INTYPE_IPV4_VALUE => Some(4),
        t if t == TDH_INTYPE_IPV6_VALUE => Some(16),
        _ => None,
    }
}

fn extract_numeric_value(value: &EventFieldValue) -> Option<u64> {
    match value {
        EventFieldValue::U8(v) => Some(*v as u64),
        EventFieldValue::U16(v) => Some(*v as u64),
        EventFieldValue::U32(v) => Some(*v as u64),
        EventFieldValue::U64(v) => Some(*v),
        EventFieldValue::I32(v) => u64::try_from(*v).ok(),
        EventFieldValue::I64(v) => u64::try_from(*v).ok(),
        EventFieldValue::Pointer(v) => Some(*v),
        EventFieldValue::Bool(v) => Some(u64::from(*v)),
        _ => None,
    }
}

fn extract_text_value(value: &EventFieldValue) -> Option<&str> {
    match value {
        EventFieldValue::String(v) => Some(v.as_str()),
        _ => None,
    }
}

fn parse_one_value(prop: &PropertyMeta, data: &[u8]) -> Option<(EventFieldValue, usize)> {
    let size_hint = prop.length as usize;
    let prefer_fixed_blob = |scalar_size: usize| size_hint > scalar_size && size_hint <= data.len();

    if let Some((value, consumed)) = parse_out_type_override(prop, data) {
        return Some((value, consumed));
    }

    match prop.in_type {
        t if t == TDH_INTYPE_UINT8.0 => {
            if prefer_fixed_blob(1) {
                return Some((
                    EventFieldValue::Binary(data[..size_hint].to_vec()),
                    size_hint,
                ));
            }
            Some((EventFieldValue::U8(*data.first()?), 1))
        }
        t if t == TDH_INTYPE_UINT16.0 => {
            if prefer_fixed_blob(2) {
                return Some((
                    EventFieldValue::Binary(data[..size_hint].to_vec()),
                    size_hint,
                ));
            }
            let bytes: [u8; 2] = data.get(0..2)?.try_into().ok()?;
            Some((EventFieldValue::U16(u16::from_le_bytes(bytes)), 2))
        }
        t if t == TDH_INTYPE_UINT32.0 => {
            if prefer_fixed_blob(4) {
                return Some((
                    EventFieldValue::Binary(data[..size_hint].to_vec()),
                    size_hint,
                ));
            }
            let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
            Some((EventFieldValue::U32(u32::from_le_bytes(bytes)), 4))
        }
        t if t == TDH_INTYPE_UINT64.0 => {
            if prefer_fixed_blob(8) {
                return Some((
                    EventFieldValue::Binary(data[..size_hint].to_vec()),
                    size_hint,
                ));
            }
            let bytes: [u8; 8] = data.get(0..8)?.try_into().ok()?;
            Some((EventFieldValue::U64(u64::from_le_bytes(bytes)), 8))
        }
        t if t == TDH_INTYPE_INT32.0 => {
            if prefer_fixed_blob(4) {
                return Some((
                    EventFieldValue::Binary(data[..size_hint].to_vec()),
                    size_hint,
                ));
            }
            let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
            Some((EventFieldValue::I32(i32::from_le_bytes(bytes)), 4))
        }
        t if t == TDH_INTYPE_INT64.0 => {
            if prefer_fixed_blob(8) {
                return Some((
                    EventFieldValue::Binary(data[..size_hint].to_vec()),
                    size_hint,
                ));
            }
            let bytes: [u8; 8] = data.get(0..8)?.try_into().ok()?;
            Some((EventFieldValue::I64(i64::from_le_bytes(bytes)), 8))
        }
        t if t == TDH_INTYPE_BOOLEAN.0 => {
            let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
            Some((EventFieldValue::Bool(u32::from_le_bytes(bytes) != 0), 4))
        }
        t if t == TDH_INTYPE_GUID.0 => {
            let g = parse_guid(data)?;
            Some((EventFieldValue::Guid(g), 16))
        }
        t if t == TDH_INTYPE_POINTER.0 => {
            if size_hint == 4 {
                let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
                Some((
                    EventFieldValue::Pointer(u32::from_le_bytes(bytes) as u64),
                    4,
                ))
            } else {
                let bytes: [u8; 8] = data.get(0..8)?.try_into().ok()?;
                Some((EventFieldValue::Pointer(u64::from_le_bytes(bytes)), 8))
            }
        }
        t if t == TDH_INTYPE_IPV4_VALUE => {
            let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
            Some((
                EventFieldValue::IpAddr(IpAddr::V4(Ipv4Addr::from(bytes))),
                4,
            ))
        }
        t if t == TDH_INTYPE_IPV6_VALUE => {
            let bytes: [u8; 16] = data.get(0..16)?.try_into().ok()?;
            Some((
                EventFieldValue::IpAddr(IpAddr::V6(Ipv6Addr::from(bytes))),
                16,
            ))
        }
        t if t == TDH_INTYPE_UNICODESTRING.0 => {
            let (s, consumed) = if size_hint >= 2 && size_hint <= data.len() {
                parse_utf16_sized(data, size_hint)?
            } else {
                parse_utf16_cstr(data)?
            };
            Some((EventFieldValue::String(s), consumed))
        }
        t if t == TDH_INTYPE_ANSISTRING.0 => {
            let (s, consumed) = if size_hint > 0 && size_hint <= data.len() {
                parse_ascii_sized(data, size_hint)?
            } else {
                parse_ascii_cstr(data)?
            };
            Some((EventFieldValue::String(s), consumed))
        }
        _ => {
            let take = if size_hint > 0 {
                size_hint.min(data.len())
            } else {
                data.len()
            };
            Some((EventFieldValue::Binary(data[..take].to_vec()), take))
        }
    }
}

fn parse_out_type_override(prop: &PropertyMeta, data: &[u8]) -> Option<(EventFieldValue, usize)> {
    let size_hint = prop.length as usize;
    let out_type = prop.out_type;

    if out_type == TDH_OUTTYPE_HEXINT8.0 {
        let v = *data.first()?;
        return Some((EventFieldValue::String(format!("0x{v:02X}")), 1));
    }

    if out_type == TDH_OUTTYPE_HEXINT16.0 {
        let bytes: [u8; 2] = data.get(0..2)?.try_into().ok()?;
        let v = u16::from_le_bytes(bytes);
        return Some((EventFieldValue::String(format!("0x{v:04X}")), 2));
    }

    if out_type == TDH_OUTTYPE_HEXINT32.0 {
        let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
        let v = u32::from_le_bytes(bytes);
        return Some((EventFieldValue::String(format!("0x{v:08X}")), 4));
    }

    if out_type == TDH_OUTTYPE_HEXINT64.0 {
        let bytes: [u8; 8] = data.get(0..8)?.try_into().ok()?;
        let v = u64::from_le_bytes(bytes);
        return Some((EventFieldValue::String(format!("0x{v:016X}")), 8));
    }

    if out_type == TDH_OUTTYPE_HRESULT.0
        || out_type == TDH_OUTTYPE_NTSTATUS.0
        || out_type == TDH_OUTTYPE_WIN32ERROR.0
    {
        let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
        let v = u32::from_le_bytes(bytes);
        return Some((EventFieldValue::String(format!("0x{v:08X}")), 4));
    }

    if out_type == TDH_OUTTYPE_PORT.0 {
        let bytes: [u8; 2] = data.get(0..2)?.try_into().ok()?;
        return Some((EventFieldValue::U16(u16::from_le_bytes(bytes)), 2));
    }

    if out_type == TDH_OUTTYPE_PID.0 || out_type == TDH_OUTTYPE_TID.0 {
        let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
        return Some((EventFieldValue::U32(u32::from_le_bytes(bytes)), 4));
    }

    if out_type == TDH_OUTTYPE_IPV4.0 {
        let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
        return Some((
            EventFieldValue::IpAddr(IpAddr::V4(Ipv4Addr::from(bytes))),
            4,
        ));
    }

    if out_type == TDH_OUTTYPE_IPV6.0 {
        let bytes: [u8; 16] = data.get(0..16)?.try_into().ok()?;
        return Some((
            EventFieldValue::IpAddr(IpAddr::V6(Ipv6Addr::from(bytes))),
            16,
        ));
    }

    if out_type == TDH_OUTTYPE_SOCKETADDRESS.0 {
        return parse_socket_address(data);
    }

    if out_type == TDH_OUTTYPE_BOOLEAN.0 {
        let consumed = if size_hint >= 4 && size_hint <= data.len() {
            4
        } else {
            1
        };
        let value = if consumed == 4 {
            let bytes: [u8; 4] = data.get(0..4)?.try_into().ok()?;
            u32::from_le_bytes(bytes) != 0
        } else {
            *data.first()? != 0
        };
        return Some((EventFieldValue::Bool(value), consumed));
    }

    if (out_type == TDH_OUTTYPE_UTF8.0
        || out_type == TDH_OUTTYPE_STRING.0
        || out_type == TDH_OUTTYPE_JSON.0
        || out_type == TDH_OUTTYPE_XML.0
        || out_type == TDH_OUTTYPE_REDUCEDSTRING.0)
        && size_hint > 0
        && size_hint <= data.len()
    {
        let (s, consumed) = parse_utf8_sized(data, size_hint)?;
        return Some((EventFieldValue::String(s), consumed));
    }

    None
}

fn parse_socket_address(data: &[u8]) -> Option<(EventFieldValue, usize)> {
    if data.len() < 8 {
        return None;
    }

    let family = u16::from_le_bytes([data[0], data[1]]);
    match family {
        2 => {
            let bytes: [u8; 4] = data.get(4..8)?.try_into().ok()?;
            Some((
                EventFieldValue::IpAddr(IpAddr::V4(Ipv4Addr::from(bytes))),
                8,
            ))
        }
        23 => {
            let bytes: [u8; 16] = data.get(8..24)?.try_into().ok()?;
            Some((
                EventFieldValue::IpAddr(IpAddr::V6(Ipv6Addr::from(bytes))),
                24,
            ))
        }
        _ => None,
    }
}

fn parse_utf16_sized(data: &[u8], byte_len: usize) -> Option<(String, usize)> {
    if byte_len == 0 || byte_len > data.len() || !byte_len.is_multiple_of(2) {
        return None;
    }

    let mut units = Vec::with_capacity(byte_len / 2);
    let mut idx = 0usize;
    while idx + 1 < byte_len {
        let unit = u16::from_le_bytes([data[idx], data[idx + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        idx += 2;
    }

    Some((String::from_utf16_lossy(&units), byte_len))
}

fn parse_ascii_sized(data: &[u8], byte_len: usize) -> Option<(String, usize)> {
    if byte_len == 0 || byte_len > data.len() {
        return None;
    }

    let raw = &data[..byte_len];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let text = String::from_utf8(raw[..end].to_vec()).ok()?;
    Some((text, byte_len))
}

fn parse_utf8_sized(data: &[u8], byte_len: usize) -> Option<(String, usize)> {
    if byte_len == 0 || byte_len > data.len() {
        return None;
    }

    let raw = &data[..byte_len];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let text = String::from_utf8(raw[..end].to_vec()).ok()?;
    Some((text, byte_len))
}

fn parse_guid(data: &[u8]) -> Option<GUID> {
    let d1 = u32::from_le_bytes(data.get(0..4)?.try_into().ok()?);
    let d2 = u16::from_le_bytes(data.get(4..6)?.try_into().ok()?);
    let d3 = u16::from_le_bytes(data.get(6..8)?.try_into().ok()?);
    let d4: [u8; 8] = data.get(8..16)?.try_into().ok()?;
    Some(GUID::from_values(d1, d2, d3, d4))
}

fn read_utf16_cstr_at(buffer: &[u8], offset: usize) -> Option<String> {
    if offset >= buffer.len() {
        return None;
    }
    parse_utf16_cstr(&buffer[offset..]).map(|(s, _)| s)
}

fn parse_utf16_cstr(data: &[u8]) -> Option<(String, usize)> {
    if data.len() < 2 {
        return None;
    }

    let mut consumed = 0usize;
    let mut units = Vec::new();

    while consumed + 1 < data.len() {
        let unit = u16::from_le_bytes([data[consumed], data[consumed + 1]]);
        consumed += 2;
        if unit == 0 {
            break;
        }
        units.push(unit);
    }

    Some((String::from_utf16_lossy(&units), consumed))
}

fn parse_ascii_cstr(data: &[u8]) -> Option<(String, usize)> {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let text = String::from_utf8(data[..end].to_vec()).ok()?;
    let consumed = if end < data.len() { end + 1 } else { end };
    Some((text, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_value() {
        let prop = PropertyMeta {
            name: "SourceIp".to_string(),
            in_type: TDH_INTYPE_IPV4_VALUE,
            out_type: 0,
            length: 4,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [192, 168, 1, 10];
        let (value, consumed) = parse_one_value(&prop, &data).expect("expected ipv4 value");

        assert_eq!(consumed, 4);
        match value {
            EventFieldValue::IpAddr(ip) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
            }
            _ => panic!("expected EventFieldValue::IpAddr for IPv4"),
        }
    }

    #[test]
    fn parse_ipv6_value() {
        let prop = PropertyMeta {
            name: "DestinationIp".to_string(),
            in_type: TDH_INTYPE_IPV6_VALUE,
            out_type: 0,
            length: 16,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let (value, consumed) = parse_one_value(&prop, &data).expect("expected ipv6 value");

        assert_eq!(consumed, 16);
        match value {
            EventFieldValue::IpAddr(ip) => {
                assert_eq!(
                    ip,
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
                );
            }
            _ => panic!("expected EventFieldValue::IpAddr for IPv6"),
        }
    }

    #[test]
    fn parse_unicode_string_with_fixed_length_no_null() {
        let prop = PropertyMeta {
            name: "Image".to_string(),
            in_type: TDH_INTYPE_UNICODESTRING.0,
            out_type: 0,
            length: 8,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [b'T', 0, b'e', 0, b's', 0, b't', 0];
        let (value, consumed) = parse_one_value(&prop, &data).expect("expected unicode string");

        assert_eq!(consumed, 8);
        match value {
            EventFieldValue::String(s) => assert_eq!(s, "Test"),
            _ => panic!("expected EventFieldValue::String"),
        }
    }

    #[test]
    fn parse_ansi_string_with_fixed_length_no_null() {
        let prop = PropertyMeta {
            name: "Name".to_string(),
            in_type: TDH_INTYPE_ANSISTRING.0,
            out_type: 0,
            length: 4,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = *b"PING";
        let (value, consumed) = parse_one_value(&prop, &data).expect("expected ansi string");

        assert_eq!(consumed, 4);
        match value {
            EventFieldValue::String(s) => assert_eq!(s, "PING"),
            _ => panic!("expected EventFieldValue::String"),
        }
    }

    #[test]
    fn parse_uint8_array_as_binary_blob() {
        let prop = PropertyMeta {
            name: "ByteArray".to_string(),
            in_type: TDH_INTYPE_UINT8.0,
            out_type: 0,
            length: 6,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [1u8, 2, 3, 4, 5, 6, 99, 100];
        let (value, consumed) = parse_one_value(&prop, &data).expect("expected binary blob");

        assert_eq!(consumed, 6);
        match value {
            EventFieldValue::Binary(bytes) => assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6]),
            _ => panic!("expected EventFieldValue::Binary"),
        }
    }

    #[test]
    fn parse_pointer_uses_declared_32bit_length() {
        let prop = PropertyMeta {
            name: "Ptr".to_string(),
            in_type: TDH_INTYPE_POINTER.0,
            out_type: 0,
            length: 4,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [0x78u8, 0x56, 0x34, 0x12, 0xaa, 0xbb, 0xcc, 0xdd];
        let (value, consumed) = parse_one_value(&prop, &data).expect("expected pointer value");

        assert_eq!(consumed, 4);
        match value {
            EventFieldValue::Pointer(ptr) => assert_eq!(ptr, 0x1234_5678),
            _ => panic!("expected EventFieldValue::Pointer"),
        }
    }

    #[test]
    fn parse_outtype_ipv4_from_scalar_bytes() {
        let prop = PropertyMeta {
            name: "RemoteAddress".to_string(),
            in_type: TDH_INTYPE_UINT32.0,
            out_type: TDH_OUTTYPE_IPV4.0,
            length: 4,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [8u8, 8, 4, 4, 1, 2, 3, 4];
        let (value, consumed) =
            parse_one_value(&prop, &data).expect("expected ipv4 out-type parse");

        assert_eq!(consumed, 4);
        match value {
            EventFieldValue::IpAddr(ip) => assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            _ => panic!("expected EventFieldValue::IpAddr"),
        }
    }

    #[test]
    fn parse_outtype_utf8_with_fixed_length() {
        let prop = PropertyMeta {
            name: "Payload".to_string(),
            in_type: TDH_INTYPE_UINT8.0,
            out_type: TDH_OUTTYPE_UTF8.0,
            length: 5,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [b'H', b'e', b'l', b'l', b'o', 0, b'!'];
        let (value, consumed) =
            parse_one_value(&prop, &data).expect("expected utf8 out-type parse");

        assert_eq!(consumed, 5);
        match value {
            EventFieldValue::String(s) => assert_eq!(s, "Hello"),
            _ => panic!("expected EventFieldValue::String"),
        }
    }

    #[test]
    fn parse_outtype_socketaddress_ipv4() {
        let prop = PropertyMeta {
            name: "SockAddr".to_string(),
            in_type: TDH_INTYPE_UINT8.0,
            out_type: TDH_OUTTYPE_SOCKETADDRESS.0,
            length: 16,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [
            2u8, 0, // AF_INET
            0, 0, // port
            127, 0, 0, 1, // addr
            0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let (value, consumed) = parse_one_value(&prop, &data).expect("expected sockaddr parse");
        assert_eq!(consumed, 8);
        match value {
            EventFieldValue::IpAddr(ip) => assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            _ => panic!("expected EventFieldValue::IpAddr"),
        }
    }

    #[test]
    fn parse_values_uses_count_property_index_for_arrays() {
        let schema = CachedSchema {
            props: vec![
                PropertyMeta {
                    name: "Count".to_string(),
                    in_type: TDH_INTYPE_UINT8.0,
                    out_type: 0,
                    length: 1,
                    count: 1,
                    count_property_index: None,
                    length_property_index: None,
                    map_name: None,
                },
                PropertyMeta {
                    name: "Values".to_string(),
                    in_type: TDH_INTYPE_UINT32.0,
                    out_type: 0,
                    length: 0,
                    count: 1,
                    count_property_index: Some(0),
                    length_property_index: None,
                    map_name: None,
                },
                PropertyMeta {
                    name: "Tail".to_string(),
                    in_type: TDH_INTYPE_UINT8.0,
                    out_type: 0,
                    length: 1,
                    count: 1,
                    count_property_index: None,
                    length_property_index: None,
                    map_name: None,
                },
            ],
        };

        let data = [
            2u8, // Count
            0x11, 0x00, 0x00, 0x00, // Values[0]
            0x22, 0x00, 0x00, 0x00, // Values[1]
            9u8,  // Tail
        ];

        let fields = parse_values(&schema, &data);
        assert_eq!(fields.len(), 3);
        match &fields[1].value {
            EventFieldValue::Binary(bytes) => {
                assert_eq!(bytes, &vec![0x11, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00]);
            }
            _ => panic!("expected Values to be parsed as binary array payload"),
        }
        match &fields[2].value {
            EventFieldValue::U8(v) => assert_eq!(*v, 9),
            _ => panic!("expected Tail to remain aligned and parsed as u8"),
        }
    }

    #[test]
    fn parse_values_uses_length_property_index_for_sized_string() {
        let schema = CachedSchema {
            props: vec![
                PropertyMeta {
                    name: "Len".to_string(),
                    in_type: TDH_INTYPE_UINT8.0,
                    out_type: 0,
                    length: 1,
                    count: 1,
                    count_property_index: None,
                    length_property_index: None,
                    map_name: None,
                },
                PropertyMeta {
                    name: "Name".to_string(),
                    in_type: TDH_INTYPE_ANSISTRING.0,
                    out_type: TDH_OUTTYPE_UTF8.0,
                    length: 0,
                    count: 1,
                    count_property_index: None,
                    length_property_index: Some(0),
                    map_name: None,
                },
                PropertyMeta {
                    name: "Tail".to_string(),
                    in_type: TDH_INTYPE_UINT8.0,
                    out_type: 0,
                    length: 1,
                    count: 1,
                    count_property_index: None,
                    length_property_index: None,
                    map_name: None,
                },
            ],
        };

        let data = [4u8, b'T', b'e', b's', b't', 7u8];
        let fields = parse_values(&schema, &data);

        assert_eq!(fields.len(), 3);
        match &fields[1].value {
            EventFieldValue::String(v) => assert_eq!(v, "Test"),
            _ => panic!("expected Name as UTF-8 string with dynamic length"),
        }
        match &fields[2].value {
            EventFieldValue::U8(v) => assert_eq!(*v, 7),
            _ => panic!("expected Tail to remain aligned and parsed as u8"),
        }
    }

    #[test]
    fn map_definition_renders_value_map_exact_match() {
        let map = MapDefinition {
            kind: MapKind::Value,
            entries: vec![
                MapEntry {
                    key: MapKey::Numeric(1),
                    label: "One".to_string(),
                },
                MapEntry {
                    key: MapKey::Numeric(2),
                    label: "Two".to_string(),
                },
            ],
        };

        assert_eq!(map.render_numeric(2).as_deref(), Some("Two"));
        assert!(map.render_numeric(3).is_none());
    }

    #[test]
    fn map_definition_renders_bitmap_as_joined_labels() {
        let map = MapDefinition {
            kind: MapKind::Bitmap,
            entries: vec![
                MapEntry {
                    key: MapKey::Numeric(0x1),
                    label: "Read".to_string(),
                },
                MapEntry {
                    key: MapKey::Numeric(0x2),
                    label: "Write".to_string(),
                },
                MapEntry {
                    key: MapKey::Numeric(0x4),
                    label: "Execute".to_string(),
                },
            ],
        };

        assert_eq!(map.render_numeric(0x3).as_deref(), Some("Read|Write"));
    }

    #[test]
    fn map_definition_renders_string_key_maps_case_insensitively() {
        let map = MapDefinition {
            kind: MapKind::Value,
            entries: vec![MapEntry {
                key: MapKey::Text("start".to_string()),
                label: "StartLabel".to_string(),
            }],
        };

        assert_eq!(map.render_text("START").as_deref(), Some("StartLabel"));
    }

    #[test]
    fn parse_outtype_hresult_formats_hex_string() {
        let prop = PropertyMeta {
            name: "Result".to_string(),
            in_type: TDH_INTYPE_UINT32.0,
            out_type: TDH_OUTTYPE_HRESULT.0,
            length: 4,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [0x57u8, 0x00, 0x07, 0x80];
        let (value, consumed) = parse_one_value(&prop, &data).expect("expected HRESULT parse");

        assert_eq!(consumed, 4);
        match value {
            EventFieldValue::String(s) => assert_eq!(s, "0x80070057"),
            _ => panic!("expected EventFieldValue::String"),
        }
    }

    #[test]
    fn parse_outtype_hexint16_formats_hex_string() {
        let prop = PropertyMeta {
            name: "Flags".to_string(),
            in_type: TDH_INTYPE_UINT16.0,
            out_type: TDH_OUTTYPE_HEXINT16.0,
            length: 2,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [0x34u8, 0x12];
        let (value, consumed) = parse_one_value(&prop, &data).expect("expected hexint16 parse");

        assert_eq!(consumed, 2);
        match value {
            EventFieldValue::String(s) => assert_eq!(s, "0x1234"),
            _ => panic!("expected EventFieldValue::String"),
        }
    }

    #[test]
    fn parse_outtype_port_returns_u16() {
        let prop = PropertyMeta {
            name: "Port".to_string(),
            in_type: TDH_INTYPE_UINT16.0,
            out_type: TDH_OUTTYPE_PORT.0,
            length: 2,
            count: 1,
            count_property_index: None,
            length_property_index: None,
            map_name: None,
        };

        let data = [0xBBu8, 0x01];
        let (value, consumed) = parse_one_value(&prop, &data).expect("expected port parse");

        assert_eq!(consumed, 2);
        match value {
            EventFieldValue::U16(v) => assert_eq!(v, 443),
            _ => panic!("expected EventFieldValue::U16"),
        }
    }
}
