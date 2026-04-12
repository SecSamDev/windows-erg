use super::events::{
    DecodedEvent, EventField, EventFieldValue, FileIoEvent, FileIoOperation, RegistryEvent,
    RegistryOperation, TcpEvent, TcpOperation,
};
use crate::types::ProcessId;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::System::Diagnostics::Etw::{FileIoGuid, RegistryGuid, TcpIpGuid};
use windows::core::GUID;

/// Decode field-based events for providers handled through schema parsing.
///
/// This path maps TCP/IP, Registry, and File I/O kernel provider payloads from
/// parsed field sets into typed decoded events.
pub(crate) fn decode_from_generic(
    provider_guid: GUID,
    opcode: u8,
    fields: &[EventField],
) -> Option<DecodedEvent> {
    if provider_guid == TcpIpGuid {
        return Some(DecodedEvent::Tcp(map_tcp(opcode, fields)));
    }

    if provider_guid == RegistryGuid {
        return Some(DecodedEvent::Registry(map_registry(opcode, fields)));
    }

    if provider_guid == FileIoGuid {
        return Some(DecodedEvent::FileIo(map_file(opcode, fields)));
    }

    None
}

fn map_tcp(opcode: u8, fields: &[EventField]) -> TcpEvent {
    let source_ip = field_ip(
        fields,
        &[
            "saddr",
            "saddrv4",
            "saddrv6",
            "SourceIp",
            "SourceAddress",
            "LocalAddress",
            "srcaddr",
            "srcip",
        ],
    )
    .or_else(|| field_ip_by_pattern(fields, true));

    let destination_ip = field_ip(
        fields,
        &[
            "daddr",
            "daddrv4",
            "daddrv6",
            "DestinationIp",
            "DestinationAddress",
            "RemoteAddress",
            "dstaddr",
            "dstip",
        ],
    )
    .or_else(|| field_ip_by_pattern(fields, false));

    TcpEvent {
        operation: match opcode {
            10 | 26 => TcpOperation::Send,
            11 | 27 => TcpOperation::Receive,
            12 | 28 => TcpOperation::Connect,
            13 | 29 => TcpOperation::Disconnect,
            14 | 30 => TcpOperation::Retransmit,
            15 | 31 => TcpOperation::Accept,
            16 | 32 => TcpOperation::Reconnect,
            18 | 34 => TcpOperation::Copy,
            _ => TcpOperation::Unknown,
        },
        process_id: field_process_id(fields, &["PID", "ProcessId"]),
        source_ip,
        source_port: field_u16(fields, &["sport", "SourcePort"]),
        destination_ip,
        destination_port: field_u16(fields, &["dport", "DestinationPort"]),
        size: field_u32(fields, &["size"]),
        sequence_number: field_u32(fields, &["seqnum"]),
    }
}

fn map_registry(opcode: u8, fields: &[EventField]) -> RegistryEvent {
    RegistryEvent {
        operation: match opcode {
            10 => RegistryOperation::Create,
            11 | 27 => RegistryOperation::Open,
            12 | 23 => RegistryOperation::DeleteKey,
            13 => RegistryOperation::QueryKey,
            14 => RegistryOperation::SetValue,
            15 => RegistryOperation::DeleteValue,
            16 | 19 => RegistryOperation::QueryValue,
            17 | 24 | 25 => RegistryOperation::EnumerateKey,
            18 => RegistryOperation::EnumerateValue,
            20 => RegistryOperation::SetInformation,
            _ => RegistryOperation::Unknown,
        },
        process_id: field_process_id(fields, &["PID", "ProcessId"]),
        key_name: field_string(fields, &["KeyName", "registry_key_name"]),
        relative_name: field_string(fields, &["RelativeName", "registry_relative_name"]),
        value_name: field_string(fields, &["ValueName", "registry_value_name"]),
        status: field_u32(fields, &["Status", "status"]),
        key_handle: field_u64(fields, &["KeyHandle", "registry_key_handle"]),
    }
}

fn map_file(opcode: u8, fields: &[EventField]) -> FileIoEvent {
    FileIoEvent {
        operation: match opcode {
            0 => FileIoOperation::Name,
            32 | 64 => FileIoOperation::Create,
            36 => FileIoOperation::Rundown,
            65 => FileIoOperation::Cleanup,
            66 => FileIoOperation::Close,
            69 => FileIoOperation::SetInformation,
            72 => FileIoOperation::DirectoryEnumeration,
            73 => FileIoOperation::Flush,
            74 => FileIoOperation::QueryInformation,
            75 => FileIoOperation::FileSystemControl,
            76 => FileIoOperation::OperationEnd,
            77 => FileIoOperation::DirectoryNotification,
            67 => FileIoOperation::Read,
            68 => FileIoOperation::Write,
            35 | 70 => FileIoOperation::Delete,
            71 => FileIoOperation::Rename,
            _ => FileIoOperation::Unknown,
        },
        process_id: field_process_id(fields, &["PID", "ProcessId"]),
        file_object: field_u64(fields, &["FileObject"]),
        irp_ptr: field_u64(fields, &["IrpPtr"]),
        file_key: field_u64(fields, &["FileKey"]),
        open_path: field_string(fields, &["OpenPath", "file.path"]),
        create_options: field_u32(fields, &["CreateOptions"]),
        file_attributes: field_u32(fields, &["FileAttributes"]),
        share_access: field_u32(fields, &["ShareAccess"]),
    }
}

fn field_by_name<'a>(fields: &'a [EventField], names: &[&str]) -> Option<&'a EventFieldValue> {
    for name in names {
        if let Some(f) = fields.iter().find(|f| f.name.eq_ignore_ascii_case(name)) {
            return Some(&f.value);
        }
    }
    None
}

fn field_string(fields: &[EventField], names: &[&str]) -> Option<String> {
    match field_by_name(fields, names)? {
        EventFieldValue::String(v) => Some(v.clone()),
        _ => None,
    }
}

fn field_ip(fields: &[EventField], names: &[&str]) -> Option<IpAddr> {
    match field_by_name(fields, names)? {
        value => parse_ip_value(value),
    }
}

fn field_ip_by_pattern(fields: &[EventField], source: bool) -> Option<IpAddr> {
    for f in fields {
        let lower = f.name.to_ascii_lowercase();
        if !(lower.contains("ip") || lower.contains("addr") || lower.contains("address")) {
            continue;
        }

        let is_source = lower.contains("src") || lower.starts_with('s') || lower.contains("local");
        let is_destination =
            lower.contains("dst") || lower.starts_with('d') || lower.contains("remote");

        if ((source && is_source) || (!source && is_destination))
            && let Some(ip) = parse_ip_value(&f.value)
        {
            return Some(ip);
        }
    }
    None
}

fn parse_ip_value(value: &EventFieldValue) -> Option<IpAddr> {
    match value {
        EventFieldValue::IpAddr(v) => Some(*v),
        EventFieldValue::String(v) => v.parse().ok(),
        // Some TDH schemas expose IPv4 as UInt32; value was decoded from LE bytes.
        EventFieldValue::U32(v) => Some(IpAddr::V4(Ipv4Addr::from(v.to_le_bytes()))),
        EventFieldValue::U64(v) => {
            let bytes = v.to_le_bytes();
            Some(IpAddr::V4(Ipv4Addr::from([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ])))
        }
        // Other schemas expose addresses as fixed-size binary blobs.
        EventFieldValue::Binary(v) if v.len() == 4 => {
            Some(IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3])))
        }
        EventFieldValue::Binary(v) if v.len() == 16 => {
            let bytes: [u8; 16] = v.as_slice().try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

fn field_u16(fields: &[EventField], names: &[&str]) -> Option<u16> {
    match field_by_name(fields, names)? {
        EventFieldValue::U16(v) => Some(*v),
        EventFieldValue::U32(v) => u16::try_from(*v).ok(),
        EventFieldValue::U64(v) => u16::try_from(*v).ok(),
        _ => None,
    }
}

fn field_u32(fields: &[EventField], names: &[&str]) -> Option<u32> {
    match field_by_name(fields, names)? {
        EventFieldValue::U8(v) => Some(*v as u32),
        EventFieldValue::U16(v) => Some(*v as u32),
        EventFieldValue::U32(v) => Some(*v),
        EventFieldValue::U64(v) => u32::try_from(*v).ok(),
        EventFieldValue::I32(v) => u32::try_from(*v).ok(),
        EventFieldValue::I64(v) => u32::try_from(*v).ok(),
        _ => None,
    }
}

fn field_u64(fields: &[EventField], names: &[&str]) -> Option<u64> {
    match field_by_name(fields, names)? {
        EventFieldValue::U8(v) => Some(*v as u64),
        EventFieldValue::U16(v) => Some(*v as u64),
        EventFieldValue::U32(v) => Some(*v as u64),
        EventFieldValue::U64(v) => Some(*v),
        EventFieldValue::Pointer(v) => Some(*v),
        EventFieldValue::I32(v) => u64::try_from(*v).ok(),
        EventFieldValue::I64(v) => u64::try_from(*v).ok(),
        _ => None,
    }
}

fn field_process_id(fields: &[EventField], names: &[&str]) -> Option<ProcessId> {
    field_u32(fields, names).map(ProcessId::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(name: &str, value: &str) -> EventField {
        EventField {
            name: name.to_string(),
            value: EventFieldValue::String(value.to_string()),
        }
    }

    fn u16f(name: &str, value: u16) -> EventField {
        EventField {
            name: name.to_string(),
            value: EventFieldValue::U16(value),
        }
    }

    fn u32f(name: &str, value: u32) -> EventField {
        EventField {
            name: name.to_string(),
            value: EventFieldValue::U32(value),
        }
    }

    fn u64f(name: &str, value: u64) -> EventField {
        EventField {
            name: name.to_string(),
            value: EventFieldValue::U64(value),
        }
    }

    #[test]
    fn map_tcp_v2_alias_opcode_send() {
        let fields = vec![
            u32f("PID", 100),
            EventField {
                name: "saddr".to_string(),
                value: EventFieldValue::IpAddr("10.0.0.5".parse().unwrap()),
            },
            u16f("sport", 5555),
            EventField {
                name: "daddr".to_string(),
                value: EventFieldValue::IpAddr("8.8.8.8".parse().unwrap()),
            },
            u16f("dport", 53),
        ];

        let event = map_tcp(26, &fields);
        assert_eq!(event.operation, TcpOperation::Send);
        assert_eq!(event.process_id, Some(ProcessId::new(100)));
        assert_eq!(event.destination_port, Some(53));
        assert_eq!(event.destination_ip, Some("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn map_tcp_accepts_binary_and_u32_ip_fields() {
        let fields = vec![
            u32f("PID", 123),
            EventField {
                name: "SourceAddress".to_string(),
                value: EventFieldValue::Binary(vec![192, 168, 1, 99]),
            },
            EventField {
                name: "DestinationAddress".to_string(),
                value: EventFieldValue::U32(u32::from_le_bytes([8, 8, 8, 8])),
            },
        ];

        let event = map_tcp(26, &fields);
        assert_eq!(event.operation, TcpOperation::Send);
        assert_eq!(event.process_id, Some(ProcessId::new(123)));
        assert_eq!(event.source_ip, Some("192.168.1.99".parse().unwrap()));
        assert_eq!(event.destination_ip, Some("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn map_tcp_accepts_ipv6_binary_ip_fields() {
        let fields = vec![
            EventField {
                name: "saddrv6".to_string(),
                value: EventFieldValue::Binary(vec![
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
            },
            EventField {
                name: "daddrv6".to_string(),
                value: EventFieldValue::Binary(vec![
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ]),
            },
        ];

        let event = map_tcp(27, &fields);
        assert_eq!(event.operation, TcpOperation::Receive);
        assert_eq!(event.source_ip, Some("2001:db8::1".parse().unwrap()));
        assert_eq!(event.destination_ip, Some("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn map_registry_alias_and_case_insensitive_names() {
        let fields = vec![
            u32f("processid", 200),
            s("keyname", "\\Registry\\Machine\\Software"),
            s("VALUENAME", "Run"),
            u32f("status", 0),
        ];

        let event = map_registry(27, &fields);
        assert_eq!(event.operation, RegistryOperation::Open);
        assert_eq!(event.process_id, Some(ProcessId::new(200)));
        assert_eq!(event.value_name.as_deref(), Some("Run"));
    }

    #[test]
    fn map_file_alias_delete_and_pointer_values() {
        let fields = vec![
            u32f("ProcessId", 300),
            u64f("FileObject", 0x1111),
            EventField {
                name: "IrpPtr".to_string(),
                value: EventFieldValue::Pointer(0x2222),
            },
            s("OpenPath", "C:\\Temp\\x.bin"),
        ];

        let event = map_file(70, &fields);
        assert_eq!(event.operation, FileIoOperation::Delete);
        assert_eq!(event.process_id, Some(ProcessId::new(300)));
        assert_eq!(event.file_object, Some(0x1111));
        assert_eq!(event.irp_ptr, Some(0x2222));
    }

    #[test]
    fn map_file_operation_end_opcode() {
        let event = map_file(76, &[]);
        assert_eq!(event.operation, FileIoOperation::OperationEnd);
    }
}
