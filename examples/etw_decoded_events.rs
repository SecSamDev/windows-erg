//! ETW decoded events example.
//!
//! Demonstrates:
//! - direct in-place decoding for Process/Image events
//! - TDH-backed detailed parsing for Network/Registry/FileIo
//! - matching on typed `DecodedEvent` variants
//!
//! Run as Administrator:
//! `cargo run --example etw_decoded_events`

use windows_erg::etw::{
    DecodedEvent, EventTrace, FileIoOperation, RegistryOperation, SystemProvider, TcpOperation,
};

fn main() -> windows_erg::Result<()> {
    println!("Starting ETW decoded events monitor...");
    println!("Press Ctrl+C to stop\n");

    let mut trace = EventTrace::builder("DecodedEventsMonitor")
        .system_provider(SystemProvider::Process)
        .system_provider(SystemProvider::ImageLoad)
        .system_provider(SystemProvider::Network)
        .system_provider(SystemProvider::Registry)
        .system_provider(SystemProvider::FileIo)
        .with_decoded_stream()
        .with_detailed_events()
        .buffer_size(256)
        .min_buffers(8)
        .max_buffers(40)
        .channel_capacity(25_000)
        .start()?;

    let mut batch = Vec::with_capacity(256);
    let mut processed = 0usize;

    loop {
        let count = trace.next_batch_decoded(&mut batch)?;
        if count == 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        }

        for event in &batch {
            processed += 1;

            // Print only every N events to keep output readable.
            if !processed.is_multiple_of(100) {
                continue;
            }

            match event {
                DecodedEvent::ProcessStart(p) => {
                    println!(
                        "[{}] ProcessStart pid={} parent={} image={}",
                        processed, p.process_id, p.parent_process_id, p.image_file_name
                    );
                }
                DecodedEvent::ProcessEnd(p) => {
                    println!(
                        "[{}] ProcessEnd pid={} parent={} image={} exit_status={:?}",
                        processed,
                        p.process_id,
                        p.parent_process_id,
                        p.image_file_name,
                        p.exit_status
                    );
                }
                DecodedEvent::ImageLoad(i) => {
                    println!(
                        "[{}] ImageLoad pid={} path={} size={}",
                        processed, i.process_id, i.file_name, i.image_size
                    );
                }
                DecodedEvent::ImageUnload(i) => {
                    println!(
                        "[{}] ImageUnload pid={} path={} size={}",
                        processed, i.process_id, i.file_name, i.image_size
                    );
                }
                DecodedEvent::Tcp(t) => {
                    let op = match t.operation {
                        TcpOperation::Send => "Send",
                        TcpOperation::Receive => "Receive",
                        TcpOperation::Connect => "Connect",
                        TcpOperation::Disconnect => "Disconnect",
                        TcpOperation::Retransmit => "Retransmit",
                        TcpOperation::Accept => "Accept",
                        TcpOperation::Reconnect => "Reconnect",
                        TcpOperation::Copy => "Copy",
                        TcpOperation::Unknown => "Unknown",
                    };
                    println!(
                        "[{}] Tcp{} pid={:?} {}:{} -> {}:{} size={:?}",
                        processed,
                        op,
                        t.process_id,
                        t.source_ip
                            .as_ref()
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "?".to_string()),
                        t.source_port.unwrap_or_default(),
                        t.destination_ip
                            .as_ref()
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "?".to_string()),
                        t.destination_port.unwrap_or_default(),
                        t.size
                    );
                }
                DecodedEvent::Registry(r) => {
                    let op = match r.operation {
                        RegistryOperation::Create => "Create",
                        RegistryOperation::Open => "Open",
                        RegistryOperation::DeleteKey => "DeleteKey",
                        RegistryOperation::QueryKey => "QueryKey",
                        RegistryOperation::SetValue => "SetValue",
                        RegistryOperation::DeleteValue => "DeleteValue",
                        RegistryOperation::QueryValue => "QueryValue",
                        RegistryOperation::EnumerateKey => "EnumerateKey",
                        RegistryOperation::EnumerateValue => "EnumerateValue",
                        RegistryOperation::SetInformation => "SetInformation",
                        RegistryOperation::Unknown => "Unknown",
                    };
                    println!(
                        "[{}] Registry{} pid={:?} key={:?} value={:?} status={:?}",
                        processed, op, r.process_id, r.key_name, r.value_name, r.status
                    );
                }
                DecodedEvent::FileIo(f) => {
                    let op = match f.operation {
                        FileIoOperation::Name => "Name",
                        FileIoOperation::Create => "Create",
                        FileIoOperation::Rundown => "Rundown",
                        FileIoOperation::Cleanup => "Cleanup",
                        FileIoOperation::Close => "Close",
                        FileIoOperation::SetInformation => "SetInformation",
                        FileIoOperation::DirectoryEnumeration => "DirectoryEnumeration",
                        FileIoOperation::Flush => "Flush",
                        FileIoOperation::QueryInformation => "QueryInformation",
                        FileIoOperation::FileSystemControl => "FileSystemControl",
                        FileIoOperation::OperationEnd => "OperationEnd",
                        FileIoOperation::DirectoryNotification => "DirectoryNotification",
                        FileIoOperation::Read => "Read",
                        FileIoOperation::Write => "Write",
                        FileIoOperation::Delete => "Delete",
                        FileIoOperation::Rename => "Rename",
                        FileIoOperation::Unknown => "Unknown",
                    };
                    println!(
                        "[{}] File{} pid={:?} path={:?} irp={:?}",
                        processed, op, f.process_id, f.open_path, f.irp_ptr
                    );
                }
                DecodedEvent::Generic(fields) => {
                    println!("[{}] Generic fields={}", processed, fields.len());
                }
                DecodedEvent::Unknown => {
                    println!("[{}] Unknown event", processed);
                }
            }
        }
    }
}
