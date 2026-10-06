//! TCP/IP probe: which kernel TcpIp events does a loopback connect/accept
//! and an outbound connect produce, with which fields, and how many events
//! of each opcode does normal traffic generate?
//!
//! Starts a private system-logger session with `SystemProvider::Network`,
//! opens a loopback listener on a known port, connects to it, accepts,
//! exchanges a few bytes, then connects out to 1.1.1.1:443. Prints every
//! TcpIp event whose decoded or header PID is this process, with its fields
//! and whether the decoded ports equal the known ports as-is or byte-swapped
//! (which settles `TDH_OUTTYPE_PORT`'s byte order). Then it keeps counting
//! every TcpIp opcode system-wide for `--secs N` (default 30) of whatever
//! the machine is doing, to show how much of the volume is Send/Receive.
//!
//! Run as Administrator:
//! `cargo run --example etw_tcpip_probe` or
//! `cargo run --example etw_tcpip_probe -- --secs 120`

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use windows::core::GUID;
use windows_erg::etw::{DecodedEvent, EventFieldValue, EventTrace, SystemProvider, TraceEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !windows_erg::is_elevated()? {
        eprintln!("run this from an elevated terminal");
        std::process::exit(1);
    }
    let secs: u64 = std::env::args()
        .skip_while(|a| a != "--secs")
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let own_pid = std::process::id();

    let mut trace = EventTrace::builder(format!("TcpIpProbe-{own_pid}"))
        .system_provider(SystemProvider::Network)
        .with_detailed_events()
        .private_system_logger(GUID::from_u128(
            0x7b2e_1f6f_8d2c_4d4f_ae6b_0000_0000_0000 ^ u128::from(own_pid),
        ))
        .buffer_size(128)
        .flush_interval(1)
        .channel_capacity(262_144)
        .start()?;
    std::thread::sleep(Duration::from_millis(500));

    // Loopback: connect, accept, one round trip.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let server_port = listener.local_addr()?.port();
    let mut client = TcpStream::connect(("127.0.0.1", server_port))?;
    let client_port = client.local_addr()?.port();
    let (mut accepted, _) = listener.accept()?;
    client.write_all(b"ping")?;
    let mut buf = [0u8; 4];
    accepted.read_exact(&mut buf)?;
    accepted.write_all(b"pong")?;
    client.read_exact(&mut buf)?;
    drop((client, accepted));
    println!("loopback: server port {server_port}, client port {client_port}");

    // Outbound, best effort.
    let outbound = "1.1.1.1:443"
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok())
        .and_then(|s| s.local_addr().ok().map(|a| a.port()));
    println!("outbound to 1.1.1.1:443: client port {outbound:?}");

    let known = [Some(server_port), Some(client_port), Some(443), outbound];
    let mut counts: BTreeMap<u8, u64> = BTreeMap::new();
    let mut total = 0u64;
    let mut own = 0usize;
    let mut batch: Vec<TraceEvent> = Vec::with_capacity(4096);
    let deadline = Instant::now() + Duration::from_secs(secs);
    println!("counting all TcpIp events for {secs} s...");
    while Instant::now() < deadline {
        trace.next_batch_timeout(&mut batch, Duration::from_millis(200))?;
        for event in &batch {
            total += 1;
            *counts.entry(event.opcode).or_default() += 1;
            let DecodedEvent::Tcp(tcp) = event.decode() else {
                continue;
            };
            let decoded_pid = tcp.process_id.map(|p| p.as_u32());
            if decoded_pid != Some(own_pid) && event.process_id.as_u32() != own_pid {
                continue;
            }
            own += 1;
            println!(
                "opcode={:3} op={:?} header_pid={} decoded_pid={:?} src={:?}:{} dst={:?}:{}",
                event.opcode,
                tcp.operation,
                event.process_id.as_u32(),
                decoded_pid,
                tcp.source_ip,
                port_note(tcp.source_port, &known),
                tcp.destination_ip,
                port_note(tcp.destination_port, &known),
            );
            for f in event.fields().unwrap_or(&[]) {
                if matches!(f.value, EventFieldValue::U16(_)) || f.name.contains("port") {
                    println!("    {} = {:?}", f.name, f.value);
                }
            }
        }
    }
    trace.stop()?;

    println!("{own} events from this process; {total} TcpIp events in total by opcode:");
    for (opcode, n) in &counts {
        println!(
            "  opcode {opcode:3} ({:<10}) {n:>9}  {:5.1}%",
            name(*opcode),
            *n as f64 * 100.0 / total.max(1) as f64
        );
    }
    Ok(())
}

/// The decoded port, marked `=` if it equals a known port as decoded, or
/// `swapped` if it only does after a byte swap.
fn port_note(port: Option<u16>, known: &[Option<u16>]) -> String {
    match port {
        None => "None".into(),
        Some(p) if known.contains(&Some(p)) => format!("{p} (=)"),
        Some(p) if known.contains(&Some(p.swap_bytes())) => {
            format!("{p} (swapped: {})", p.swap_bytes())
        }
        Some(p) => format!("{p} (?)"),
    }
}

fn name(opcode: u8) -> &'static str {
    match opcode {
        10 | 26 => "Send",
        11 | 27 => "Receive",
        12 | 28 => "Connect",
        13 | 29 => "Disconnect",
        14 | 30 => "Retransmit",
        15 | 31 => "Accept",
        16 | 32 => "Reconnect",
        17 | 33 => "Fail",
        18 | 34 => "Copy",
        _ => "other",
    }
}
