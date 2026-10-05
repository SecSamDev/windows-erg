//! File I/O probe: which kernel File I/O events does a create / write /
//! rename / delete sequence actually produce, and with which fields?
//!
//! Starts a private system-logger session, performs a scripted sequence of
//! file operations in a temp directory itself, then prints every File I/O
//! event that either came from this process (header PID) or mentions the
//! probe directory in a field. The `pid_ok` column shows whether the header
//! PID was this process, which answers whether the header PID can be trusted
//! for these events.
//!
//! Run as Administrator:
//! `cargo run --example etw_fileio_probe` (FILE_IO_INIT only)
//! `cargo run --example etw_fileio_probe -- --full` (FILE_IO | FILE_IO_INIT)

use std::time::{Duration, Instant};
use windows::core::GUID;
use windows_erg::etw::{EventTrace, SystemProvider, TraceEvent};

const MARKER: &str = "bg-fileio-probe";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !windows_erg::is_elevated()? {
        eprintln!("run this from an elevated terminal");
        std::process::exit(1);
    }
    let full = std::env::args().any(|a| a == "--full");
    let provider = if full {
        SystemProvider::FileIo
    } else {
        SystemProvider::FileIoInit
    };
    let own_pid = std::process::id();

    let mut trace = EventTrace::builder(format!("FileIoProbe-{own_pid}"))
        .system_provider(provider)
        .with_detailed_events()
        .private_system_logger(GUID::from_u128(
            0x6a1f_0e5e_7c1b_4c3e_9d5a_0000_0000_0000 ^ u128::from(own_pid),
        ))
        .buffer_size(128)
        .flush_interval(1)
        .channel_capacity(65_536)
        .start()?;

    // Give the session a moment to start delivering.
    std::thread::sleep(Duration::from_millis(500));
    let dir = std::env::temp_dir().join(format!("{MARKER}-{own_pid}"));
    script(&dir)?;
    println!("script done in {}", dir.display());

    let mut batch: Vec<TraceEvent> = Vec::with_capacity(1024);
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut seen = 0usize;
    while Instant::now() < deadline {
        trace.next_batch_timeout(&mut batch, Duration::from_millis(200))?;
        for event in &batch {
            let fields = event.fields().unwrap_or(&[]);
            let mentions = fields
                .iter()
                .any(|f| format!("{:?}", f.value).contains(MARKER));
            let pid_ok = event.process_id.as_u32() == own_pid;
            if !(pid_ok || mentions) {
                continue;
            }
            seen += 1;
            println!(
                "opcode={:3} pid_ok={:5} header_pid={:6} tid={:6} decoded={:?}",
                event.opcode,
                pid_ok,
                event.process_id.as_u32(),
                event.thread_id.as_u32(),
                file_op(event),
            );
            for f in fields {
                println!("    {} = {:?}", f.name, f.value);
            }
        }
    }
    println!("{seen} matching events");
    trace.stop()?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

fn file_op(event: &TraceEvent) -> String {
    match event.decode() {
        windows_erg::etw::DecodedEvent::FileIo(f) => format!("{:?}", f.operation),
        other => format!("{other:?}").chars().take(40).collect(),
    }
}

/// The sequences ransomware uses: write a copy then delete the original,
/// and overwrite in place then rename.
fn script(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let a = dir.join("a.docx");
    let b = dir.join("b.docx");
    std::fs::write(&a, b"original a")?;
    std::fs::write(&b, b"original b")?;

    // Copy-then-delete.
    std::fs::write(dir.join("a.docx.bgsim"), b"encrypted a")?;
    std::fs::remove_file(&a)?;

    // Overwrite in place, then rename.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).open(&b)?;
        f.write_all(b"encrypted b")?;
    }
    std::fs::rename(&b, dir.join("b.docx.bgsim"))?;
    Ok(())
}
