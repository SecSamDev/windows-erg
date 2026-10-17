//! Registry probe: which kernel Registry events does a create / set /
//! delete sequence actually produce, with which fields, and can every
//! write be resolved to a full key path?
//!
//! Starts a private system-logger session with the Registry flag, asks for
//! a KCB rundown ([`EventTrace::request_rundown`]), then runs `reg.exe`
//! against a marker key under HKCU. It keeps a KCB → name map the way a
//! consumer would (opcode 22 KCBCreate and 25 KCBRundown insert, 23
//! KCBDelete removes), and prints:
//!
//! - how many KCB events the rundown delivered;
//! - every Create / SetValue / DeleteValue / DeleteKey / SetInformation
//!   event from a `reg.exe` child, with its fields and the path the map
//!   resolves it to (or `UNRESOLVED`);
//! - a count of every opcode seen after the rundown, idle traffic
//!   included, so the per-second volume is visible;
//! - how many writes system-wide resolved and how many did not.
//!
//! Run as Administrator:
//! `cargo run --example etw_registry_probe` (add `-- --idle 60` for a
//! longer idle tail after the script, `-- --no-rundown` to skip it)

use std::collections::{BTreeMap, HashMap};
use std::process::Command;
use std::time::{Duration, Instant};
use windows::core::GUID;
use windows_erg::etw::{EventFieldValue as FieldValue, EventTrace, SystemProvider, TraceEvent};

const MARKER: &str = "BGRegistryProbe";
const KCB_CREATE: u8 = 22;
const KCB_DELETE: u8 = 23;
const KCB_RUNDOWN_BEGIN: u8 = 24;
const KCB_RUNDOWN_END: u8 = 25;
/// Create, SetValue, DeleteValue, DeleteKey, SetInformation.
const WRITES: [u8; 5] = [10, 14, 15, 12, 20];

#[derive(Default)]
struct Kcbs {
    names: HashMap<u64, String>,
    resolved: u64,
    unresolved: u64,
}

impl Kcbs {
    /// Update the map from a KCB event; `true` if it was one.
    fn observe(&mut self, event: &TraceEvent) -> bool {
        match event.opcode {
            KCB_CREATE | KCB_RUNDOWN_BEGIN | KCB_RUNDOWN_END => {
                if let (Some(h), Some(name)) = (handle(event), key_name(event))
                    && !name.is_empty()
                {
                    self.names.insert(h, name);
                }
                true
            }
            KCB_DELETE => {
                if let Some(h) = handle(event) {
                    self.names.remove(&h);
                }
                true
            }
            _ => false,
        }
    }

    /// The full path of a write: its KCB's name joined with its relative
    /// `KeyName`, or the `KeyName` alone when it is already absolute.
    fn resolve(&mut self, event: &TraceEvent) -> Option<String> {
        let name = key_name(event).unwrap_or_default();
        if name.starts_with('\\') {
            self.resolved += 1;
            return Some(name);
        }
        let base = handle(event).and_then(|h| self.names.get(&h));
        match base {
            Some(base) => {
                self.resolved += 1;
                // For a value op KeyName is the value name, not a subkey.
                Some(match event.opcode {
                    14 | 15 => format!("{base} [value {name:?}]"),
                    _ if name.is_empty() => base.clone(),
                    _ => format!("{base}\\{name}"),
                })
            }
            None => {
                self.unresolved += 1;
                None
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !windows_erg::is_elevated()? {
        eprintln!("run this from an elevated terminal");
        std::process::exit(1);
    }
    let args: Vec<String> = std::env::args().collect();
    let idle = args
        .iter()
        .skip_while(|a| *a != "--idle")
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5);
    let rundown = !args.iter().any(|a| a == "--no-rundown");
    let own_pid = std::process::id();

    let mut trace = EventTrace::builder(format!("RegistryProbe-{own_pid}"))
        .system_provider(SystemProvider::Registry)
        .with_detailed_events()
        .private_system_logger(GUID::from_u128(
            0x6a1f_0e5e_7c1b_4c3e_9d5a_1111_0000_0000 ^ u128::from(own_pid),
        ))
        .buffer_size(256)
        .flush_interval(1)
        .channel_capacity(262_144)
        .start()?;

    let mut batch: Vec<TraceEvent> = Vec::with_capacity(4096);
    let mut kcbs = Kcbs::default();

    // Let the consumer attach, then ask for the rundown and drain it.
    std::thread::sleep(Duration::from_millis(500));
    if rundown {
        let asked = Instant::now();
        trace.request_rundown()?;
        let mut by_opcode: BTreeMap<u8, u64> = BTreeMap::new();
        let mut shown = 0;
        drain(
            &mut trace,
            &mut batch,
            Duration::from_secs(3),
            &mut |event| {
                if kcbs.observe(event) {
                    *by_opcode.entry(event.opcode).or_default() += 1;
                    if event.opcode != KCB_CREATE && shown < 3 {
                        shown += 1;
                        print_event("rundown", event, None);
                    }
                }
            },
        )?;
        println!(
            "--- rundown: KCB events by opcode {by_opcode:?}, {} names known, {:?} after asking",
            kcbs.names.len(),
            asked.elapsed()
        );
    } else {
        println!("--- no rundown requested");
    }

    let mut reg_pids: Vec<u32> = Vec::new();
    let key = format!(r"HKCU\Software\{MARKER}");
    for args in [
        vec!["add", key.as_str(), "/f"],
        vec!["add", key.as_str(), "/v", "probe", "/d", "1", "/f"],
        vec!["delete", key.as_str(), "/v", "probe", "/f"],
        vec!["delete", key.as_str(), "/f"],
    ] {
        let child = Command::new("reg.exe").args(&args).spawn()?;
        reg_pids.push(child.id());
        let out = child.wait_with_output()?;
        println!("reg {} -> {}", args.join(" "), out.status);
    }

    let tail = Instant::now();
    let mut counts: BTreeMap<u8, u64> = BTreeMap::new();
    let mut unresolved_samples = 0;
    drain(
        &mut trace,
        &mut batch,
        Duration::from_secs(idle),
        &mut |event| {
            *counts.entry(event.opcode).or_default() += 1;
            if kcbs.observe(event) || !WRITES.contains(&event.opcode) {
                return;
            }
            let path = kcbs.resolve(event);
            if reg_pids.contains(&event.process_id.as_u32()) {
                print_event("reg", event, Some(path.as_deref().unwrap_or("UNRESOLVED")));
            } else if path.is_none() && unresolved_samples < 5 {
                unresolved_samples += 1;
                print_event("unresolved", event, None);
            }
        },
    )?;
    let tail_secs = tail.elapsed().as_secs_f64();
    println!(
        "--- writes system-wide: {} resolved, {} unresolved; {} KCB names known",
        kcbs.resolved,
        kcbs.unresolved,
        kcbs.names.len()
    );
    println!("--- after the rundown, {tail_secs:.1} s, per opcode (total, per second):");
    for (op, n) in &counts {
        println!("    opcode {op:3}: {n:8}  {:10.1}/s", *n as f64 / tail_secs);
    }
    trace.stop()?;
    Ok(())
}

fn handle(event: &TraceEvent) -> Option<u64> {
    field(event, "KeyHandle").and_then(|v| match v {
        FieldValue::Pointer(p) => Some(*p),
        FieldValue::U64(p) => Some(*p),
        _ => None,
    })
}

fn key_name(event: &TraceEvent) -> Option<String> {
    field(event, "KeyName").and_then(|v| match v {
        FieldValue::String(s) => Some(s.clone()),
        _ => None,
    })
}

fn field<'a>(event: &'a TraceEvent, name: &str) -> Option<&'a FieldValue> {
    event
        .fields()?
        .iter()
        .find(|f| f.name == name)
        .map(|f| &f.value)
}

fn drain(
    trace: &mut EventTrace,
    batch: &mut Vec<TraceEvent>,
    for_how_long: Duration,
    on_event: &mut dyn FnMut(&TraceEvent),
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + for_how_long;
    while Instant::now() < deadline {
        trace.next_batch_timeout(batch, Duration::from_millis(200))?;
        for event in batch.iter() {
            on_event(event);
        }
    }
    Ok(())
}

fn print_event(tag: &str, event: &TraceEvent, path: Option<&str>) {
    println!(
        "[{tag}] opcode={:3} version={} header_pid={:6} tid={:6}{}",
        event.opcode,
        event.version,
        event.process_id.as_u32(),
        event.thread_id.as_u32(),
        path.map(|p| format!(" path={p}")).unwrap_or_default(),
    );
    for f in event.fields().unwrap_or(&[]) {
        println!("    {} = {:?}", f.name, f.value);
    }
}
