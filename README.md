# windows-erg

[![Crates.io](https://img.shields.io/crates/v/windows-erg.svg)](https://crates.io/crates/windows-erg)
[![Documentation](https://docs.rs/windows-erg/badge.svg)](https://docs.rs/windows-erg)
[![License](https://img.shields.io/crates/l/windows-erg.svg)](LICENSE)

Ergonomic, idiomatic Rust wrappers for Windows APIs.

windows-erg provides safe, high-level APIs on top of windows-rs for common Windows system programming tasks.

For contributors and coding agents: read CONTEXT.md first.

## Highlights

- Safe handle lifecycle via RAII
- Structured error model
- Type-safe identifiers and API surfaces
- Builder-style configuration where useful
- Buffer-reuse variants for allocation-sensitive paths

## Installation

Add to Cargo.toml:

```toml
[dependencies]
windows-erg = "0.1"
```

## Platform Requirements

- Windows 10+
- Rust 1.70+
- Targets:
  - x86_64-pc-windows-msvc
  - aarch64-pc-windows-msvc

## Core Modules

- process: process and thread enumeration, process tree operations, module inspection
- registry: key/value operations with ergonomic typed access
- evt: Windows Event Log query and rendering
- etw: ETW session and event consumption support
- proxy: system and URL-specific proxy resolution
- mitigation: process mitigation query/apply helpers
- file: raw file operations
- service: Windows Service Control Manager query/control/enumeration
- security, pipes: security and IPC primitives

## Quick Examples

### Process listing

```rust
use windows_erg::process::Process;

for p in Process::list()? {
    println!("{} {}", p.id().as_u32(), p.name());
}
# Ok::<(), windows_erg::Error>(())
```

### Registry read

```rust
use windows_erg::registry::{Hive, RegistryKey};

let key = RegistryKey::open(
    Hive::LocalMachine,
    r"SOFTWARE\Microsoft\Windows\CurrentVersion",
)?;
let value: String = key.get_value("ProgramFilesDir")?;
println!("{}", value);
# Ok::<(), windows_erg::Error>(())
```

### Event log query

```rust
use windows_erg::evt::EventLog;

let log = EventLog::open("System")?;
let events = log.query().level("Error").execute()?;
println!("events: {}", events.len());
# Ok::<(), windows_erg::Error>(())
```

### ETW (real-time tracing)

```rust
use windows_erg::etw::{EventTrace, SystemProvider};

let mut trace = EventTrace::builder("ProcessMonitor")
  .system_provider(SystemProvider::Process)
  .with_decoded_stream()
  .start()?;

let mut decoded = Vec::with_capacity(128);
let count = trace.next_batch_decoded(&mut decoded)?;
println!("decoded events: {}", count);

trace.stop()?;
# Ok::<(), windows_erg::Error>(())
```

### Security descriptors and ACL editing

```rust
use windows_erg::security::{
  AccessMask, ApplyMode, PermissionEditor, PermissionTarget, Sid,
};

let target = PermissionTarget::file(r"C:\\Temp\\example.txt".to_string());
let users = Sid::parse("S-1-5-32-545")?; // Built-in Users

let plan = PermissionEditor::new()
  .grant(users, AccessMask::from_bits(0x120089))
  .build()?;

let result = plan.execute_against_target(&target, ApplyMode::DryRunDiff)?;
println!("added ACEs: {}", result.diff.added.len());
# Ok::<(), windows_erg::Error>(())
```

## Permissions

Some operations require administrator privileges:

- ETW session management
- raw file operations
- writes under protected registry hives
- operations on protected/high-integrity processes

APIs return structured permission/access errors when denied.

## ETW Notes

- ETW supports raw, decoded, or dual stream modes.
- Kernel providers require elevated privileges and use the kernel logger session.
- You cannot mix kernel system providers and user-mode provider GUIDs in a single ETW session.
- Use bounded channel capacity and batch draining for sustained high-volume traces.

See examples:

- examples/etw_process_monitor.rs
- examples/etw_network_monitor.rs
- examples/etw_multi_provider.rs
- examples/etw_decoded_events.rs

## Security Descriptor Notes

- Security descriptor APIs support both file and registry targets.
- Use dry-run first to inspect ACL diffs before applying changes.
- Descriptor model includes owner, group, DACL, and typed ACE entries.
- Convenience APIs are available in file and registry modules for common read/write/apply flows.

See examples:

- examples/security_permissions.rs

## Examples In This Repository

- examples/process_basics.rs
- examples/process_monitoring.rs
- examples/process_tree.rs
- examples/process_mitigation.rs
- examples/registry_basics.rs
- examples/registry_operations.rs
- examples/registry_write.rs
- examples/evt_query_basic.rs
- examples/evt_streaming.rs
- examples/etw_process_monitor.rs
- examples/etw_network_monitor.rs
- examples/proxy_system.rs
- examples/proxy_for_url.rs
- examples/raw_file_copy.rs
- examples/service_basics.rs
- examples/service_enumerate.rs
- examples/security_permissions.rs

Run one example:

```bash
cargo run --example process_basics
```

## Error Handling

Fallible operations return:

```rust
Result<T, windows_erg::Error>
```

The crate uses structured error types (see src/error.rs), not string-only error payloads.

## Documentation

- API docs: https://docs.rs/windows-erg
- Project coding context: CONTEXT.md

## Contributing

Contributions are welcome. Keep changes minimal, consistent with module patterns, and aligned with CONTEXT.md.

## License

MIT
