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
- Rust 1.90+
- Targets:
  - x86_64-pc-windows-msvc
  - aarch64-pc-windows-msvc

### ARM64 Validation Scope

- CI validates `aarch64-pc-windows-msvc` using cross-target compile checks.
- Runtime behavior should be validated on native Windows ARM64 hardware/runners.

## Core Modules

- process: process and thread enumeration, process tree operations, module inspection
- desktop: desktop window enumeration, tray icon lifecycle, tray balloon notifications
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
- examples/desktop_windows.rs
- examples/desktop_tray_notification.rs
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

## Testing

### Running Examples

Examples are organized into three buckets based on privilege level, runtime behavior, and side effects.

#### Phase 1: Default Auto-Run (17 examples, ~8s, non-admin friendly)

Quick sanity check for core APIs. No side effects, no special privileges needed:

```powershell
$examples = @(
  "process_basics", "process_metrics", "process_mitigation", "process_monitoring",
  "desktop_windows", "system_snapshot", "wait_multi_object", "security_permissions",
  "registry_basics", "registry_convenience", "registry_enumerate", "registry_operations",
  "registry_safe_access", "registry_write", "proxy_system", "proxy_for_url", "service_enumerate"
)

foreach ($ex in $examples) {
  cargo run --example $ex 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $ex" -ForegroundColor Red; break }
  Write-Host "PASSED: $ex" -ForegroundColor Green
}
```

#### Phase 2: Conditional Examples (machine/privilege dependent)

Event log examples with results that vary by system state and access level:

```powershell
# These run without admin but may return 0 events depending on log state
cargo run --example evt_custom_parsing
cargo run --example evt_filter
cargo run --example evt_streaming

# Requires admin (Security log access)
cargo run --example evt_query_basic

# Requires serde feature flag
cargo run --example evt_serde --features serde
```

#### Phase 3: Manual-Only (Long-running + side effects)

Run these individually in separate terminal sessions.

**Long-running ETW monitors** — press Ctrl+C to stop (require admin):
```powershell
cargo run --example etw_process_monitor
cargo run --example etw_registry_monitor
cargo run --example etw_network_monitor
cargo run --example etw_multi_provider
cargo run --example etw_decoded_events
cargo run --example etw_user_mode_provider
```

**Side-effect examples** — modify state or require elevated privileges:
```powershell
cargo run --example desktop_tray_notification   # 5s UI notification
cargo run --example process_spawn_parented       # spawns notepad as explorer child
cargo run --example process_tree                 # spawns and kills test process
cargo run --example process_wait_any             # multiple timeout scenarios (~8s)
cargo run --example service_basics               # may restart/stop Spooler service
cargo run --example etw_stop_with_wait           # admin + kernel provider required
cargo run --example raw_file_copy                # admin + raw file I/O required
```

### Quick Validation

Fastest way to confirm nothing is broken:

```powershell
cargo check
cargo test --lib
cargo run --example system_snapshot
cargo run --example process_basics
cargo run --example registry_basics
```

### Optional Features

Enable serde support for event log serialization:

```toml
[dependencies]
windows-erg = { version = "0.1", features = ["serde"] }
```

## Documentation

- API docs: https://docs.rs/windows-erg
- Project coding context: CONTEXT.md

## Contributing

Thank you for your interest in contributing!

### Before You Start

1. **Read [CONTEXT.md](CONTEXT.md)** — Contains critical coding standards, error handling patterns, buffer management conventions, and RAII handle rules. This is non-negotiable.
2. **Check existing patterns** — Review `src/registry/mod.rs` and `src/process/processes.rs` as complete reference implementations before building new features.
3. **Understand module structure** — Each module follows a consistent pattern: public API in `mod.rs`, internal utilities in submodules, tests alongside implementations.

### Making Changes

Keep changes minimal and focused. One feature or fix per PR.

Match existing module patterns:

- Use `Cow<'static, str>` for error messages — never plain `String`
- Implement RAII with `Drop` for all Windows handles
- Provide `_with_buffer` and `_with_filter` variants for collection APIs
- Use structured error types from `src/error.rs`, not ad-hoc errors

### Error Handling

```rust
// Wrong
Error::InvalidParameter("invalid value".to_string())

// Correct
Error::InvalidParameter(InvalidParameterError::new("param_name", "why it's invalid"))
```

### RAII and Handle Safety

- All Windows handles must implement `Drop`
- Use a `close_on_drop` flag for predefined handles (e.g., `INVALID_HANDLE_VALUE`)
- No manual `CloseHandle` calls in user code — cleanup is always automatic via `Drop`

### Validation Before Submitting

```powershell
cargo check
cargo test --lib
# Run Phase 1 sanity pass
cargo run --example process_basics
cargo run --example registry_write
```

### Code Review Checklist

- Follows patterns in CONTEXT.md?
- All Windows handles are RAII-protected?
- Error messages use `Cow<'static, str>`, not `String`?
- Collection APIs provide `_with_buffer` and `_with_filter` variants?
- Phase 1 examples still pass?

For questions or design discussions, open an issue before submitting code.

## License

MIT
