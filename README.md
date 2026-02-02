# windows-erg

[![Crates.io](https://img.shields.io/crates/v/windows-erg.svg)](https://crates.io/crates/windows-erg)
[![Documentation](https://docs.rs/windows-erg/badge.svg)](https://docs.rs/windows-erg)
[![License](https://img.shields.io/crates/l/windows-erg.svg)](LICENSE)

**Ergonomic, idiomatic Rust wrappers for Windows APIs**

`windows-erg` provides a safe, ergonomic interface to Windows system programming. Built on top of the excellent [`windows-rs`](https://github.com/microsoft/windows-rs) crate, it abstracts away the complexity of raw Windows API calls, automatic handle management, and permission handling.

> **For AI Agents / GitHub Copilot**: Before making any changes, read [CONTEXT.md](./CONTEXT.md) for critical coding standards and patterns.

## Features

- 🛡️ **Safe**: RAII handle management, no manual cleanup required
- 🎯 **Ergonomic**: Idiomatic Rust APIs with builder patterns and iterators
- 🔧 **Comprehensive**: Process, registry, threads, event logs, ETW, and more
- 📝 **Well-documented**: Extensive documentation with working examples
- ⚡ **Efficient**: Zero-cost abstractions over Windows APIs

## Modules

### 🔄 Process Management
```rust
use windows_erg::process::Process;

// List all processes
for process in Process::list()? {
    println!("{}: {} ({})", 
        process.id(), 
        process.name(), 
        process.memory_usage()
    );
}

// Get specific process info
let process = Process::get(1234)?;
println!("Process path: {}", process.path());

// Kill a process
Process::kill(1234)?;

// Spawn as child of another process
Process::spawn()
    .command("cmd.exe")
    .args(&["/c", "echo Hello"])
    .parent(parent_pid)
    .execute()?;
```

### 📋 Registry Operations
```rust
use windows_erg::registry::{Hive, RegistryKey};

// Open a registry key
let key = RegistryKey::open(
    Hive::LocalMachine, 
    r"SOFTWARE\Microsoft\Windows\CurrentVersion"
)?;

// Read a value
let program_files: String = key.get_value("ProgramFilesDir")?;

// Create and write
let key = RegistryKey::create(Hive::CurrentUser, r"Software\MyApp")?;
key.set_value("Version", "1.0.0")?;
key.set_value("InstallCount", 42u32)?;

// Enumerate subkeys
for subkey in key.subkeys()? {
    println!("Subkey: {}", subkey);
}
```

### 🧵 Thread Management
```rust
use windows_erg::thread::Thread;

// List threads in a process
for thread in Thread::list_for_process(process_id)? {
    println!("Thread {}: {}", thread.id(), thread.state());
}

// Suspend/Resume
thread.suspend()?;
thread.resume()?;
```

### 📊 Windows Event Logs (EVT)
```rust
use windows_erg::evt::EventLog;

// Open system event log
let log = EventLog::open("System")?;

// Query recent events
let events = log.query()
    .level("Error")
    .source("Service Control Manager")
    .last_hours(24)
    .execute()?;

for event in events {
    println!("[{}] {}: {}", 
        event.timestamp(), 
        event.source(), 
        event.message()
    );
}
```

### 🔍 Event Tracing for Windows (ETW)
```rust
use windows_erg::etw::{EtwSession, Provider};

// Start ETW session
let session = EtwSession::new("MyTrace")?
    .enable_provider(
        Provider::by_name("Microsoft-Windows-Kernel-Process")?
            .keywords(0x10)
            .level(4)
    )?
    .start()?;

// Consume events
for event in session.events()? {
    println!("ETW Event: {:?}", event);
}
```

### 🌐 Network Proxy Configuration
```rust
use windows_erg::proxy;

// Get system proxy settings
let config = proxy::get_system_proxy()?;
println!("Proxy server: {}", config.server);
println!("Bypass list: {:?}", config.bypass);

// Get proxy for specific URL
let proxy = proxy::get_proxy_for_url("https://example.com")?;
```

### 🛡️ Process Mitigations
```rust
use windows_erg::mitigation::{Mitigation, MitigationPolicy};

// Apply mitigations to current process
MitigationPolicy::new()
    .enable(Mitigation::Dep)
    .enable(Mitigation::Aslr)
    .enable(Mitigation::ControlFlowGuard)
    .enable(Mitigation::StrictHandleChecks)
    .apply_to_current()?;

// Apply to another process
MitigationPolicy::new()
    .enable(Mitigation::DisableDynamicCode)
    .apply_to_process(pid)?;
```

### 📁 Raw File Operations
```rust
use windows_erg::file;

// Copy file at raw level (bypasses file system filters)
file::raw_copy(
    r"C:\source\file.dat",
    r"C:\destination\file.dat"
)?;
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
windows-erg = "0.1"
```

For async support:
```toml
[dependencies]
windows-erg = { version = "0.1", features = ["async"] }
```

## Platform Requirements

- **Operating System**: Windows 10 or later
- **Rust Version**: 1.70 or later
- **Target**: `x86_64-pc-windows-msvc` or `aarch64-pc-windows-msvc`

## Permissions

Many operations require elevated privileges (administrator rights):
- Registry writes to `HKEY_LOCAL_MACHINE`
- Process operations on protected processes
- ETW session management
- Raw file operations

The library will return clear error messages when insufficient permissions are detected.

## Examples

See the [`examples/`](examples/) directory for complete working examples:

- [`list_processes.rs`](examples/list_processes.rs) - Process enumeration and information
- [`registry_operations.rs`](examples/registry_operations.rs) - Registry manipulation
- [`event_log.rs`](examples/event_log.rs) - Event log querying
- [`process_mitigation.rs`](examples/process_mitigation.rs) - Applying security mitigations

Run an example:
```bash
cargo run --example list_processes
```

## Documentation

Full API documentation is available at [docs.rs/windows-erg](https://docs.rs/windows-erg).

For architecture and design decisions, see:
- [CONTEXT.md](CONTEXT.md) - Project context for AI agents
- [ARCHITECTURE.md](ARCHITECTURE.md) - Detailed architecture documentation

## Error Handling

All fallible operations return `Result<T, windows_erg::Error>`:

```rust
use windows_erg::Error;

match Process::get(pid) {
    Ok(process) => println!("Found: {}", process.name()),
    Err(Error::ProcessNotFound(_)) => println!("Process not found"),
    Err(Error::AccessDenied(_)) => println!("Permission denied"),
    Err(e) => println!("Other error: {}", e),
}
```

## Safety

This library provides safe abstractions over unsafe Windows APIs:

- ✅ Automatic handle cleanup via RAII
- ✅ No manual memory management required
- ✅ Type-safe APIs prevent common mistakes
- ✅ Bounds checking on all buffer operations

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Acknowledgments

Built on top of the excellent [`windows-rs`](https://github.com/microsoft/windows-rs) project by Microsoft.

## See Also

- [`windows`](https://crates.io/crates/windows) - Raw Windows API bindings
- [`winapi`](https://crates.io/crates/winapi) - Alternative Windows API bindings
- [`sysinfo`](https://crates.io/crates/sysinfo) - Cross-platform system information
