# Changelog

All notable changes to this project will be documented in this file.

This changelog currently captures the documented 0.1.0 feature surface that is present in the repository today. Future updates should append release entries rather than rewriting this snapshot.

## [0.1.0] - 2026-04-24

### Added

- Ergonomic, RAII-backed Windows API wrappers with structured error types, strong ID newtypes, and builder-oriented APIs where configuration is non-trivial.
- Process management APIs covering process enumeration, process and thread inspection, process tree operations, spawn helpers, module inspection, memory and host metrics, PEB-backed command line/environment access, and process injection support.
- Registry APIs with typed value reads and writes, key builders, subkey/value enumeration, WOW64 view selection, convenience helpers, and registry security descriptor read/write/apply support.
- Desktop APIs for top-level window enumeration, window metadata inspection, tray icon lifecycle management, and tray balloon notifications.
- Event Log APIs for channel and EVTX access, query builders, streaming batch consumption, publisher-backed message rendering, optional EventData extraction, explicit corrupted-event handling, and serde-based deserialization behind the `serde` feature.
- ETW tracing APIs for kernel and user-mode providers, configurable sessions, raw and decoded event streams, schema-based field parsing, and decoded process, registry, network, file I/O, and image load events.
- Proxy APIs for effective system or user proxy discovery, IE/WinHTTP proxy configuration access, and URL-specific proxy resolution.
- Process mitigation APIs for querying supported mitigations on current or external processes and applying supported runtime mitigations to the current process.
- Raw file APIs for cluster-based file copying via raw reads, plus file security descriptor and permission editing helpers.
- Security descriptor and ACL modeling APIs with SID parsing, typed ACE and access-mask types, permission edit planning, dry-run diffs, and file/registry application backends.
- Pipe APIs for named pipe servers and clients, anonymous pipes, child-process stdio integration helpers, named-pipe enumeration, local information queries, and stateful polling for appearance or removal changes.
- Service Control Manager APIs for connecting to the SCM, listing services, querying status, and starting, stopping, or restarting services through RAII-backed handles.
- System inventory APIs for collecting host snapshots including identity, OS details, GUIDs, BIOS information, logical and physical disks, network interfaces, and users while preserving per-section errors.
- Shared wait primitives for manual-reset and auto-reset events, named events, wait-any, wait-all, timeout-aware waiting, and integration across modules.
- Example programs covering process, registry, desktop, event log, ETW, proxy, service, pipe, mitigation, file, security, system, and wait scenarios.

### Improved

- Added buffer-reuse and filtered enumeration variants across collection-heavy APIs to reduce allocation churn in hot paths.
- Adopted least-privilege defaults in service querying so common status lookups do not require unnecessary control rights.
- Hardened process injection implementation for ARM64 and pointer-width safety by removing unsafe remote module handle assumptions.
- Standardized on structured crate error variants instead of string-only failures across public APIs and examples.

### Platform And Tooling

- Declared Windows 10+ and Rust 1.90+ as the supported baseline.
- Added docs.rs target metadata for both `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`.
- Added CI coverage for ARM64 cross-target compile validation, including example builds for `aarch64-pc-windows-msvc`.
- Established a clippy warning baseline in the manifest and cleaned up the library to pass `cargo clippy --lib` cleanly with narrow, documented exceptions.
- Expanded CI to cover build, lint, unit tests, integration tests, example compilation, safe example auto-run phases, and MSRV validation.

### Known Limitations

- ETW support is functional but not complete: some enrichment and decoder paths remain narrower than the public builder surface, and runtime behavior for high-volume or provider-specific scenarios should still be validated against target systems.
- ETW kernel sessions, raw file operations, protected registry writes, and operations against protected or high-integrity processes still depend on elevation.
- ARM64 support is validated in CI via cross-compilation and example builds; runtime behavior should still be exercised on native Windows ARM64 hardware.
