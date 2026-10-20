# Changelog

All notable changes to this project will be documented in this file.

This changelog currently captures the documented 0.1.0 feature surface that is present in the repository today. Future updates should append release entries rather than rewriting this snapshot.

## [0.4.0] - Unreleased

### Changed (breaking)

- Upgraded `windows` from 0.58 to 0.62. Public items that expose `windows` types (`etw::GUID`, `windows::core::Error` in `error` and `utils::io`, `EVENT_RECORD` in `etw::TraceEvent::from_event_record`) now use 0.62 types; downstream crates that pass these across the API must depend on `windows` 0.62 as well.
- New direct dependency `windows-numerics` 0.3 (Direct2D `Vector2`, used by `desktop::Canvas`; `windows` 0.62 does not re-export it).

### Internal

- CI runs clippy (`-D warnings`) and the lib tests for `i686-pc-windows-msvc`, so 32-bit builds no longer regress unnoticed.

## [0.3.0] - 2026-10-20

### Added

- **desktop**
  - Windows backed by a boxed `WindowHandler`, a message loop, `MessagePoster` for cross-thread `PostMessageW`, child windows, `PaintGuard`, and mouse and timer helpers.
  - Common controls: a virtual (`LVS_OWNERDATA`) list view, a tab strip and a status bar, with `WM_NOTIFY` decoding. The list view supports custom draw (including the row post-paint stage), selection-change and `LVN_KEYDOWN` (`ControlNotify::KeyDown`) notifications, `select`, `ensure_visible`, cell rects and colours, row height, column width, and flat rows without focus rectangles.
  - Popup menus (tray pattern), per-monitor v2 DPI awareness, a `Local\` single-instance mutex, and clipboard text.
  - Direct2D `Canvas` that draws in DIPs: cards, rounded rects, circles, lines, and DirectWrite text with font fallback and ellipsis. It renders in software by default; `for_window_hardware` uses the GPU.
  - Theming: the system's app-mode preference, a dark title bar, the Mica backdrop, dark menus, and dark/light `ItemsView`/`Explorer` list views with header text colour.
  - `TrayIcon`: a version-4 callback message (`TrayEvent`), an icon from resources, re-adding after `TaskbarCreated`, quiet-time and silent balloons, and icon swaps.
- **etw**
  - `EventTraceBuilder::private_system_logger(guid)` runs kernel providers in an independently named system-logger session instead of the shared "NT Kernel Logger".
  - `EventTrace::replaced_existing_session`, `is_running`, `events_dropped`, `events_lost` and `next_batch_timeout`.
  - `EventTrace::user_provider_with` enables a user-mode provider at a level and `MatchAnyKeyword` mask.
  - `EventTrace::request_rundown` makes the kernel replay cached KCBs and open files, so keys opened before the session started get names.
  - `EventTraceBuilder::drop_opcodes(KernelEventClass, ..)` discards chosen opcodes in the callback, before any TDH parsing.
  - `SystemProvider::FileIoInit` (create/close/delete/rename plus read/write, without completions), separate from `FileIo`. File I/O decoding covers the path operations (`DeletePath`, `RenamePath`, `SetLinkPath`) and the TTID, FileName, InfoClass, ExtraInfo, IoSize and Offset fields.
  - `EventProvider` registers a provider and writes manifest-based events (RAII), with `EventDescriptor` and typed `EventData` fields.
  - `etw::GUID` re-exported, so callers don't need their own `windows` dependency.
  - `TraceEvent::pointer_size`: the width (4 or 8) of pointer-sized fields in the raw payload, taken from the event header.
  - Probe examples: `etw_fileio_probe`, `etw_tcpip_probe`, `etw_registry_probe`, `etw_kernel_process_probe` and a Task Scheduler probe.
- **crypto**: SHA-256, SHA-1, MD5, HMAC-SHA256, system RNG (`random_bytes`), AES-256-GCM (`AesGcmKey` seal/open), ECDSA P-256 sign/verify/keygen, and DPAPI `protect`/`unprotect` (current-user or local-machine scope).
- **security**
  - `ProcessToken`: `is_elevated`, `integrity_level`, `is_admin` and `user_sid`.
  - `IntegrityLevel::from_rid` and `from_label_sid`.
  - `Sid::lookup_account` resolves a SID to its account (domain, name and `AccountKind`, displayed as `DOMAIN\name`).
  - `PermissionTarget::set_protected_dacl_sddl` and `dacl_sddl` for files, directories and registry keys.
- **process**
  - `Process::snapshot()`: a system-wide snapshot with parent PID, creation time, session ID and image name.
  - `Process::cwd()` reads the real current directory from the PEB.
  - `ProcessAccess::QueryAndVmRead`.
- **file**
  - `analyze_pe_file` / `analyze_pe_bytes` return a `PeAnalysis`: hashes, imphash, imported DLLs, 64-bit, .NET and overlay detection, and checksum mismatch.
  - `create_new_no_follow` and `delete_no_follow` refuse every reparse point along the path.
- **path**: a public `nt_path_to_dos`, `nt_path_to_dos_into` and `refresh_device_map`.
- **pipes**
  - `NamedPipeServerBuilder::first_instance`.
  - `NamedPipeServer::set_io_timeout` and `client_is_elevated_admin`.
- **console**: `signal_on_ctrl` signals a `Wait` on console control events.
- **system**: `known_folder` (ProgramData, Program Files, app data) and `filetime_to_local`.

### Changed

- `SystemProvider::Process` and `SystemProvider::Thread` are separate, so process events no longer pull in the thread stream.
- ETW registry decoding maps opcodes 21–29 to their own KCB operations (`KCBCreate`, `KCBDelete`, KCB rundown, `Close`, …) instead of reading them as `DeleteKey`, `EnumerateKey` or `Open`. A value event's name now lands in `value_name`.
- Pipe clients request data and attribute access instead of `GENERIC_WRITE`, so DACLs that grant callers data access only no longer deny them.

### Fixed

- `process` PEB reads could call `Vec::set_len` past the buffer's capacity (undefined behaviour) when a remote `UNICODE_STRING` was longer than the scratch buffer.
- Named pipe server I/O now uses `OVERLAPPED` (the handle is overlapped), `flush` calls `FlushFileBuffers`, and reads follow std semantics (`Ok(0)` on close, partial reads on `ERROR_MORE_DATA`).
- `utils::win_to_io_error` unwraps `HRESULT_FROM_WIN32`, so `io::ErrorKind` (`BrokenPipe`, `TimedOut`, `PermissionDenied`) is correct.
- ETW TcpIp ports were byte-swapped (TDH reports them in network byte order).
- 32-bit (`i686-pc-windows-msvc`) builds compile again, and their tests pass.
- ETW process and image-load decoding used the consumer's pointer width, so a 32-bit process reading 64-bit kernel events decoded garbage. The decoders now use the event header's pointer size.

## [0.2.0] - 2026-05-22

### Added

- New `system` module functionality for host snapshot collection via `system::snapshot()`, including host identity, OS details, machine/firmware GUIDs, BIOS metadata, logical and physical disk inventory, network interfaces, and user/account discovery.
- New resilient snapshot behavior with per-section partial-failure reporting through `section_errors`, allowing snapshot collection to continue even when individual sections fail.
- New system power control APIs for local machine shutdown and restart (`system::shutdown`, `system::restart`) with typed `PowerActionOptions` support for timeout, force-close, planned flag, reason code, and optional user-facing comment.

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
