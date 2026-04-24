# Windows-ERG Agent Context

Purpose: fast, reliable implementation guidance for contributors and coding agents.

Rule: do not create extra documentation files unless explicitly requested. Update existing docs instead.

Rule: when adding a new example under `examples/`, update README example lists in the same change. If the example is safe and stable for CI/CD, add it to the appropriate README auto-run testing bucket.

## 1) Fast Path Checklist

Follow this order before changing code:

1. Read src/error.rs — reuse existing error types, never invent new strings.
2. Open the target module in src/<module>/mod.rs.
3. Confirm patterns in src/registry/ and src/process/ match your approach.
4. Implement with RAII handle cleanup and structured errors.
5. If returning collections, add buffer-reuse variants.
6. Run the closest example and the lib tests.

If the task is small, stop after step 3 and apply the minimal diff.

## 2) Non-Negotiable Standards

### Error Handling

Never use String in error structs. Always use structured types with Cow<'static, str>.

```rust
// Wrong
Error::InvalidParameter("invalid value".to_string())

// Correct — static text preferred
Error::InvalidParameter(InvalidParameterError::new("param", "reason"))

// Correct — dynamic text when necessary
Cow::Owned(format!("bad value: {}", val))
```

All error types live in src/error.rs. Check there before adding a new variant.

### RAII For Windows Handles

Every owned handle must call its close function in Drop.

```rust
pub struct MyHandle {
    handle: HANDLE,
    close_on_drop: bool,  // false for predefined/pseudo handles
}
impl Drop for MyHandle {
    fn drop(&mut self) {
        if self.close_on_drop {
            unsafe { CloseHandle(self.handle); }
        }
    }
}
```

### windows crate 0.58 — Handle and API Changes

These differ from older examples and online documentation:

- `HANDLE` is pointer-backed: use `HANDLE(std::ptr::null_mut())` and `handle.0.is_null()` for null checks — not `HANDLE(0)` or integer comparisons.
- `GetWindowRect` returns `Result<()>` (not BOOL).
- `GetWindowTextW` / `GetClassNameW` accept `&mut [u16]`.
- `CreateWindowExW` returns `Result<HWND>`.
- `WinHttpOpen` returns `*mut c_void` (null on failure, not Result).
- `WinHttpGetIEProxyConfigForCurrentUser` / `WinHttpGetProxyForUrl` return `Result<()>`.
- `WINHTTP_NO_PROXY_NAME` / `WINHTTP_NO_PROXY_BYPASS` are not exposed; pass `PCWSTR::null()`.
- WinHTTP PWSTRs must be freed via `Win32::Foundation::GlobalFree`.
- Service APIs use plain `u32` access/control flags — no `SC_MANAGER_ACCESS_RIGHTS` / `SERVICE_ACCESS_RIGHTS` types.
- `Vec::reserve(n)` adds n to current capacity — it does not set capacity to n. Use `reserve(target - current_capacity)` or `reserve(target)` only when the buffer is empty.

### Strong Types

Use newtypes for domain IDs. Do not expose raw primitives in public APIs.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(u32);
impl ProcessId {
    pub fn new(id: u32) -> Self { ProcessId(id) }
    pub fn as_u32(&self) -> u32 { self.0 }
}
```

Existing newtypes: `ProcessId`, `ThreadId`. See src/types.rs.

### Buffer Reuse APIs

For collection-heavy operations provide all three forms:

```rust
// 1. Convenience — allocates internally
pub fn list() -> Result<Vec<T>> { ... }

// 2. Buffer reuse — caller provides storage
pub fn list_with_buffer(out: &mut Vec<T>) -> Result<usize> { ... }

// 3. Filtered — eliminates post-filtering alloc churn
pub fn list_with_filter<F>(out: &mut Vec<T>, filter: F) -> Result<usize>
where F: Fn(&T) -> bool { ... }
```

Rules:
- clear output buffers at start of with_buffer/with_filter
- use `out_*` prefix for output parameters
- use `work_buffer` for temporary Windows API scratch memory
- filter during enumeration, not after collecting

## 3) Agent Execution Rules

Reduce context load and iteration cost:

1. Search narrow first — target module directory, then broaden if needed.
2. Read only relevant file ranges, not entire files.
3. Reuse sibling patterns; do not reinvent.
4. Prefer minimal diffs over broad refactors.
5. Do not introduce new abstractions for single-use operations.
6. Validate impacted files/tests only; do broader `cargo test` only when needed.

Recommended search order for any change:

1. src/error.rs — error variant check
2. src/<module>/mod.rs — public API
3. src/<module>/*.rs — target symbol
4. tests/* — matching integration test
5. examples/* — closest matching feature

## 4) Project Shape

```
src/
  error.rs          ← always read first
  types.rs          ← ProcessId, ThreadId, ImagePath, newtypes
  lib.rs
  registry/         ← pattern anchor (builder + key + values + types + tests)
  process/          ← pattern anchor (processes, modules, threads, metrics, spawn, tree)
  evt/              ← event log (query, render, types)
  etw/              ← ETW session (session, schema, types, decode/)
  file/             ← raw file ops (builder, raw, win, mod)
  proxy/            ← proxy resolution (mod, types)
  security/         ← ACL editing (descriptor, editor, acl, sid, rights, target, backends/)
  pipes/            ← named/anonymous pipes (server, client, anonymous, types)
  mitigation/       ← process mitigations (mod)
  desktop/          ← window enumeration + tray icons (windows, tray, types)
  service/          ← SCM wrappers (manager, service, status, types)
  system/           ← system snapshot (mod, types)
  utils/            ← internal helpers (handles, strings)
  wait/             ← wait handle primitives (mod)
```

## 5) Module Status

| Module | Status | Notes |
|---|---|---|
| registry | ✅ stable | reference implementation; use as pattern anchor |
| process | ✅ stable | buffer patterns, ImagePath caching, PEB access |
| evt | ✅ stable | query, streaming, serde (feature-gated) |
| etw | ✅ functional | stubbed: stack traces, thread context, CPU samples, process filter; image decoder v0–v2 missing |
| security | ✅ stable | dry-run ACL editing, SID parsing |
| service | ✅ stable | least-privilege default (SERVICE_QUERY_STATUS); use plain u32 flags |
| desktop | ✅ stable | window enumeration, tray icon lifecycle |
| proxy | ✅ stable | system proxy + WinHTTP URL-based resolution |
| mitigation | ✅ stable | query + apply; set only applies to current process |
| file | ✅ stable | raw NTFS file copy via retrieval pointers |
| pipes | ✅ stable | named pipe server/client, anonymous pipes |
| system | ✅ stable | snapshot of host metrics |
| wait | ✅ stable | manual reset events, wait_any, wait_all |

Treat `src/registry/` and `src/process/` as style and pattern anchors for all new work.

### Known Gaps (ETW)

- `with_stack_traces()`, `with_thread_context()`, `with_cpu_samples()`, `with_process_filter()` — declared on builder, fields are set, but have no effect in `start()` (see TODO at session.rs line 437).
- Image provider decoder supports only version 3. Versions 0–2 fall through silently.
- Network, Registry, FileIO providers rely on TDH schema parsing only (no direct binary decoders). Silent fallback to `Unknown` if TDH fails.
- ETW test coverage is minimal (3 builder validation tests, 1 schema test, 4 helper tests). No lifecycle or decode integration tests.
- `TDH_INTYPE_IPV4`/`TDH_INTYPE_IPV6` not exported by windows-rs 0.58; use numeric values 19/20 in schema.rs.

### Known Caveats (service)

- Avoid asserting start/stop behavior in tests — permission results vary by environment.
- Requires `Win32_System_Services` feature; `Win32_System_SystemServices` alone is insufficient.

### Known Caveats (etw/session.rs)

- `Box<Arc<CallbackContext>>` is intentionally redundant; `#[allow(clippy::redundant_allocation)]` is kept to stabilize the callback pointer address.

## 6) Implementation Patterns

### Builders

Use builders for multi-option operations. Validate required fields only at the terminal method (`open`, `start`, `execute`).

### Windows API Wrapping

```rust
unsafe { SomeWindowsApi(...) }
    .map_err(|e| Error::Module(ModuleError::with_code(
        resource_identifier,
        "operation description",
        e.code().0,
    )))?;
```

- wrap unsafe blocks tightly around the single call
- attach operation context to every error
- preserve OS error code as `Option<i32>` when available

### Allocation Discipline

- preallocate with sensible capacity
- support caller-provided reusable buffers
- no clone/collect churn in hot paths

## 7) Testing and Verification

```powershell
# Targeted (preferred first)
cargo check
cargo test --lib
cargo run --example <closest_example>

# Full suite
cargo test
```

When changing behavior:
1. Run or update the closest example in examples/
2. Run focused tests in tests/ for the touched area
3. Verify public API signatures have not changed unintentionally

**Example buckets** (see README.md for full split):
- Phase 1 (17 examples, non-admin, ~8s): process_basics, registry_*, system_snapshot, desktop_windows, security_permissions, service_enumerate, proxy_*, wait_multi_object, process_metrics, process_mitigation, process_monitoring
- Phase 2 (conditional, machine-dependent): evt_* examples
- Phase 3 (manual only, admin or long-running): etw_* monitors, service_basics, raw_file_copy, process_spawn_parented, process_tree, process_wait_any, desktop_tray_notification

## 8) Quick Do/Do-Not

Do:
- keep edits small and local
- reuse existing error variants from src/error.rs
- return structured errors with resource context and OS code
- keep handle ownership explicit

Do not:
- use String in error structs
- add manual CloseHandle calls at call sites for owned handles
- post-filter large collections after full allocation
- create extra markdown files without a request
- use HANDLE(0) or integer null checks — HANDLE is pointer-backed in windows 0.58

## 9) High-Value References

| File | Why |
|---|---|
| src/error.rs | all error variants; check before adding |
| src/types.rs | all domain newtypes |
| src/registry/mod.rs | complete reference: builder + key + values |
| src/process/processes.rs | buffer reuse + HANDLE + RAII patterns |
| src/process/modules.rs | three-variant collection API reference |
| src/etw/session.rs | ETW RAII, builder, channel delivery |
| src/etw/schema.rs | TDH schema parsing quirks |
| examples/registry_operations.rs | registry 5-pattern demo |
| examples/process_basics.rs | process API baseline |
| examples/evt_streaming.rs | event log streaming |
| examples/etw_process_monitor.rs | ETW kernel session |
