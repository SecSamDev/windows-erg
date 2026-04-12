# Windows-ERG Agent Context

Purpose: fast, reliable implementation guidance for contributors and coding agents.

Rule: do not create extra documentation files unless explicitly requested. Update existing docs instead.

## 1) Fast Path Checklist

Follow this order before changing code:

1. Read src/error.rs and reuse existing error types.
2. Find the target module implementation in src/<module>/.
3. Confirm matching patterns in src/registry/ and src/process/.
4. Implement with RAII handle cleanup and structured errors.
5. If returning collections, provide buffer-reuse variants.
6. Run tests/examples relevant to the change.

If the task is small, stop after step 3 and make the minimal patch.

## 2) Non-Negotiable Standards

### Error Handling

Never use String as the error payload type in public/internal error structs.
Use structured errors and Cow<'static, str>.

Preferred:

- static text: Cow::Borrowed("message")
- dynamic text: Cow::Owned(format!("..."))

Pattern:

- define/extend typed error structs in src/error.rs
- store context fields and optional error codes
- keep formatting in Display

### RAII For Windows Handles

All owned handles must close in Drop.

- add close_on_drop for pseudo/predefined handles
- guard cleanup based on ownership

### Strong Types

Use newtypes for IDs and similar domain values.

- ProcessId(u32)
- ThreadId(u32)

Avoid raw primitive IDs in public APIs when a domain type exists.

### Buffer Reuse APIs

For collection-heavy operations, provide all three forms:

1. convenience: allocates and returns Vec<T>
2. with_buffer: fills caller buffer, returns Result<usize>
3. with_filter: filters during enumeration, returns Result<usize>

Rules:

- clear output buffers at start
- use out_* for output buffers
- use work_buffer for temporary API memory
- filter during enumeration, not after collect

## 3) Agent Performance Mode

Use these rules to reduce context and execution cost:

1. Search narrow first: target module directory, then broaden.
2. Read only relevant ranges from files, not entire trees.
3. Reuse existing patterns from sibling implementations.
4. Prefer minimal diffs over broad refactors.
5. Avoid introducing new abstractions unless repeated 2+ times.
6. Validate only impacted files/tests first, then broader checks if needed.

Recommended search order:

1. src/error.rs
2. src/<module>/mod.rs
3. src/<module>/*.rs around target symbol
4. tests/* matching module
5. examples/* matching feature

## 4) Project Shape (Current)

Top-level modules:

- src/registry/
- src/process/
- src/evt/
- src/etw/
- src/file/
- src/proxy/
- src/security/
- src/pipes/
- src/mitigation/
- src/types.rs
- src/error.rs

Component collectors live under components/ and use the library APIs.

## 5) Module Status Snapshot

- registry: stable reference implementation
- process: mature, includes buffer patterns and caching
- thread behavior: integrated via process APIs
- evt: implemented, robust parsing paths present
- etw: implemented, edge-case/runtime validation still important
- proxy/mitigation/file/security/pipes: implemented

Treat src/registry/ and src/process/ as style and pattern anchors.

## 6) Implementation Patterns

### Builders

Use builders for multi-option operations and validate required fields at execute/open time.

### Windows API Calls

- wrap unsafe blocks tightly
- attach operation context to errors
- preserve OS error code when available

### Allocation Discipline

- preallocate with sensible capacity
- support reusable caller buffers
- avoid clone/collect churn in hot paths

## 7) Testing And Verification

When changing behavior:

1. run or update the closest example in examples/
2. run focused tests in tests/ for touched area
3. verify no regression in public API signatures unless intentional

If full test runs are expensive, perform targeted verification first and document what was run.

## 8) Quick Do/Do-Not

Do:

- keep edits small and local
- reuse existing error structs when possible
- return structured errors with context
- keep handle ownership explicit

Do not:

- add ad-hoc String errors
- add manual close calls at call sites for owned handles
- post-filter large collections after allocating full vectors
- create extra markdown docs without request

## 9) High-Value References

- src/error.rs
- src/registry/mod.rs
- src/process/processes.rs
- src/process/modules.rs
- examples/registry_operations.rs
- examples/process_basics.rs
- examples/evt_query_basic.rs
- examples/etw_process_monitor.rs
