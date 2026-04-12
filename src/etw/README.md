# ETW (Event Tracing for Windows) Module

Real-time ETW monitoring for kernel and user-mode providers with typed decoding
and bounded stream consumption.

## Status

The ETW module provides:
- Session start/stop via `StartTraceW` and `ControlTraceW`
- User-mode provider enablement by GUID via `EnableTraceEx2`
- Real-time consumption via `OpenTraceW` + `ProcessTrace`
- Bounded channel delivery with backpressure (drops when full)
- Raw and decoded stream modes
- Optional schema parsing with cached TDH metadata
- Stale `NT Kernel Logger` recovery on start

## Public API

- `EventTrace` - running ETW session handle (RAII cleanup)
- `EventTraceBuilder` - fluent configuration and startup
- `SystemProvider` - kernel providers (`Process`, `Registry`, `Network`, `FileIo`, `ImageLoad`)
- `user_provider(GUID)` - register one or more user-mode ETW providers
- `TraceEvent` - raw event with metadata + optional parsed fields
- `DecodedEvent` - typed event variants for common providers

## Quick Start

```rust
use windows_erg::etw::{EventTrace, SystemProvider};

fn main() -> windows_erg::Result<()> {
    let mut trace = EventTrace::builder("ProcessMonitor")
        .system_provider(SystemProvider::Process)
        .start()?;

    let mut events = Vec::with_capacity(128);
    loop {
        let count = trace.next_batch(&mut events)?;
        if count == 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            continue;
        }

        for event in &events {
            println!(
                "id={} opcode={} pid={} tid={}",
                event.id, event.opcode, event.process_id, event.thread_id
            );
        }
    }
}
```

## Stream Modes

- Raw only (default): `next_batch(&mut Vec<TraceEvent>)`
- Decoded only: `.with_decoded_stream()` + `next_batch_decoded(&mut Vec<DecodedEvent>)`
- Both: `.with_both_streams()`

## Provider Selection Rules

- Kernel providers: use `.system_provider(SystemProvider::...)`
- User-mode providers: use `.user_provider(GUID::from_u128(...))`
- Mixed provider types in one session are rejected at `start()`

## Filtering

- Buffer-time filtering:
  - `next_batch_with_filter(...)`
  - `next_batch_decoded_with_filter(...)`
- Callback-time filtering:
  - `.with_process_filter(vec![...])` limits callback enqueue by PID

## Enrichment Options

- Active:
  - `with_detailed_events()` - attach schema-parsed fields to raw events and
    feed typed generic decoders
  - `with_process_filter(...)` - callback-level PID filter
  - `with_thread_context()` - attach `ThreadContext` metadata to raw events
  - `with_stack_traces()` - parse ETW extended stack data into `StackTrace`
  - `with_cpu_samples()` - attach per-event processor-number metadata as `CpuSample`

## Current Limitations

1. Real-time only (no ETL file replay support)
2. Kernel and user providers cannot be mixed in one session
3. Partial TDH coverage for complex property shapes (arrays/maps/out-type formatting)
4. Windows only
5. Administrator privileges required for kernel tracing (user providers depend on ACLs)

## Architecture

```
EventTraceBuilder
  -> StartTraceW (NT Kernel Logger)
  -> OpenTraceW (real-time callback)
  -> ProcessTrace thread
  -> callback: EVENT_RECORD -> TraceEvent/DecodedEvent
  -> bounded channels
  -> next_batch / next_batch_decoded
```

## Examples

- `cargo run --example etw_process_monitor`
- `cargo run --example etw_registry_monitor`
- `cargo run --example etw_network_monitor`
- `cargo run --example etw_multi_provider`
- `cargo run --example etw_decoded_events`
- `cargo run --example etw_user_mode_provider`

## Testing

```bash
cargo check
cargo test --lib etw
cargo test --doc
```

## References

- ETW Architecture: https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing
- windows-rs docs: https://microsoft.github.io/windows-docs-rs/
