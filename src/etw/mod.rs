//! Real-time ETW event monitoring.
//!
//! This module lets you observe system-wide activity as it happens — process
//! creation, registry changes, network connections, file operations, and more
//! — with low overhead and structured event access.
//!
//! Internally this uses **ETW (Event Tracing for Windows)**, the same
//! infrastructure that powers Windows Performance Recorder, Process Monitor,
//! and Microsoft Defender. The API hides the ETW complexity behind familiar
//! builder and iterator patterns.
//!
//! > **Privileges**: Kernel tracing requires **Administrator** access.
//! > User-mode providers may run without elevation depending on provider ACLs.
//! > Kernel (`SystemProvider`) and user-mode GUID providers cannot be mixed in one session.
//!
//! # Quick Start
//!
//! Monitor process creation and termination:
//!
//! ```no_run
//! use windows_erg::etw::{EventTrace, SystemProvider};
//!
//! # fn main() -> windows_erg::Result<()> {
//! let mut trace = EventTrace::builder("ProcessMonitor")
//!     .system_provider(SystemProvider::Process)
//!     .start()?;
//!
//! let mut events = Vec::with_capacity(64);
//! loop {
//!     trace.next_batch(&mut events)?;
//!     for event in &events {
//!         println!("Event ID {}: PID={}", event.id, event.process_id);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # System Providers
//!
//! [`SystemProvider`] values represent kernel-level event sources. Each covers
//! a different area of system activity. Because they run inside the kernel they
//! see events from **all processes** — no instrumentation required.
//!
//! | Provider | What it captures | Typical use case |
//! |----------|-----------------|------------------|
//! | `Process` | Process/thread start and stop | Process monitoring, EDR |
//! | `Registry` | Key/value read, write, delete | Auditing, config tracking |
//! | `Network` | TCP/UDP connections | Network monitoring, firewall |
//! | `FileIo` | File create, read, write, delete | File system auditing |
//! | `ImageLoad` | DLL/EXE load and unload | Code injection detection |
//!
//! # Multiple Providers
//!
//! Chain [`system_provider`][EventTraceBuilder::system_provider] calls to
//! monitor several sources in a single session:
//!
//! ```no_run
//! # use windows_erg::etw::{EventTrace, SystemProvider};
//! # fn example() -> windows_erg::Result<()> {
//! let mut trace = EventTrace::builder("SecurityMonitor")
//!     .system_provider(SystemProvider::Process)
//!     .system_provider(SystemProvider::Registry)
//!     .system_provider(SystemProvider::Network)
//!     .start()?;
//! # Ok(())
//! # }
//! ```
//!
//! # User-Mode Providers
//!
//! You can subscribe to user-mode ETW providers directly by GUID:
//!
//! ```no_run
//! # use windows::core::GUID;
//! # use windows_erg::etw::EventTrace;
//! # fn example() -> windows_erg::Result<()> {
//! let provider = GUID::from_u128(0x3d6fa8d1_fe05_11d0_9dda_00c04fd7ba7c);
//! let mut trace = EventTrace::builder("UserModeSession")
//!     .user_provider(provider)
//!     .start()?;
//! # let _ = &mut trace;
//! # Ok(())
//! # }
//! ```
//!
//! # Buffer Tuning
//!
//! High-volume providers (especially `FileIo`) benefit from larger buffers:
//!
//! ```no_run
//! # use windows_erg::etw::{EventTrace, SystemProvider};
//! # fn example() -> windows_erg::Result<()> {
//! let trace = EventTrace::builder("FileMonitor")
//!     .system_provider(SystemProvider::FileIo)
//!     .buffer_size(256)       // 256 KB per buffer  (default: 64 KB)
//!     .min_buffers(10)        // pre-allocate 10    (default: 2)
//!     .max_buffers(50)        // cap at 50          (default: 20)
//!     .channel_capacity(50_000)
//!     .start()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Enrichment Features
//!
//! The following enrichment options are available on [`EventTraceBuilder`]:
//!
//! | Method | Effect |
//! |--------|--------|
//! | `with_stack_traces()` | Capture call stacks per event |
//! | `with_thread_context()` | Include thread metadata in raw events |
//! | `with_detailed_events()` | Schema-based field parsing of raw payloads |
//! | `with_cpu_samples()` | Correlate CPU usage samples with the event stream |
//!
//! Already active:
//! - `with_process_filter(pids)` filters events by PID in the callback path
//!   before they are pushed to output channels.
//! - `with_thread_context()` attaches `ThreadContext` to raw `TraceEvent` values.
//! - `with_stack_traces()` parses ETW extended stack data into `StackTrace`.
//! - `with_cpu_samples()` attaches processor-number metadata as `CpuSample`.

mod decode;
mod schema;
mod session;
mod types;

pub use decode::{
    DecodedEvent, EventField, EventFieldValue, FileIoEvent, FileIoOperation, ImageLoadEvent,
    ImageUnloadEvent, ProcessEndEvent, ProcessStartEvent, RegistryEvent, RegistryOperation,
    TcpEvent, TcpOperation,
};
pub use session::{EventStreamMode, EventTrace, EventTraceBuilder};
pub use types::{CpuSample, StackTrace, SystemProvider, ThreadContext, TraceEvent, TraceLevel};
