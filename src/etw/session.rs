//! ETW trace session management.

use super::decode::{DecodedEvent, decode_from_record_parts};
use super::schema::SchemaCache;
use super::types::{CpuSample, StackTrace, SystemProvider, ThreadContext, TraceEvent};
use crate::Result;
use crate::error::{Error, EtwConsumeError, EtwError, EtwProviderError, EtwSessionError};
use crate::types::ProcessId;
use crate::utils::to_utf16_nul;
use crate::wait::Wait;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::core::{GUID, PWSTR};

const MAX_SESSION_NAME_LEN: usize = 1024;
const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";
const ERROR_ALREADY_EXISTS_CODE: u32 = 183;

/// Callback context shared between the `ProcessTrace` thread and the consumer.
struct CallbackContext {
    raw_sender: Option<SyncSender<TraceEvent>>,
    decoded_sender: Option<SyncSender<DecodedEvent>>,
    schema_cache: Option<Mutex<SchemaCache>>,
    process_filter: Option<HashSet<ProcessId>>,
    include_thread_context: bool,
    include_stack_traces: bool,
    include_cpu_samples: bool,
    /// Events dropped because a bounded output channel was full.
    dropped: AtomicU64,
}

fn normalize_process_filter(pids: Vec<ProcessId>) -> Option<HashSet<ProcessId>> {
    if pids.is_empty() {
        return None;
    }
    Some(pids.into_iter().collect())
}

/// Kernel-session identity and mode, resolved once so `start()` and its
/// stale-session retry path can't disagree with each other.
struct KernelSessionConfig {
    session_name: String,
    log_file_mode: u32,
    wnode_guid: GUID,
}

/// Resolve the session name, `LogFileMode`, and `Wnode.Guid` for a kernel
/// session, or `None` when no kernel providers were requested (a user-mode
/// session keeps the caller's own name unconditionally).
///
/// Pure and OS-call-free so it can be unit-tested directly.
fn kernel_session_config(
    builder_name: &str,
    has_kernel_providers: bool,
    private_logger_guid: Option<GUID>,
) -> Option<KernelSessionConfig> {
    if !has_kernel_providers {
        return None;
    }

    let is_private_logger = private_logger_guid.is_some();
    Some(KernelSessionConfig {
        session_name: if is_private_logger {
            builder_name.to_string()
        } else {
            KERNEL_LOGGER_NAME.to_string()
        },
        log_file_mode: if is_private_logger {
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE
        } else {
            EVENT_TRACE_REAL_TIME_MODE
        },
        wnode_guid: private_logger_guid.unwrap_or(GUID::zeroed()),
    })
}

fn extract_stack_trace(record: &EVENT_RECORD) -> Option<StackTrace> {
    if record.ExtendedDataCount == 0 || record.ExtendedData.is_null() {
        return None;
    }

    let items = unsafe {
        std::slice::from_raw_parts(record.ExtendedData, record.ExtendedDataCount as usize)
    };

    for item in items {
        let ext_type = item.ExtType;
        let is_stack32 = ext_type == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 as u16;
        let is_stack64 = ext_type == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 as u16;
        if !is_stack32 && !is_stack64 {
            continue;
        }

        if item.DataPtr == 0 || item.DataSize < 8 {
            continue;
        }

        let raw = unsafe {
            std::slice::from_raw_parts(item.DataPtr as *const u8, item.DataSize as usize)
        };

        if raw.len() < 8 {
            continue;
        }

        let match_id = u64::from_le_bytes(raw[0..8].try_into().ok()?);
        let frame_size = if is_stack32 { 4 } else { 8 };

        let mut frames = Vec::new();
        let mut offset = 8usize;
        while offset + frame_size <= raw.len() {
            let addr = if frame_size == 4 {
                let bytes: [u8; 4] = raw[offset..offset + 4].try_into().ok()?;
                u32::from_le_bytes(bytes) as u64
            } else {
                let bytes: [u8; 8] = raw[offset..offset + 8].try_into().ok()?;
                u64::from_le_bytes(bytes)
            };

            if addr != 0 {
                frames.push(addr);
            }
            offset += frame_size;
        }

        return Some(StackTrace::new(match_id, frames));
    }

    None
}

fn extract_cpu_sample(record: &EVENT_RECORD) -> CpuSample {
    // ETW_BUFFER_CONTEXT starts with ProcessorNumber (u8).
    let processor_number = unsafe { *(std::ptr::addr_of!(record.BufferContext) as *const u8) };
    CpuSample::new(processor_number)
}

/// Owns callback context storage and provides a stable user-context pointer.
///
/// `EVENT_TRACE_LOGFILEW::Context` stores a raw pointer that ETW passes back to
/// `trace_callback_fn` for every event. We keep the `Arc<CallbackContext>` in a
/// boxed allocation so the address stays stable for the full trace lifetime.
struct CallbackContextGuard {
    #[allow(clippy::redundant_allocation)]
    boxed_ctx: Box<Arc<CallbackContext>>,
}

impl CallbackContextGuard {
    fn new(ctx: CallbackContext) -> Self {
        Self {
            boxed_ctx: Box::new(Arc::new(ctx)),
        }
    }

    fn as_user_context_ptr(&self) -> *mut std::ffi::c_void {
        self.boxed_ctx.as_ref() as *const Arc<CallbackContext> as *mut std::ffi::c_void
    }

    /// Total events dropped so far because an output channel was full.
    fn dropped_count(&self) -> u64 {
        self.boxed_ctx.dropped.load(Ordering::Relaxed)
    }
}

/// Output stream strategy for ETW events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStreamMode {
    /// Emit only raw `TraceEvent` values.
    Raw,
    /// Emit only decoded `DecodedEvent` values.
    Decoded,
    /// Emit both raw and decoded streams.
    Both,
}

/// The `ProcessTrace` callback invoked by Windows for each event record.
///
/// # Safety
///
/// Called by the OS from the `ProcessTrace` background thread. The `UserContext`
/// field of the `EVENT_RECORD` must point to a valid `Arc<CallbackContext>` that
/// remains alive for the duration of the trace.
unsafe extern "system" fn trace_callback_fn(event_record: *mut EVENT_RECORD) {
    let record = match unsafe { event_record.as_ref() } {
        Some(r) => r,
        None => return,
    };
    let ctx_ptr = record.UserContext as *const Arc<CallbackContext>;
    let ctx = match unsafe { ctx_ptr.as_ref() } {
        Some(c) => c,
        None => return,
    };

    if let Some(filter) = &ctx.process_filter
        && !filter.contains(&ProcessId::new(record.EventHeader.ProcessId))
    {
        return;
    }

    let fields = ctx
        .schema_cache
        .as_ref()
        .and_then(|cache| cache.lock().ok())
        .and_then(|mut cache| cache.parse_event_fields(record));

    let payload = if record.UserDataLength > 0 && !record.UserData.is_null() {
        unsafe {
            std::slice::from_raw_parts(record.UserData as *const u8, record.UserDataLength as usize)
        }
    } else {
        &[]
    };

    if let Some(sender) = &ctx.decoded_sender {
        let desc = record.EventHeader.EventDescriptor;
        let decoded = decode_from_record_parts(
            record.EventHeader.ProviderId,
            desc.Version,
            desc.Opcode,
            payload,
            fields.as_deref(),
        );
        // Drop decoded events when channel is full (bounded backpressure).
        if sender.try_send(decoded).is_err() {
            ctx.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    if let Some(sender) = &ctx.raw_sender {
        let mut event = TraceEvent::from_event_record_with_fields(record, fields);
        if ctx.include_thread_context {
            event.thread_context = Some(ThreadContext::new(event.process_id, event.thread_id));
        }
        if ctx.include_stack_traces {
            event.stack_trace = extract_stack_trace(record);
        }
        if ctx.include_cpu_samples {
            event.cpu_sample = Some(extract_cpu_sample(record));
        }
        // Drop raw events when channel is full (bounded backpressure).
        if sender.try_send(event).is_err() {
            ctx.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A running ETW trace session.
///
/// Created by [`EventTraceBuilder::start`]. Automatically stops the trace when
/// dropped (RAII).
///
/// Use [`EventTrace::builder`] to configure and start a session.
pub struct EventTrace {
    /// Session name (`NT Kernel Logger` for kernel providers, custom for user-mode providers).
    name: String,

    /// Handle used for [`ControlTraceW`] stop/flush operations.
    session_handle: CONTROLTRACE_HANDLE,

    /// Handle returned by `OpenTraceW`, used for `CloseTrace`.
    trace_handle: PROCESSTRACE_HANDLE,

    /// Optional bounded channel receiving raw events from the callback.
    event_rx: Option<Receiver<TraceEvent>>,

    /// Optional bounded channel receiving decoded events from the callback.
    decoded_rx: Option<Receiver<DecodedEvent>>,

    /// Running total of events delivered through [`next_batch`][Self::next_batch].
    events_processed: usize,

    /// `false` after [`stop`][Self::stop] or [`drop`][Drop::drop] to avoid double-stop.
    started: bool,

    /// Background thread running `ProcessTrace` (blocks until `CloseTrace`).
    process_thread: Option<JoinHandle<()>>,

    /// Internal stop signal that can be shared with external coordinators.
    stop_signal: Wait,

    /// Owns callback context memory for ETW callback user-data pointer.
    callback_ctx_guard: CallbackContextGuard,

    /// `true` if `start()` had to stop and replace a leftover session with the
    /// same name before it could start (see [`Self::replaced_existing_session`]).
    replaced_existing_session: bool,
}

impl EventTrace {
    /// Create a builder to configure and start an ETW trace session.
    ///
    /// No validation happens here — all checks run in
    /// [`EventTraceBuilder::start`] so the builder can always be constructed
    /// without a `Result`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use windows_erg::etw::{EventTrace, SystemProvider};
    ///
    /// let mut trace = EventTrace::builder("ProcessMonitor")
    ///     .system_provider(SystemProvider::Process)
    ///     .start()?;
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn builder(name: impl Into<String>) -> EventTraceBuilder {
        EventTraceBuilder {
            name: name.into(),
            system_providers: Vec::new(),
            user_providers: Vec::new(),
            buffer_size: 64,
            min_buffers: 2,
            max_buffers: 20,
            flush_interval: 1,
            channel_capacity: 10_000,
            stream_mode: EventStreamMode::Raw,
            stack_traces: false,
            thread_context: false,
            detailed_events: false,
            cpu_samples: false,
            process_filter: Vec::new(),
            private_logger_guid: None,
        }
    }

    /// The active ETW session name.
    ///
    /// Kernel sessions always use `NT Kernel Logger`; user-mode sessions use
    /// the builder name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Total events delivered so far across all [`next_batch`][Self::next_batch] calls.
    pub fn events_processed(&self) -> usize {
        self.events_processed
    }

    /// Get a clone of the stop signal for external cancellation coordination.
    pub fn stop_handle(&self) -> Wait {
        self.stop_signal.clone()
    }

    /// `true` if starting this session had to stop and replace a leftover
    /// session with the same name first.
    ///
    /// With a private system-logger name (see
    /// [`private_system_logger`][EventTraceBuilder::private_system_logger]),
    /// that leftover session can only be one this process (or a previous run
    /// of it) created, never an unrelated tool's `NT Kernel Logger`.
    pub fn replaced_existing_session(&self) -> bool {
        self.replaced_existing_session
    }

    /// `true` while the `ProcessTrace` background thread is still running.
    ///
    /// Turns `false` if another tool stops this session out from under us
    /// (e.g. by name collision or an administrator running `logman stop`).
    /// Once `false`, the session is dead and a new one must be started.
    pub fn is_running(&self) -> bool {
        self.started
            && self
                .process_thread
                .as_ref()
                .is_some_and(|handle| !handle.is_finished())
    }

    /// Total events dropped so far because a bounded output channel was full.
    ///
    /// Distinct from [`events_lost`][Self::events_lost]: this counts events
    /// this process's callback chose to discard; that counts events the
    /// kernel itself lost before our callback ever ran.
    pub fn events_dropped(&self) -> u64 {
        self.callback_ctx_guard.dropped_count()
    }

    /// Query the kernel for events lost before delivery to our callback.
    ///
    /// Sums `EventsLost` (events dropped because all trace buffers were full)
    /// and `RealTimeBuffersLost` (buffers dropped before the real-time
    /// consumer could read them).
    pub fn events_lost(&self) -> Result<u32> {
        let name_wide = to_utf16_nul(&self.name);
        let mut properties_buffer =
            vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (MAX_SESSION_NAME_LEN * 2)];

        let result = unsafe {
            let properties = &mut *(properties_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
            properties.Wnode.BufferSize = properties_buffer.len() as u32;
            properties.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            ControlTraceW(
                self.session_handle,
                PWSTR(name_wide.as_ptr() as *mut u16),
                properties,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };

        if result != ERROR_SUCCESS {
            return Err(Error::Etw(EtwError::ConsumeFailed(
                EtwConsumeError::with_code(
                    Cow::Borrowed("Failed to query trace session loss statistics"),
                    result.0 as i32,
                ),
            )));
        }

        let properties = unsafe { &*(properties_buffer.as_ptr() as *const EVENT_TRACE_PROPERTIES) };
        Ok(properties
            .EventsLost
            .saturating_add(properties.RealTimeBuffersLost))
    }

    /// Fetch the next batch of events into the output buffer.
    ///
    /// Clears `out_events` before filling it. Returns the number of events added.
    pub fn next_batch(&mut self, out_events: &mut Vec<TraceEvent>) -> Result<usize> {
        self.next_batch_with_filter(out_events, |_| true)
    }

    /// Fetch the next batch unless the session stop signal has been set.
    ///
    /// Returns `0` when stop was requested.
    pub fn next_batch_or_stopped(&mut self, out_events: &mut Vec<TraceEvent>) -> Result<usize> {
        if self.stop_signal.is_signaled()? {
            out_events.clear();
            return Ok(0);
        }
        self.next_batch(out_events)
    }

    /// Continuously drain batches until the stop signal is set.
    ///
    /// The output buffer is reused on each iteration.
    pub fn run_until_stopped(
        &mut self,
        out_events: &mut Vec<TraceEvent>,
        poll_interval: Duration,
    ) -> Result<()> {
        loop {
            if self.stop_signal.is_signaled()? {
                out_events.clear();
                return Ok(());
            }
            let _ = self.next_batch(out_events)?;
            std::thread::sleep(poll_interval);
        }
    }

    /// Fetch the next batch of events, keeping only those that pass `filter`.
    ///
    /// Clears `out_events` before filling it. Returns the number of events added.
    ///
    /// Filtering happens **during** enumeration, so rejected events are never
    /// pushed to the buffer.
    pub fn next_batch_with_filter<F>(
        &mut self,
        out_events: &mut Vec<TraceEvent>,
        filter: F,
    ) -> Result<usize>
    where
        F: Fn(&TraceEvent) -> bool,
    {
        let rx = self.event_rx.as_ref().ok_or_else(|| {
            Error::Etw(EtwError::ConsumeFailed(EtwConsumeError::new(
                Cow::Borrowed("Raw event stream is disabled for this session"),
            )))
        })?;

        out_events.clear();
        while let Ok(event) = rx.try_recv() {
            if filter(&event) {
                out_events.push(event);
                self.events_processed += 1;
            }
        }
        Ok(out_events.len())
    }

    /// Fetch the next batch of raw events, blocking up to `timeout` for the
    /// first one, then draining whatever else has already arrived.
    ///
    /// Clears `out_events` before filling it. Returns the number of events
    /// added, `0` if `timeout` elapsed with nothing to deliver.
    ///
    /// Prefer this over [`next_batch`][Self::next_batch] for a consumer loop:
    /// `next_batch` never blocks, so a caller must poll it in a tight loop to
    /// get low latency. This blocks efficiently and still drains a full batch
    /// once something arrives.
    pub fn next_batch_timeout(
        &mut self,
        out_events: &mut Vec<TraceEvent>,
        timeout: Duration,
    ) -> Result<usize> {
        let rx = self.event_rx.as_ref().ok_or_else(|| {
            Error::Etw(EtwError::ConsumeFailed(EtwConsumeError::new(
                Cow::Borrowed("Raw event stream is disabled for this session"),
            )))
        })?;

        out_events.clear();
        match rx.recv_timeout(timeout) {
            Ok(event) => out_events.push(event),
            Err(RecvTimeoutError::Timeout) => return Ok(0),
            Err(RecvTimeoutError::Disconnected) => return Ok(0),
        }
        while let Ok(event) = rx.try_recv() {
            out_events.push(event);
        }
        self.events_processed += out_events.len();
        Ok(out_events.len())
    }

    /// Fetch the next batch of decoded events into the output buffer.
    ///
    /// Clears `out_events` before filling it. Returns the number of events added.
    pub fn next_batch_decoded(&mut self, out_events: &mut Vec<DecodedEvent>) -> Result<usize> {
        self.next_batch_decoded_with_filter(out_events, |_| true)
    }

    /// Fetch the next batch of decoded events, keeping only those that pass `filter`.
    ///
    /// Clears `out_events` before filling it. Returns the number of events added.
    pub fn next_batch_decoded_with_filter<F>(
        &mut self,
        out_events: &mut Vec<DecodedEvent>,
        filter: F,
    ) -> Result<usize>
    where
        F: Fn(&DecodedEvent) -> bool,
    {
        let rx = self.decoded_rx.as_ref().ok_or_else(|| {
            Error::Etw(EtwError::ConsumeFailed(EtwConsumeError::new(
                Cow::Borrowed("Decoded event stream is disabled for this session"),
            )))
        })?;

        out_events.clear();
        while let Ok(event) = rx.try_recv() {
            if filter(&event) {
                out_events.push(event);
                self.events_processed += 1;
            }
        }
        Ok(out_events.len())
    }

    /// Stop the trace session explicitly.
    ///
    /// Also called automatically when `EventTrace` is dropped.
    pub fn stop(&mut self) -> Result<()> {
        if !self.started {
            return Ok(());
        }

        let _ = self.stop_signal.set();

        // 1. Stop the ETW session via ControlTraceW.
        let name_wide = to_utf16_nul(&self.name);

        let mut properties_buffer =
            vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (MAX_SESSION_NAME_LEN * 2)];

        unsafe {
            let properties = &mut *(properties_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
            properties.Wnode.BufferSize = properties_buffer.len() as u32;
            properties.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

            let _ = ControlTraceW(
                self.session_handle,
                PWSTR(name_wide.as_ptr() as *mut u16),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );
        }

        // 2. Close the trace handle — unblocks the ProcessTrace background thread.
        if self.trace_handle.Value != u64::MAX {
            unsafe {
                // ERROR_CTX_CLOSE_PENDING is expected while ProcessTrace finishes.
                let _ = CloseTrace(self.trace_handle);
            }
            self.trace_handle = PROCESSTRACE_HANDLE { Value: u64::MAX };
        }

        // 3. Wait for the ProcessTrace background thread to exit.
        if let Some(handle) = self.process_thread.take() {
            let _ = handle.join();
        }

        self.started = false;
        Ok(())
    }
}

impl Drop for EventTrace {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// SAFETY: CONTROLTRACE_HANDLE is an opaque integer; EventTrace owns it exclusively.
unsafe impl Send for EventTrace {}

/// Builder for configuring an ETW trace session.
///
/// Obtained from [`EventTrace::builder`]. Chain configuration methods, then
/// call [`start`][Self::start] to begin tracing and receive an [`EventTrace`] handle.
pub struct EventTraceBuilder {
    name: String,
    system_providers: Vec<SystemProvider>,
    user_providers: Vec<GUID>,
    buffer_size: u32,
    min_buffers: u32,
    max_buffers: u32,
    flush_interval: u32,
    channel_capacity: usize,
    stream_mode: EventStreamMode,

    // Optional enrichment and filtering flags.
    stack_traces: bool,
    thread_context: bool,
    detailed_events: bool,
    cpu_samples: bool,
    process_filter: Vec<ProcessId>,
    private_logger_guid: Option<GUID>,
}

impl EventTraceBuilder {
    /// Add a kernel event source to this trace session.
    ///
    /// Can be called multiple times to monitor several sources at once.
    /// At least one provider must be added before calling [`start`][Self::start].
    ///
    /// # Example
    ///
    /// ```no_run
    /// use windows_erg::etw::{EventTrace, SystemProvider};
    ///
    /// let trace = EventTrace::builder("SecurityMonitor")
    ///     .system_provider(SystemProvider::Process)
    ///     .system_provider(SystemProvider::Registry)
    ///     .start()?;
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn system_provider(mut self, provider: SystemProvider) -> Self {
        self.system_providers.push(provider);
        self
    }

    /// Run kernel providers as a private system-logger session instead of the
    /// shared `NT Kernel Logger`.
    ///
    /// Windows 8+ allows up to 8 concurrent system-logger sessions, each
    /// identified by its own `Wnode.Guid` and `EVENT_TRACE_SYSTEM_LOGGER_MODE`
    /// flag, and each keeping the caller's own session name instead of the
    /// reserved `NT Kernel Logger`. Without this, starting a kernel session
    /// silently stops (or clashes with) whatever other profiler or security
    /// tool already owns the one legacy session — `guid` must be a value this
    /// caller controls, never [`windows::Win32::System::Diagnostics::Etw::SystemTraceControlGuid`].
    ///
    /// Has no effect on user-mode ([`user_provider`][Self::user_provider]) sessions.
    pub fn private_system_logger(mut self, guid: GUID) -> Self {
        self.private_logger_guid = Some(guid);
        self
    }

    /// Add a user-mode ETW provider by GUID.
    ///
    /// This enables events from providers registered with `EventRegister`
    /// (for example application or service providers).
    ///
    /// User-mode providers cannot be mixed with kernel [`SystemProvider`]s in
    /// a single session.
    pub fn user_provider(mut self, provider_guid: GUID) -> Self {
        self.user_providers.push(provider_guid);
        self
    }

    /// Set buffer size in kilobytes (default: 64 KB).
    ///
    /// Larger buffers reduce the chance of losing events at the cost of memory.
    pub fn buffer_size(mut self, size_kb: u32) -> Self {
        self.buffer_size = size_kb;
        self
    }

    /// Set the minimum number of event buffers pre-allocated by the OS (default: 2).
    pub fn min_buffers(mut self, count: u32) -> Self {
        self.min_buffers = count;
        self
    }

    /// Set the maximum number of event buffers the OS may allocate (default: 20).
    pub fn max_buffers(mut self, count: u32) -> Self {
        self.max_buffers = count;
        self
    }

    /// Set how often the OS flushes filled buffers, in seconds (default: 1).
    pub fn flush_interval(mut self, seconds: u32) -> Self {
        self.flush_interval = seconds;
        self
    }

    /// Set the internal event channel capacity (default: 10 000).
    ///
    /// Bounds memory usage during high-volume tracing. Events beyond this
    /// limit are dropped when the consumer falls behind.
    pub fn channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self
    }

    /// Emit only decoded events to avoid raw event allocation overhead.
    pub fn with_decoded_stream(mut self) -> Self {
        self.stream_mode = EventStreamMode::Decoded;
        self
    }

    /// Emit both raw and decoded events.
    pub fn with_both_streams(mut self) -> Self {
        self.stream_mode = EventStreamMode::Both;
        self
    }

    // -------------------------------------------------------------------------
    // Optional with_* enrichment features
    // -------------------------------------------------------------------------

    /// Capture stack trace metadata for events when ETW provides it.
    ///
    /// When enabled, raw [`TraceEvent`] values may include `stack_trace`
    /// parsed from event extended data items.
    pub fn with_stack_traces(mut self) -> Self {
        self.stack_traces = true;
        self
    }

    /// Include thread context metadata in each event.
    ///
    /// When enabled, raw [`TraceEvent`] values include `thread_context` metadata
    /// populated from the ETW event header (`ProcessId` and `ThreadId`).
    pub fn with_thread_context(mut self) -> Self {
        self.thread_context = true;
        self
    }

    /// Parse event payloads into named fields using the provider schema *(planned feature)*.
    ///
    /// When implemented, the raw `data` bytes in each [`TraceEvent`] will be
    /// pre-decoded into structured fields based on the provider's event schema.
    pub fn with_detailed_events(mut self) -> Self {
        self.detailed_events = true;
        self
    }

    /// Attach basic CPU sampling metadata to each raw event.
    ///
    /// When enabled, raw [`TraceEvent`] values include `cpu_sample`
    /// with the logical processor number from ETW buffer context.
    pub fn with_cpu_samples(mut self) -> Self {
        self.cpu_samples = true;
        self
    }

    /// Restrict event collection to specific process IDs.
    ///
    /// When non-empty, only events whose `ProcessId` matches one of `pids`
    /// are forwarded from the ETW callback to the output channels.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use windows_erg::etw::{EventTrace, SystemProvider};
    ///
    /// let trace = EventTrace::builder("TargetedMonitor")
    ///     .system_provider(SystemProvider::FileIo)
    ///     .with_process_filter(vec![1234, 5678])
    ///     .start()?;
    /// # Ok::<(), windows_erg::Error>(())
    /// ```
    pub fn with_process_filter<I, P>(mut self, pids: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<ProcessId>,
    {
        self.process_filter = pids.into_iter().map(Into::into).collect();
        self
    }

    /// Start the trace session and return an [`EventTrace`] handle.
    ///
    /// # Errors
    ///
    /// | Condition | Error |
    /// |-----------|-------|
    /// | Empty session name | [`EtwError::SessionStartFailed`] |
    /// | Name longer than 1024 chars | [`EtwError::SessionStartFailed`] |
    /// | No providers specified | [`EtwError::SessionStartFailed`] |
    /// | Mixed kernel + user providers | [`EtwError::SessionStartFailed`] |
    /// | `min_buffers` > `max_buffers` | [`EtwError::SessionStartFailed`] |
    /// | `NT Kernel Logger` already running | `SessionStartFailed` with `ERROR_ALREADY_EXISTS` |
    /// | Windows API failure | [`EtwError::SessionStartFailed`] with OS error code |
    pub fn start(self) -> Result<EventTrace> {
        // ----- Validate -----

        if self.name.is_empty() {
            return Err(Error::Etw(EtwError::SessionStartFailed(
                EtwSessionError::new(
                    Cow::Borrowed(""),
                    Cow::Borrowed("Session name cannot be empty"),
                ),
            )));
        }

        if self.name.len() > MAX_SESSION_NAME_LEN {
            return Err(Error::Etw(EtwError::SessionStartFailed(
                EtwSessionError::new(
                    Cow::Owned(self.name.clone()),
                    Cow::Borrowed("Session name exceeds 1024 characters"),
                ),
            )));
        }

        if self.system_providers.is_empty() && self.user_providers.is_empty() {
            return Err(Error::Etw(EtwError::SessionStartFailed(
                EtwSessionError::new(
                    Cow::Owned(self.name.clone()),
                    Cow::Borrowed(
                        "At least one system provider or user provider GUID must be specified",
                    ),
                ),
            )));
        }

        if !self.system_providers.is_empty() && !self.user_providers.is_empty() {
            return Err(Error::Etw(EtwError::SessionStartFailed(
                EtwSessionError::invalid_config(
                    Cow::Owned(self.name.clone()),
                    "providers",
                    Cow::Borrowed(
                        "Cannot mix kernel system providers with user-mode provider GUIDs in one session",
                    ),
                ),
            )));
        }

        if self.min_buffers > self.max_buffers {
            return Err(Error::Etw(EtwError::SessionStartFailed(
                EtwSessionError::new(
                    Cow::Owned(self.name.clone()),
                    Cow::Owned(format!(
                        "min_buffers ({}) cannot exceed max_buffers ({})",
                        self.min_buffers, self.max_buffers
                    )),
                ),
            )));
        }

        // ----- Build EVENT_TRACE_PROPERTIES -----

        let is_kernel_session = !self.system_providers.is_empty();
        let kernel_config =
            kernel_session_config(&self.name, is_kernel_session, self.private_logger_guid);

        // Kernel providers require the reserved "NT Kernel Logger" name,
        // unless running as a private system logger (its own name and GUID).
        let session_name = kernel_config
            .as_ref()
            .map(|c| c.session_name.clone())
            .unwrap_or_else(|| self.name.clone());
        let log_file_mode = kernel_config
            .as_ref()
            .map(|c| c.log_file_mode)
            .unwrap_or(EVENT_TRACE_REAL_TIME_MODE);
        let wnode_guid = kernel_config
            .as_ref()
            .map(|c| c.wnode_guid)
            .unwrap_or(GUID::zeroed());
        let name_wide: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let properties_size =
            std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (MAX_SESSION_NAME_LEN * 2);
        let mut properties_buffer = vec![0u8; properties_size];

        let properties =
            unsafe { &mut *(properties_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };

        // Kernel sessions combine EVENT_TRACE_FLAG values from enabled providers.
        let enable_flags: u32 = if is_kernel_session {
            self.system_providers
                .iter()
                .fold(0u32, |acc, p| acc | p.trace_flags())
        } else {
            0
        };

        properties.Wnode.BufferSize = properties_buffer.len() as u32;
        properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties.Wnode.ClientContext = 1; // QPC clock resolution
        properties.Wnode.Guid = wnode_guid;
        properties.BufferSize = self.buffer_size;
        properties.MinimumBuffers = self.min_buffers;
        properties.MaximumBuffers = self.max_buffers;
        properties.FlushTimer = self.flush_interval;
        properties.LogFileMode = log_file_mode;
        properties.EnableFlags = EVENT_TRACE_FLAG(enable_flags);
        properties.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        // ----- StartTraceW -----

        let mut session_handle = CONTROLTRACE_HANDLE::default();
        let mut replaced_existing_session = false;

        let start_result = unsafe {
            StartTraceW(
                &mut session_handle,
                PWSTR(name_wide.as_ptr() as *mut u16),
                properties,
            )
        };

        if start_result.0 == ERROR_ALREADY_EXISTS_CODE && is_kernel_session {
            // Stale session from a previous crash — stop it and retry.
            let stop_buf_size =
                std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (MAX_SESSION_NAME_LEN * 2);
            let mut stop_buf = vec![0u8; stop_buf_size];
            unsafe {
                let stop_props = &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                stop_props.Wnode.BufferSize = stop_buf.len() as u32;
                stop_props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
                let _ = ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    PWSTR(name_wide.as_ptr() as *mut u16),
                    stop_props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }

            // Re-build properties and retry (StartTraceW may have modified the buffer).
            let mut retry_buf = vec![0u8; properties_size];
            let retry_result = unsafe {
                let props = &mut *(retry_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                props.Wnode.BufferSize = retry_buf.len() as u32;
                props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
                props.Wnode.ClientContext = 1;
                props.Wnode.Guid = wnode_guid;
                props.BufferSize = self.buffer_size;
                props.MinimumBuffers = self.min_buffers;
                props.MaximumBuffers = self.max_buffers;
                props.FlushTimer = self.flush_interval;
                props.LogFileMode = log_file_mode;
                props.EnableFlags = EVENT_TRACE_FLAG(enable_flags);
                props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
                StartTraceW(
                    &mut session_handle,
                    PWSTR(name_wide.as_ptr() as *mut u16),
                    props,
                )
            };

            if retry_result != ERROR_SUCCESS {
                return Err(Error::Etw(EtwError::SessionStartFailed(
                    EtwSessionError::with_code(
                        Cow::Owned(session_name),
                        Cow::Borrowed("Failed to start trace after stopping stale session"),
                        retry_result.0 as i32,
                    ),
                )));
            }

            replaced_existing_session = true;
        } else if start_result != ERROR_SUCCESS {
            return Err(Error::Etw(EtwError::SessionStartFailed(
                EtwSessionError::with_code(
                    Cow::Owned(session_name),
                    Cow::Borrowed("Failed to start trace session"),
                    start_result.0 as i32,
                ),
            )));
        }

        if !is_kernel_session {
            for provider_guid in &self.user_providers {
                let enable_result = unsafe {
                    EnableTraceEx2(
                        session_handle,
                        provider_guid as *const GUID,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                        TRACE_LEVEL_VERBOSE as u8,
                        u64::MAX,
                        0,
                        0,
                        None,
                    )
                };

                if enable_result != ERROR_SUCCESS {
                    let mut stop_buf = vec![
                        0u8;
                        std::mem::size_of::<EVENT_TRACE_PROPERTIES>()
                            + (MAX_SESSION_NAME_LEN * 2)
                    ];
                    unsafe {
                        let stop_props =
                            &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                        stop_props.Wnode.BufferSize = stop_buf.len() as u32;
                        stop_props.LoggerNameOffset =
                            std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
                        let _ = ControlTraceW(
                            session_handle,
                            PWSTR(name_wide.as_ptr() as *mut u16),
                            stop_props,
                            EVENT_TRACE_CONTROL_STOP,
                        );
                    }

                    return Err(Error::Etw(EtwError::ProviderEnableFailed(
                        EtwProviderError::with_code(
                            Cow::Owned(format!("{provider_guid:?}")),
                            Cow::Borrowed("Failed to enable user-mode ETW provider"),
                            enable_result.0 as i32,
                        ),
                    )));
                }
            }
        }

        // ----- Event consumption pipeline -----

        let (raw_tx, event_rx) = match self.stream_mode {
            EventStreamMode::Raw | EventStreamMode::Both => {
                let (tx, rx) = mpsc::sync_channel(self.channel_capacity);
                (Some(tx), Some(rx))
            }
            EventStreamMode::Decoded => (None, None),
        };

        let (decoded_tx, decoded_rx) = match self.stream_mode {
            EventStreamMode::Decoded | EventStreamMode::Both => {
                let (tx, rx) = mpsc::sync_channel(self.channel_capacity);
                (Some(tx), Some(rx))
            }
            EventStreamMode::Raw => (None, None),
        };

        let schema_cache = if self.detailed_events || decoded_tx.is_some() {
            Some(Mutex::new(SchemaCache::new()))
        } else {
            None
        };

        let callback_ctx_guard = CallbackContextGuard::new(CallbackContext {
            raw_sender: raw_tx,
            decoded_sender: decoded_tx,
            schema_cache,
            process_filter: normalize_process_filter(self.process_filter),
            include_thread_context: self.thread_context,
            include_stack_traces: self.stack_traces,
            include_cpu_samples: self.cpu_samples,
            dropped: AtomicU64::new(0),
        });
        let ctx_ptr = callback_ctx_guard.as_user_context_ptr();

        // Configure real-time trace consumption via OpenTraceW.
        let mut log_file = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(name_wide.as_ptr() as *mut u16),
            Anonymous1: EVENT_TRACE_LOGFILEW_0 {
                ProcessTraceMode: PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME,
            },
            Anonymous2: EVENT_TRACE_LOGFILEW_1 {
                EventRecordCallback: Some(trace_callback_fn),
            },
            Context: ctx_ptr,
            ..Default::default()
        };

        let trace_handle = unsafe { OpenTraceW(&mut log_file) };
        if trace_handle.Value == u64::MAX {
            // OpenTraceW failed — clean up the started session.
            let mut stop_buf = vec![
                0u8;
                std::mem::size_of::<EVENT_TRACE_PROPERTIES>()
                    + (MAX_SESSION_NAME_LEN * 2)
            ];
            unsafe {
                let stop_props = &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES);
                stop_props.Wnode.BufferSize = stop_buf.len() as u32;
                stop_props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
                let _ = ControlTraceW(
                    session_handle,
                    PWSTR(name_wide.as_ptr() as *mut u16),
                    stop_props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(Error::Etw(EtwError::ConsumeFailed(EtwConsumeError::new(
                Cow::Borrowed("OpenTraceW failed"),
            ))));
        }

        // Spawn background thread — ProcessTrace blocks until CloseTrace is called.
        let process_trace_handle = trace_handle;
        let process_thread = std::thread::spawn(move || unsafe {
            let handles = [process_trace_handle];
            let now = GetSystemTimeAsFileTime();
            let _ = ProcessTrace(&handles, Some(&now as *const _), None);
        });

        Ok(EventTrace {
            name: session_name,
            session_handle,
            trace_handle,
            event_rx,
            decoded_rx,
            events_processed: 0,
            started: true,
            process_thread: Some(process_thread),
            stop_signal: Wait::manual_reset(false)?,
            callback_ctx_guard,
            replaced_existing_session,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace_event(id: u16, process_id: u32) -> TraceEvent {
        const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

        let mut record = EVENT_RECORD::default();
        record.EventHeader.EventDescriptor.Id = id;
        record.EventHeader.ProviderId = GUID::zeroed();
        record.EventHeader.ProcessId = process_id;
        record.EventHeader.ThreadId = 1;
        record.EventHeader.TimeStamp = FILETIME_UNIX_EPOCH;
        record.UserDataLength = 0;
        record.UserData = std::ptr::null_mut();
        TraceEvent::from_event_record_with_fields(&record, None)
    }

    fn inert_trace(
        event_rx: Option<Receiver<TraceEvent>>,
        decoded_rx: Option<Receiver<DecodedEvent>>,
    ) -> EventTrace {
        EventTrace {
            name: "TestTrace".to_string(),
            session_handle: CONTROLTRACE_HANDLE::default(),
            trace_handle: PROCESSTRACE_HANDLE { Value: u64::MAX },
            event_rx,
            decoded_rx,
            events_processed: 0,
            started: false,
            process_thread: None,
            stop_signal: Wait::manual_reset(false).expect("wait handle create"),
            callback_ctx_guard: CallbackContextGuard::new(CallbackContext {
                raw_sender: None,
                decoded_sender: None,
                schema_cache: None,
                process_filter: None,
                include_thread_context: false,
                include_stack_traces: false,
                include_cpu_samples: false,
                dropped: AtomicU64::new(0),
            }),
            replaced_existing_session: false,
        }
    }

    #[test]
    fn test_builder_requires_provider() {
        // No provider selection → start() must fail.
        let result = EventTrace::builder("TestSession").start();
        assert!(result.is_err());
    }

    #[test]
    fn test_start_fails_when_mixing_kernel_and_user_providers() {
        let result = EventTrace::builder("TestSession")
            .system_provider(SystemProvider::Process)
            .user_provider(GUID::zeroed())
            .start();

        match result {
            Err(Error::Etw(EtwError::SessionStartFailed(e))) => {
                assert!(e.reason.contains("Cannot mix kernel system providers"));
            }
            _ => panic!("expected SessionStartFailed"),
        }
    }

    #[test]
    fn test_empty_name_fails() {
        let result = EventTrace::builder("").start();
        assert!(result.is_err());
    }

    #[test]
    fn test_name_too_long_fails() {
        let long_name = "x".repeat(MAX_SESSION_NAME_LEN + 1);
        let result = EventTrace::builder(long_name).start();

        match result {
            Err(Error::Etw(EtwError::SessionStartFailed(e))) => {
                assert!(e.reason.contains("exceeds 1024"));
            }
            _ => panic!("expected SessionStartFailed"),
        }
    }

    #[test]
    fn test_max_name_length_passes_length_validation() {
        let max_name = "x".repeat(MAX_SESSION_NAME_LEN);
        let result = EventTrace::builder(max_name).start();

        match result {
            Err(Error::Etw(EtwError::SessionStartFailed(e))) => {
                // If max length is accepted, validation proceeds to provider requirement.
                assert!(
                    e.reason
                        .contains("At least one system provider or user provider GUID")
                );
            }
            _ => panic!("expected SessionStartFailed"),
        }
    }

    #[test]
    fn test_buffer_constraint_fails() {
        let result = EventTrace::builder("Test")
            .system_provider(SystemProvider::Process)
            .min_buffers(10)
            .max_buffers(5) // invalid: min > max
            .start();
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_process_filter_empty_is_none() {
        let filter = normalize_process_filter(Vec::new());
        assert!(filter.is_none());
    }

    #[test]
    fn test_normalize_process_filter_deduplicates() {
        let filter = normalize_process_filter(vec![
            ProcessId::new(100),
            ProcessId::new(200),
            ProcessId::new(100),
        ])
        .expect("expected filter set");
        assert_eq!(filter.len(), 2);
        assert!(filter.contains(&ProcessId::new(100)));
        assert!(filter.contains(&ProcessId::new(200)));
    }

    #[test]
    fn test_extract_stack_trace_none_without_extended_data() {
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.ExtendedDataCount = 0;
        record.ExtendedData = std::ptr::null_mut();

        assert!(extract_stack_trace(&record).is_none());
    }

    #[test]
    fn test_extract_stack_trace_64bit_payload() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        payload.extend_from_slice(&0x0000_0000_0000_1111u64.to_le_bytes());
        payload.extend_from_slice(&0x0000_0000_0000_2222u64.to_le_bytes());

        let mut ext: EVENT_HEADER_EXTENDED_DATA_ITEM = unsafe { std::mem::zeroed() };
        ext.ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE64 as u16;
        ext.DataSize = payload.len() as u16;
        ext.DataPtr = payload.as_ptr() as u64;

        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.ExtendedDataCount = 1;
        record.ExtendedData = &mut ext;

        let parsed = extract_stack_trace(&record).expect("stack should parse");
        assert_eq!(parsed.match_id, 0x1122_3344_5566_7788u64);
        assert_eq!(parsed.frames, vec![0x1111, 0x2222]);
    }

    #[test]
    fn test_extract_cpu_sample_reads_processor_number() {
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        unsafe {
            *(std::ptr::addr_of_mut!(record.BufferContext) as *mut u8) = 13;
        }

        let sample = extract_cpu_sample(&record);
        assert_eq!(sample.processor_number, 13);
    }

    #[test]
    fn test_next_batch_fails_when_raw_stream_disabled() {
        let mut trace = inert_trace(None, None);
        let mut out = Vec::new();

        let result = trace.next_batch(&mut out);
        match result {
            Err(Error::Etw(EtwError::ConsumeFailed(e))) => {
                assert!(e.reason.contains("Raw event stream is disabled"));
            }
            _ => panic!("expected ConsumeFailed"),
        }
    }

    #[test]
    fn test_next_batch_decoded_fails_when_decoded_stream_disabled() {
        let mut trace = inert_trace(None, None);
        let mut out = Vec::new();

        let result = trace.next_batch_decoded(&mut out);
        match result {
            Err(Error::Etw(EtwError::ConsumeFailed(e))) => {
                assert!(e.reason.contains("Decoded event stream is disabled"));
            }
            _ => panic!("expected ConsumeFailed"),
        }
    }

    #[test]
    fn test_next_batch_drains_raw_stream_and_updates_counter() {
        let (tx, rx) = mpsc::sync_channel(8);
        tx.send(make_trace_event(1, 100)).expect("send event 1");
        tx.send(make_trace_event(2, 200)).expect("send event 2");
        drop(tx);

        let mut trace = inert_trace(Some(rx), None);
        let mut out = Vec::new();

        let count = trace
            .next_batch(&mut out)
            .expect("next_batch should succeed");
        assert_eq!(count, 2);
        assert_eq!(out.len(), 2);
        assert_eq!(trace.events_processed(), 2);
    }

    #[test]
    fn test_next_batch_with_filter_filters_during_drain() {
        let (tx, rx) = mpsc::sync_channel(8);
        tx.send(make_trace_event(1, 111)).expect("send event 1");
        tx.send(make_trace_event(2, 222)).expect("send event 2");
        tx.send(make_trace_event(3, 333)).expect("send event 3");
        drop(tx);

        let mut trace = inert_trace(Some(rx), None);
        let mut out = Vec::new();

        let count = trace
            .next_batch_with_filter(&mut out, |e| e.process_id != 222)
            .expect("next_batch_with_filter should succeed");

        assert_eq!(count, 2);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|e| e.process_id != 222));
        assert_eq!(trace.events_processed(), 2);
    }

    #[test]
    fn test_next_batch_decoded_drains_stream_and_updates_counter() {
        let (tx, rx) = mpsc::sync_channel(8);
        tx.send(DecodedEvent::Unknown)
            .expect("send decoded event 1");
        tx.send(DecodedEvent::Unknown)
            .expect("send decoded event 2");
        drop(tx);

        let mut trace = inert_trace(None, Some(rx));
        let mut out = Vec::new();

        let count = trace
            .next_batch_decoded(&mut out)
            .expect("next_batch_decoded should succeed");

        assert_eq!(count, 2);
        assert_eq!(out.len(), 2);
        assert_eq!(trace.events_processed(), 2);
    }

    #[test]
    fn test_next_batch_timeout_blocks_then_drains_batch() {
        let (tx, rx) = mpsc::sync_channel(8);
        tx.send(make_trace_event(1, 100)).expect("send event 1");
        tx.send(make_trace_event(2, 200)).expect("send event 2");
        drop(tx);

        let mut trace = inert_trace(Some(rx), None);
        let mut out = Vec::new();

        let count = trace
            .next_batch_timeout(&mut out, Duration::from_millis(50))
            .expect("next_batch_timeout should succeed");
        assert_eq!(count, 2);
        assert_eq!(trace.events_processed(), 2);
    }

    #[test]
    fn test_next_batch_timeout_returns_zero_on_timeout() {
        let (_tx, rx) = mpsc::sync_channel::<TraceEvent>(8);
        let mut trace = inert_trace(Some(rx), None);
        let mut out = Vec::new();

        let count = trace
            .next_batch_timeout(&mut out, Duration::from_millis(20))
            .expect("next_batch_timeout should succeed on timeout");
        assert_eq!(count, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn test_next_batch_timeout_returns_zero_when_disconnected() {
        let (tx, rx) = mpsc::sync_channel::<TraceEvent>(8);
        drop(tx);
        let mut trace = inert_trace(Some(rx), None);
        let mut out = Vec::new();

        let count = trace
            .next_batch_timeout(&mut out, Duration::from_millis(20))
            .expect("next_batch_timeout should succeed when disconnected");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_kernel_session_config_none_without_kernel_providers() {
        assert!(kernel_session_config("MySession", false, None).is_none());
        assert!(kernel_session_config("MySession", false, Some(GUID::from_u128(1))).is_none());
    }

    #[test]
    fn test_kernel_session_config_defaults_to_shared_kernel_logger() {
        let config = kernel_session_config("MySession", true, None)
            .expect("kernel providers should produce a config");
        assert_eq!(config.session_name, KERNEL_LOGGER_NAME);
        assert_eq!(config.log_file_mode, EVENT_TRACE_REAL_TIME_MODE);
        assert_eq!(config.wnode_guid, GUID::zeroed());
    }

    #[test]
    fn test_kernel_session_config_private_logger_keeps_name_and_sets_mode_and_guid() {
        let guid = GUID::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0);
        let config = kernel_session_config("MyPrivateSession", true, Some(guid))
            .expect("kernel providers should produce a config");

        assert_eq!(config.session_name, "MyPrivateSession");
        assert_ne!(config.session_name, KERNEL_LOGGER_NAME);
        assert_eq!(
            config.log_file_mode,
            EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE
        );
        assert_ne!(config.log_file_mode & EVENT_TRACE_SYSTEM_LOGGER_MODE, 0);
        assert_eq!(config.wnode_guid, guid);
        assert_ne!(config.wnode_guid, GUID::zeroed());
    }

    #[test]
    fn test_inert_trace_reports_not_running_and_no_drops() {
        let trace = inert_trace(None, None);
        assert!(!trace.is_running());
        assert!(!trace.replaced_existing_session());
        assert_eq!(trace.events_dropped(), 0);
    }
}
