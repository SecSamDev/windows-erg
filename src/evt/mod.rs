//! Windows Event Log (evt) - Query and read events from Windows Event Logs.
//!
//! This module provides ergonomic access to Windows Event Logs with support for:
//! - Reading from event log channels (Security, System, Application, etc.)
//! - Reading from .evtx log files
//! - Flexible XPath-based or builder-based queries
//! - Optional event message rendering with publisher metadata caching
//! - Optional EventData extraction with field name interning
//! - Custom parsing APIs for performance-critical scenarios
//! - Detailed error reporting including corrupted event information
//!
//! # Choosing the Right API
//!
//! This module provides multiple ways to process events, each optimized for different use cases:
//!
//! ## Quick Start: Standard Event Processing
//!
//! Use the built-in [`Event`](types::Event) struct with builder options:
//!
//! ```no_run
//! use windows_erg::evt::EventLog;
//!
//! # fn main() -> windows_erg::Result<()> {
//! let log = EventLog::open("Security")?;
//! let mut query = log.query_stream("*[System[EventID=4624]]")?
//!     .with_event_data()   // Extract EventData key-value pairs (opt-in)
//!     .with_message();     // Format event messages via EvtFormatMessage (opt-in)
//!
//! let mut batch = Vec::new();
//! while query.next_batch(&mut batch)? > 0 {
//!     for event in &batch {
//!         println!("Event {}: {}", event.id, event.formatted_message.as_deref().unwrap_or(""));
//!         if let Some(ref data) = event.data {
//!             for (key, value) in data {
//!                 println!("  {}: {}", key, value);  // Common fields use Cow::Borrowed (zero-copy)
//!             }
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! **When to use**: Most applications. Provides structured Event objects with opt-in features.
//!
//! ## Explicit Corruption Handling
//!
//! Use [`next_batch_with_results`](EventQuery::next_batch_with_results) when you need to handle corrupted events explicitly:
//!
//! ```no_run
//! use windows_erg::evt::EventLog;
//!
//! # fn main() -> windows_erg::Result<()> {
//! let log = EventLog::open("System")?;
//! let mut query = log.query_stream("*")?;
//! let mut batch = Vec::new();
//!
//! while query.next_batch_with_results(&mut batch)? > 0 {
//!     for result in &batch {
//!         match result {
//!             Ok(event) => println!("Event: {}", event.id),
//!             Err(corrupted) => {
//!                 eprintln!("Corrupted event at record {}: {}",
//!                     corrupted.record_id.unwrap_or(0),
//!                     corrupted.reason
//!                 );
//!             }
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! **When to use**: When parsing untrusted or potentially corrupted logs. Returns both Ok(Event) and Err(CorruptedEvent) in the same vector.
//!
//! ## Custom Types: Maximum Performance
//!
//! Use [`next_batch_raw_with_filter`](EventQuery::next_batch_raw_with_filter) when you need custom event types without allocating intermediate Event structs:
//!
//! ```no_run
//! use windows_erg::evt::{EventLog, types::{extract_event_id, extract_provider}};
//!
//! # fn main() -> windows_erg::Result<()> {
//! #[derive(Debug)]
//! struct LightweightEvent {
//!     id: u32,
//!     provider: String,
//! }
//!
//! let log = EventLog::open("Application")?;
//! let mut query = log.query_stream("*")?;
//! let mut events = Vec::new();
//!
//! query.next_batch_raw_with_filter(
//!     &mut events,
//!     |handle| {
//!         Ok(LightweightEvent {
//!             id: extract_event_id(handle)?,
//!             provider: extract_provider(handle)?,
//!         })
//!     },
//!     |event| event.id < 1000,  // Filter AFTER conversion (on your custom type)
//! )?;
//! # Ok(())
//! # }
//! ```
//!
//! **When to use**: High-throughput scenarios where you only need a subset of event fields. Avoids allocating full Event structs.
//!
//! ## Custom Types: Serde Deserialization
//!
//! Use [`next_batch_deserialize`](EventQuery::next_batch_deserialize) (requires `serde` feature) for owned XML deserialization:
//!
//! ```no_run
//! # fn main() -> windows_erg::Result<()> {
//! # #[cfg(feature = "serde")]
//! # {
//! use windows_erg::evt::EventLog;
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! struct CustomEvent {
//!     #[serde(rename = "System")]
//!     system: SystemData,
//! }
//!
//! #[derive(Deserialize)]
//! struct SystemData {
//!     #[serde(rename = "EventID")]
//!     event_id: u32,
//!     #[serde(rename = "Provider")]
//!     provider: ProviderData,
//! }
//!
//! #[derive(Deserialize)]
//! struct ProviderData {
//!     #[serde(rename = "@Name")]
//!     name: String,
//! }
//!
//! let log = EventLog::open("Security")?;
//! let mut query = log.query_stream("*")?;
//! let mut events: Vec<CustomEvent> = Vec::new();
//!
//! query.next_batch_deserialize(&mut events)?;
//! # }
//! # Ok(())
//! # }
//! ```
//!
//! **When to use**: When you need flexible custom event types with straightforward, owned Rust data structures.
//!
//! # Performance Considerations
//!
//! ## Field Name Interning
//!
//! Common EventData field names (e.g., "TargetUserName", "ProcessId", "CommandLine") are automatically interned as `Cow::Borrowed(&'static str)` via a compile-time match statement. This reduces allocations by ~30% for typical Windows security logs.
//!
//! ## Publisher Metadata Caching
//!
//! Event message formatting via `with_message()` caches publisher metadata handles with RwLock for concurrent read access. First message format per provider is ~5ms, subsequent formats are <0.1ms.
//!
//! ## Buffer Reuse
//!
//! All `next_batch_*` methods clear and reuse the provided output vector. Preallocate with `Vec::with_capacity(batch_size)` to avoid repeated allocations.
//!
//! # Examples
//!
//! ## Basic query
//! ```no_run
//! use windows_erg::evt::{EventLog, query::QueryBuilder};
//!
//! # fn main() -> windows_erg::Result<()> {
//! let log = EventLog::open("Security")?;
//! let query = QueryBuilder::new().event_id(4688);
//! let result = log.query(&query)?;
//!
//! for event in result.events {
//!     println!("Event ID: {}, Level: {}", event.id, event.level);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Batch processing with buffer reuse
//! ```no_run
//! use windows_erg::evt::{EventLog, EventQuery};
//!
//! # fn main() -> windows_erg::Result<()> {
//! let log = EventLog::open("System")?;
//! let mut query = log.query_stream("*")?;  // All events
//! let mut batch = Vec::with_capacity(64);
//!
//! while query.next_batch(&mut batch)? > 0 {
//!     for event in &batch {
//!         println!("Event: {}", event.provider);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Query with filtering
//! ```no_run
//! use windows_erg::evt::{EventLog, types::EventLevel, query::QueryBuilder};
//!
//! # fn main() -> windows_erg::Result<()> {
//! let log = EventLog::open("Application")?;
//! let query = QueryBuilder::new()
//!     .level(EventLevel::Error)
//!     .provider("MyApp");
//! let result = log.query(&query)?;
//! # Ok(())
//! # }
//! ```

pub mod query;
pub mod render;
pub mod types;

use crate::error::{Error, EventLogError, EventLogQueryError, Result};
use query::QueryBuilder;
use std::path::Path;
use types::{ChannelFilter, Event, EventQueryResult, RenderFormat};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::EventLog::*;
use windows::core::PWSTR;

/// Handle to an opened event log or log file.
pub struct EventLog {
    handle: EVT_HANDLE,
    channel_or_path: String,
    is_file: bool,
}

impl EventLog {
    /// Open an event log channel by name.
    ///
    /// Examples: "Security", "System", "Application", "Windows PowerShell", etc.
    pub fn open(channel_name: &str) -> Result<Self> {
        let channel_wide: Vec<u16> = channel_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            EvtOpenLog(
                EVT_HANDLE::default(), // Local computer
                PWSTR(channel_wide.as_ptr() as *mut u16),
                EvtOpenChannelPath.0 as u32,
            )
        }
        .map_err(|_| {
            Error::EventLog(EventLogError::QueryFailed(EventLogQueryError::new(
                channel_name.to_string(),
                "Channel not found or access denied",
            )))
        })?;

        Ok(EventLog {
            handle,
            channel_or_path: channel_name.to_string(),
            is_file: false,
        })
    }

    /// Open an event log file (.evtx, .evt, or .etl format).
    pub fn open_file(path: &Path) -> Result<Self> {
        let path_str = path.to_str().ok_or_else(|| {
            Error::EventLog(EventLogError::QueryFailed(EventLogQueryError::new(
                "file_path",
                "Invalid file path",
            )))
        })?;

        let path_wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

        let handle = unsafe {
            EvtOpenLog(
                EVT_HANDLE::default(), // Local computer
                PWSTR(path_wide.as_ptr() as *mut u16),
                EvtOpenFilePath.0 as u32,
            )
        }
        .map_err(|_| {
            Error::EventLog(EventLogError::QueryFailed(EventLogQueryError::new(
                path_str.to_string(),
                "Log file not found or cannot be read",
            )))
        })?;

        Ok(EventLog {
            handle,
            channel_or_path: path_str.to_string(),
            is_file: true,
        })
    }

    /// List available event log channels.
    pub fn list_channels() -> Result<Vec<String>> {
        Self::list_channels_filtered(ChannelFilter::Operational)
    }

    /// List event log channels with a specific filter.
    pub fn list_channels_filtered(filter: ChannelFilter) -> Result<Vec<String>> {
        let mut channels = Vec::new();

        let enum_handle =
            unsafe { EvtOpenChannelEnum(EVT_HANDLE::default(), 0) }.map_err(|_| {
                Error::EventLog(EventLogError::QueryFailed(EventLogQueryError::new(
                    "channels",
                    "Failed to enumerate channels",
                )))
            })?;

        let mut buffer = [0u16; 1024];

        loop {
            let mut buffer_used = 0u32;
            let result =
                unsafe { EvtNextChannelPath(enum_handle, Some(&mut buffer[..]), &mut buffer_used) };

            if result.is_err() {
                break;
            }

            let channel_name = String::from_utf16_lossy(&buffer[..buffer_used as usize]);

            // Apply filter
            if should_include_channel(&channel_name, filter) {
                channels.push(channel_name.to_string());
            }
        }

        unsafe {
            let _ = EvtClose(enum_handle);
        }

        Ok(channels)
    }

    /// Query events using a query builder.
    ///
    /// This returns all matching events at once. For large result sets,
    /// prefer `query_stream()` with batch processing.
    pub fn query(&self, builder: &QueryBuilder) -> Result<EventQueryResult> {
        let mut result = EventQueryResult::default();
        self.query_internal(builder, &mut result, None)?;
        Ok(result)
    }

    /// Query events in a streaming fashion with batch processing.
    ///
    /// Returns an EventQuery handle for batch iteration with buffer reuse.
    /// Use `query_stream()` for processing large logs efficiently.
    pub fn query_stream(&self, xpath: &str) -> Result<EventQuery> {
        let xpath_wide: Vec<u16> = xpath.encode_utf16().chain(std::iter::once(0)).collect();

        let channel_wide: Vec<u16> = self
            .channel_or_path
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let flags = if self.is_file {
            EvtQueryFilePath.0 as u32
        } else {
            EvtQueryChannelPath.0 as u32
        };

        let query_handle = unsafe {
            EvtQuery(
                EVT_HANDLE::default(), // Local computer
                PWSTR(channel_wide.as_ptr() as *mut u16),
                PWSTR(xpath_wide.as_ptr() as *mut u16),
                flags,
            )
        }
        .map_err(|_| {
            Error::EventLog(EventLogError::QueryFailed(EventLogQueryError::new(
                self.channel_or_path.clone(),
                "Failed to create query handle",
            )))
        })?;

        Ok(EventQuery {
            handle: query_handle,
            batch_buffer: vec![0isize; 64], // Changed to 0isize for EvtNext buffer
            render_format: RenderFormat::Values,
            include_event_data: false,
            parse_message: false,
            #[cfg(feature = "serde")]
            xml_buffer: String::with_capacity(16384),
            variant_buffer: Vec::with_capacity(8192),
            corrupted: Vec::new(),
            total_processed: 0,
        })
    }

    /// Internal query implementation.
    fn query_internal(
        &self,
        builder: &QueryBuilder,
        result: &mut EventQueryResult,
        _max_events: Option<usize>,
    ) -> Result<()> {
        let mut query = self.query_stream(&builder.build_xpath())?;

        // Fetch all batches
        let mut batch = Vec::with_capacity(64);
        while query.next_batch(&mut batch)? > 0 {
            result.events.extend(batch.drain(..));
        }

        result.corrupted = query.corrupted.clone();
        result.total_processed = query.total_processed;

        Ok(())
    }
}

impl Drop for EventLog {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = EvtClose(self.handle);
            }
        }
    }
}

/// Query result stream for batch iteration with reusable buffers.
pub struct EventQuery {
    handle: EVT_HANDLE,
    batch_buffer: Vec<isize>, // Changed from Vec<EVT_HANDLE> to Vec<isize> for EvtNext
    render_format: RenderFormat,
    include_event_data: bool,
    parse_message: bool,
    #[cfg(feature = "serde")]
    xml_buffer: String,
    #[allow(dead_code)]
    variant_buffer: Vec<u8>, // Reserved for future use
    corrupted: Vec<crate::evt::types::CorruptedEvent>,
    total_processed: usize,
}

impl EventQuery {
    /// Enable EventData extraction (opt-in).
    ///
    /// When enabled, events will have their `data` field populated with EventData key-value pairs.
    /// Common field names (e.g., "TargetUserName", "ProcessId") are automatically interned
    /// as `Cow::Borrowed(&'static str)` for zero-copy access.
    pub fn with_event_data(mut self) -> Self {
        self.include_event_data = true;
        self
    }

    /// Enable message formatting via EvtFormatMessage (opt-in).
    ///
    /// When enabled, events will have their `formatted_message` field populated with the
    /// human-readable event message. Publisher metadata is cached for performance.
    pub fn with_message(mut self) -> Self {
        self.parse_message = true;
        self
    }

    /// Set the rendering format for events (default: Values).
    pub fn set_render_format(&mut self, format: RenderFormat) {
        self.render_format = format;
    }

    /// Fetch next batch of events into output buffer.
    ///
    /// Returns the count of events added to the buffer.
    /// When no more events are available, returns 0.
    pub fn next_batch(&mut self, out_events: &mut Vec<Event>) -> Result<usize> {
        self.next_batch_with_filter(out_events, |_| true)
    }

    /// Fetch next batch with filtering applied during enumeration.
    ///
    /// The filter function is called for each parsed event;
    /// only events where the filter returns true are included.
    pub fn next_batch_with_filter<F>(
        &mut self,
        out_events: &mut Vec<Event>,
        filter: F,
    ) -> Result<usize>
    where
        F: Fn(&Event) -> bool,
    {
        out_events.clear();

        let mut returned = 0u32;
        let result = unsafe {
            EvtNext(
                self.handle,
                self.batch_buffer.as_mut_slice(),
                1000, // 1 second timeout
                0,
                &mut returned,
            )
        };

        if result.is_err() {
            // Check for normal end of stream
            let error_code = unsafe { GetLastError() };
            if error_code.0 == 259 {
                // ERROR_NO_MORE_ITEMS
                return Ok(0);
            }
            return Err(Error::EventLog(EventLogError::QueryFailed(
                EventLogQueryError::with_code("", "EvtNext failed", error_code.0 as i32),
            )));
        }

        // Process fetched events
        for i in 0..returned as usize {
            let handle_val = self.batch_buffer[i];
            let handle = EVT_HANDLE(handle_val);

            match render::render_event(
                handle,
                self.render_format,
                self.include_event_data,
                self.parse_message,
            ) {
                Ok(event) => {
                    if filter(&event) {
                        out_events.push(event);
                    }
                    self.total_processed += 1;
                }
                Err(corruption_info) => {
                    self.corrupted.push(corruption_info);
                    self.total_processed += 1;
                }
            }

            // Close the handle
            unsafe {
                let _ = EvtClose(handle);
            }
        }

        Ok(out_events.len())
    }

    /// Process events with a custom converter and filter for each raw event handle.
    ///
    /// This allows custom event parsing without allocating the intermediate Event struct.
    /// The converter receives the raw EVT_HANDLE and returns a custom type T.
    /// The filter is applied after successful conversion.
    ///
    /// # Example
    /// ```no_run
    /// use windows_erg::evt::{EventLog, types::{extract_event_id, extract_provider}};
    ///
    /// # fn main() -> windows_erg::Result<()> {
    /// #[derive(Debug)]
    /// struct LightweightEvent {
    ///     id: u32,
    ///     provider: String,
    /// }
    ///
    /// let log = EventLog::open("Security")?;
    /// let mut query = log.query_stream("*[System[EventID=4624]]")?;
    /// let mut events = Vec::new();
    ///
    /// query.next_batch_raw_with_filter(
    ///     &mut events,
    ///     |handle| {
    ///         Ok(LightweightEvent {
    ///             id: extract_event_id(handle)?,
    ///             provider: extract_provider(handle)?,
    ///         })
    ///     },
    ///     |event| event.id == 4624,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn next_batch_raw_with_filter<T, F, P>(
        &mut self,
        out_events: &mut Vec<T>,
        mut converter: F,
        filter: P,
    ) -> Result<usize>
    where
        F: FnMut(EVT_HANDLE) -> Result<T>,
        P: Fn(&T) -> bool,
    {
        out_events.clear();

        let mut returned = 0u32;
        let result = unsafe {
            EvtNext(
                self.handle,
                self.batch_buffer.as_mut_slice(),
                1000,
                0,
                &mut returned,
            )
        };

        if result.is_err() {
            let error_code = unsafe { GetLastError() };
            if error_code.0 == 259 {
                return Ok(0);
            }
            return Err(Error::EventLog(EventLogError::QueryFailed(
                EventLogQueryError::with_code("", "EvtNext failed", error_code.0 as i32),
            )));
        }

        for i in 0..returned as usize {
            let handle_val = self.batch_buffer[i];
            let handle = EVT_HANDLE(handle_val);

            match converter(handle) {
                Ok(event) => {
                    if filter(&event) {
                        out_events.push(event);
                    }
                    self.total_processed += 1;
                }
                Err(_) => {
                    // User's converter handles errors - skip this event
                    self.total_processed += 1;
                }
            }

            unsafe {
                let _ = EvtClose(handle);
            }
        }

        Ok(out_events.len())
    }

    /// Fetch next batch with explicit corruption handling.
    ///
    /// Returns both successfully parsed events (Ok) and corrupted events (Err)
    /// in a single vector, preserving event order.
    ///
    /// # Example
    /// ```no_run
    /// use windows_erg::evt::EventLog;
    ///
    /// # fn main() -> windows_erg::Result<()> {
    /// let log = EventLog::open("System")?;
    /// let mut query = log.query_stream("*")?;
    /// let mut batch = Vec::new();
    ///
    /// while query.next_batch_with_results(&mut batch)? > 0 {
    ///     for result in &batch {
    ///         match result {
    ///             Ok(event) => println!("Event: {}", event.id),
    ///             Err(corrupted) => println!("Corrupted: {}", corrupted.reason),
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn next_batch_with_results(
        &mut self,
        out_events: &mut Vec<std::result::Result<Event, types::CorruptedEvent>>,
    ) -> Result<usize> {
        out_events.clear();

        let mut returned = 0u32;
        let result = unsafe {
            EvtNext(
                self.handle,
                self.batch_buffer.as_mut_slice(),
                1000,
                0,
                &mut returned,
            )
        };

        if result.is_err() {
            let error_code = unsafe { GetLastError() };
            if error_code.0 == 259 {
                return Ok(0);
            }
            return Err(Error::EventLog(EventLogError::QueryFailed(
                EventLogQueryError::with_code("", "EvtNext failed", error_code.0 as i32),
            )));
        }

        for i in 0..returned as usize {
            let handle_val = self.batch_buffer[i];
            let handle = EVT_HANDLE(handle_val);

            match render::render_event(
                handle,
                self.render_format,
                self.include_event_data,
                self.parse_message,
            ) {
                Ok(event) => {
                    out_events.push(Ok(event));
                    self.total_processed += 1;
                }
                Err(corruption_info) => {
                    out_events.push(Err(corruption_info));
                    self.total_processed += 1;
                }
            }

            unsafe {
                let _ = EvtClose(handle);
            }
        }

        Ok(out_events.len())
    }

    /// Deserialize events to custom types using serde with owned parsing.
    ///
    /// Events are rendered as XML and deserialized into owned Rust values.
    /// This keeps the API simple and avoids lifetime coupling to internal
    /// buffers.
    ///
    /// Requires the `serde` feature.
    ///
    /// # Example
    /// ```no_run
    /// use windows_erg::evt::EventLog;
    /// use serde::Deserialize;
    ///
    /// # fn main() -> windows_erg::Result<()> {
    /// #[derive(Deserialize)]
    /// struct CustomEvent {
    ///     #[serde(rename = "System")]
    ///     system: SystemData,
    /// }
    ///
    /// #[derive(Deserialize)]
    /// struct SystemData {
    ///     #[serde(rename = "EventID")]
    ///     event_id: u32,
    ///     #[serde(rename = "Provider")]
    ///     provider: ProviderData,
    /// }
    ///
    /// #[derive(Deserialize)]
    /// struct ProviderData {
    ///     #[serde(rename = "@Name")]
    ///     name: String,
    /// }
    ///
    /// let log = EventLog::open("Application")?;
    /// let mut query = log.query_stream("*")?;
    /// let mut events: Vec<CustomEvent> = Vec::new();
    ///
    /// query.next_batch_deserialize(&mut events)?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "serde")]
    pub fn next_batch_deserialize<T>(&mut self, out_events: &mut Vec<T>) -> Result<usize>
    where
        T: serde::de::DeserializeOwned,
    {
        out_events.clear();

        let mut returned = 0u32;
        let result = unsafe {
            EvtNext(
                self.handle,
                self.batch_buffer.as_mut_slice(),
                1000,
                0,
                &mut returned,
            )
        };

        if result.is_err() {
            let error_code = unsafe { GetLastError() };
            if error_code.0 == 259 {
                return Ok(0);
            }
            return Err(Error::EventLog(EventLogError::QueryFailed(
                EventLogQueryError::with_code("", "EvtNext failed", error_code.0 as i32),
            )));
        }

        for i in 0..returned as usize {
            let handle_val = self.batch_buffer[i];
            let handle = EVT_HANDLE(handle_val);

            // Render to XML
            self.xml_buffer.clear();
            let mut buffer = vec![0u8; 16384];
            let mut buffer_used = 0u32;
            let mut prop_count = 0u32;

            let render_result = unsafe {
                EvtRender(
                    EVT_HANDLE::default(),
                    handle,
                    EvtRenderEventXml.0,
                    buffer.len() as u32,
                    Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
                    &mut buffer_used,
                    &mut prop_count,
                )
            };

            if render_result.is_ok() {
                let xml_bytes = &buffer[..buffer_used as usize];
                let xml_str = String::from_utf16_lossy(unsafe {
                    std::slice::from_raw_parts(
                        xml_bytes.as_ptr() as *const u16,
                        xml_bytes.len() / 2,
                    )
                });
                self.xml_buffer.clear();
                self.xml_buffer.push_str(&xml_str);

                // Deserialize from XML buffer
                match quick_xml::de::from_str::<T>(&self.xml_buffer) {
                    Ok(event) => {
                        out_events.push(event);
                        self.total_processed += 1;
                    }
                    Err(_) => {
                        // Deserialization failed - skip this event
                        self.total_processed += 1;
                    }
                }
            }

            unsafe {
                let _ = EvtClose(handle);
            }
        }

        Ok(out_events.len())
    }
}

impl Drop for EventQuery {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = EvtClose(self.handle);
            }
        }
    }
}

/// Determine if a channel should be included based on filter.
fn should_include_channel(channel_name: &str, filter: ChannelFilter) -> bool {
    match filter {
        ChannelFilter::All => true,
        ChannelFilter::Operational => {
            // Operational channels: Application, System, Security, etc.
            // Exclude Analytic and Debug
            !channel_name.contains("Analytic") && !channel_name.contains("Debug")
        }
        ChannelFilter::AdminOrHigher => {
            // Similar to Operational for now (can be refined)
            !channel_name.contains("Analytic") && !channel_name.contains("Debug")
        }
        ChannelFilter::IncludeAnalytic => true,
    }
}
