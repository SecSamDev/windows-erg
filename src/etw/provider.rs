//! Writing events as a manifest-based ETW provider.
//!
//! [`EventProvider::register`] registers the provider GUID declared in an
//! instrumentation manifest; [`EventProvider::write`] writes one event with
//! the descriptor and field values that manifest declares. Once the manifest
//! is installed (`wevtutil im`, or an installer), events routed to a channel
//! show up in the Event Log under that channel.
//!
//! Registering does not need the manifest: without it, or with nobody
//! listening, `write` succeeds and the event goes nowhere. That keeps a
//! development run working without an installed manifest.
//!
//! # Example
//!
//! ```no_run
//! use windows_erg::etw::{EventData, EventDescriptor, EventProvider, GUID};
//!
//! let provider = EventProvider::register(&GUID::from_u128(0x1234))?;
//! let started = EventDescriptor { id: 1, level: 4, ..EventDescriptor::default() };
//! provider.write(&started, &[EventData::U64(42), EventData::Str("ok")])?;
//! # Ok::<(), windows_erg::Error>(())
//! ```

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    EVENT_DATA_DESCRIPTOR, EVENT_DESCRIPTOR, EventRegister, EventUnregister, EventWrite, REGHANDLE,
};
use windows::core::GUID;

use crate::error::{Error, Result, WindowsApiError};

/// The manifest's description of one event: id, version, channel, level,
/// opcode, task and keyword, as `mc.exe` assigns them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventDescriptor {
    /// Event id (`value` in the manifest).
    pub id: u16,
    /// Event version.
    pub version: u8,
    /// Channel value, as `mc.exe` numbers the manifest's channels.
    pub channel: u8,
    /// Level: 1 critical, 2 error, 3 warning, 4 informational, 5 verbose.
    pub level: u8,
    /// Opcode (0 for `win:Info`).
    pub opcode: u8,
    /// Task value.
    pub task: u16,
    /// Keyword mask; the high byte carries the channel bit `mc.exe` assigns.
    pub keyword: u64,
}

/// One field of an event, in manifest order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EventData<'a> {
    /// `win:UInt32`.
    U32(u32),
    /// `win:UInt64`.
    U64(u64),
    /// `win:Float`.
    F32(f32),
    /// `win:UnicodeString` (written NUL-terminated UTF-16).
    Str(&'a str),
}

impl EventData<'_> {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::U32(v) => v.to_le_bytes().to_vec(),
            Self::U64(v) => v.to_le_bytes().to_vec(),
            Self::F32(v) => v.to_le_bytes().to_vec(),
            Self::Str(s) => s
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }
}

/// A registered ETW provider, unregistered on drop.
#[derive(Debug)]
pub struct EventProvider {
    handle: REGHANDLE,
}

impl EventProvider {
    /// Register `provider` for writing.
    pub fn register(provider: &GUID) -> Result<Self> {
        let mut handle = 0u64;
        // SAFETY: `provider` is a valid GUID for the call; no enable
        // callback; `handle` receives the registration handle.
        let status = unsafe { EventRegister(provider, None, None, &mut handle) };
        win32(status, "EventRegister")?;
        Ok(Self {
            handle: REGHANDLE(handle as i64),
        })
    }

    /// Write one event. A provider nobody listens to accepts the event and
    /// drops it; this only fails on a malformed event (too large, too many
    /// fields) or an ETW buffer shortage.
    pub fn write(&self, descriptor: &EventDescriptor, fields: &[EventData<'_>]) -> Result<()> {
        let encoded: Vec<Vec<u8>> = fields.iter().map(EventData::encode).collect();
        let data: Vec<EVENT_DATA_DESCRIPTOR> = encoded
            .iter()
            .map(|bytes| EVENT_DATA_DESCRIPTOR {
                Ptr: bytes.as_ptr() as u64,
                Size: bytes.len() as u32,
                ..Default::default()
            })
            .collect();
        let descriptor = EVENT_DESCRIPTOR {
            Id: descriptor.id,
            Version: descriptor.version,
            Channel: descriptor.channel,
            Level: descriptor.level,
            Opcode: descriptor.opcode,
            Task: descriptor.task,
            Keyword: descriptor.keyword,
        };
        // SAFETY: `self.handle` is a live registration; every data
        // descriptor points into `encoded`, which outlives the call.
        let status = unsafe {
            EventWrite(
                self.handle,
                &descriptor,
                (!data.is_empty()).then_some(data.as_slice()),
            )
        };
        win32(status, "EventWrite")
    }
}

impl Drop for EventProvider {
    fn drop(&mut self) {
        // SAFETY: the handle came from EventRegister and is unregistered
        // exactly once.
        let _ = unsafe { EventUnregister(self.handle) };
    }
}

fn win32(status: u32, api: &'static str) -> Result<()> {
    if status == 0 {
        return Ok(());
    }
    let error = windows::core::Error::from_hresult(WIN32_ERROR(status).to_hresult());
    Err(Error::WindowsApi(WindowsApiError::with_context(error, api)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_without_a_manifest_or_listener() {
        let provider =
            EventProvider::register(&GUID::from_u128(0x6b1f_0c2e_8d4a_4f7b_9e3a_5c2d_1b0a_9f8e))
                .unwrap();
        let descriptor = EventDescriptor {
            id: 1000,
            level: 4,
            ..EventDescriptor::default()
        };
        provider
            .write(
                &descriptor,
                &[
                    EventData::U64(7),
                    EventData::U32(3),
                    EventData::F32(0.5),
                    EventData::Str("ransomware"),
                ],
            )
            .unwrap();
        provider.write(&descriptor, &[]).unwrap();
    }

    #[test]
    fn strings_are_nul_terminated_utf16() {
        assert_eq!(EventData::Str("ab").encode(), vec![b'a', 0, b'b', 0, 0, 0]);
        assert_eq!(EventData::U32(1).encode(), vec![1, 0, 0, 0]);
    }
}
