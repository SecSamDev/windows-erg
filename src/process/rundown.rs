//! System-wide process snapshot via `NtQuerySystemInformation`.
//!
//! [`Process::list`] (Toolhelp32) enumerates every running process but not
//! their creation times. [`Process::snapshot`] uses the undocumented but
//! stable `SYSTEM_PROCESS_INFORMATION` layout instead, which carries each
//! process's creation time and parent PID in one call. This is the source
//! for a process *rundown*: reconstructing what was already running before
//! an observer (e.g. an ETW session) started, so that no window is blind at
//! the moment collection begins.
//!
//! ## Field layout
//!
//! Microsoft has never published `SYSTEM_PROCESS_INFORMATION`; windows-rs's
//! binding (`windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION`)
//! reflects that by typing several fields as opaque reserved bytes rather
//! than by name. The real, widely-documented (via the Windows driver kit and
//! tools such as Process Hacker) layout packs, in order:
//!
//! - `Reserved1: [u8; 48]` = `WorkingSetPrivateSize: i64`, `HardFaultCount: u32`,
//!   `NumberOfThreadsHighWatermark: u32`, `CycleTime: u64`, `CreateTime: i64`,
//!   `UserTime: i64`, `KernelTime: i64` (8+4+4+8+8+8+8 = 48 bytes). `CreateTime`
//!   is therefore bytes `24..32` of `Reserved1`, as a `FILETIME`-form `i64`.
//! - `Reserved2: *mut c_void` = `InheritedFromUniqueProcessId` (the parent PID,
//!   stored as a `HANDLE`-shaped value the same way `UniqueProcessId` is).

use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
use windows::Win32::Foundation::STATUS_INFO_LENGTH_MISMATCH;
use windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

use super::processes::Process;
use super::types::ProcessId;
use crate::error::{Error, ProcessError, ProcessOpenError, Result};

/// Byte offset of `CreateTime` within `SYSTEM_PROCESS_INFORMATION::Reserved1`.
/// See the module doc for the derivation.
const CREATE_TIME_OFFSET: usize = 24;

/// One process entry from a full-system snapshot ([`Process::snapshot`]).
#[derive(Debug, Clone)]
pub struct ProcessSnapshotEntry {
    /// Process ID.
    pub pid: ProcessId,
    /// Parent process ID, if any (the System Idle Process and PID 4's parent
    /// slot are typically absent or already exited).
    pub parent_pid: Option<ProcessId>,
    /// Process creation time, in Windows FILETIME units (100ns intervals
    /// since 1601-01-01 UTC) — the same unit `GetProcessTimes` and ETW
    /// timestamps use.
    pub create_time: u64,
    /// Terminal Services session ID.
    pub session_id: u32,
    /// Short image name (e.g. `"lsass.exe"`), decoded from the kernel's
    /// `UNICODE_STRING`. Empty for the System Idle Process (PID 0).
    pub image_name: String,
}

impl Process {
    /// Snapshot every process currently running on the system.
    ///
    /// Unlike [`Process::list`], each entry carries a real creation time and
    /// does not require enumerating twice to find a parent. Retries with a
    /// larger buffer on `STATUS_INFO_LENGTH_MISMATCH`, since the process
    /// list can grow between the sizing attempt and a successful read.
    pub fn snapshot() -> Result<Vec<ProcessSnapshotEntry>> {
        let mut buffer = Vec::with_capacity(256);
        Self::snapshot_with_buffer(&mut buffer)?;
        Ok(buffer)
    }

    /// Snapshot every process using a reusable output buffer.
    ///
    /// Returns the number of entries found and added to `out`.
    pub fn snapshot_with_buffer(out: &mut Vec<ProcessSnapshotEntry>) -> Result<usize> {
        out.clear();

        let raw = query_system_process_information()?;
        parse_system_process_information(&raw, out);
        Ok(out.len())
    }
}

/// Call `NtQuerySystemInformation(SystemProcessInformation)`, growing the
/// buffer until the call succeeds.
fn query_system_process_information() -> Result<Vec<u8>> {
    let mut size: u32 = 1 << 20; // 1 MiB: comfortably fits a normal process count.
    let mut raw: Vec<u8> = vec![0; size as usize];

    loop {
        raw.resize(size as usize, 0);
        let mut return_length: u32 = 0;

        // SAFETY: `raw` is a `size`-byte buffer that outlives the call, and
        // `return_length` is a valid, exclusively-owned out-param. The
        // kernel writes at most `size` bytes into `raw` and reports the
        // actual length used (or needed) in `return_length`.
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                raw.as_mut_ptr() as *mut core::ffi::c_void,
                size,
                &mut return_length,
            )
        };

        if status == STATUS_INFO_LENGTH_MISMATCH {
            size = return_length.max(size.saturating_mul(2));
            continue;
        }
        if status.0 < 0 {
            return Err(Error::Process(ProcessError::OpenFailed(
                ProcessOpenError::with_code(
                    0,
                    "NtQuerySystemInformation(SystemProcessInformation) failed",
                    status.0,
                ),
            )));
        }

        raw.truncate(return_length as usize);
        return Ok(raw);
    }
}

/// Walk the kernel's linked list of `SYSTEM_PROCESS_INFORMATION` records.
fn parse_system_process_information(raw: &[u8], out: &mut Vec<ProcessSnapshotEntry>) {
    const HEADER_SIZE: usize = std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>();
    let mut offset = 0usize;

    loop {
        if offset + HEADER_SIZE > raw.len() {
            break;
        }

        // SAFETY: the bounds check above guarantees `HEADER_SIZE` bytes are
        // available at `offset`, `SYSTEM_PROCESS_INFORMATION` is `Copy` with
        // no destructor, and `raw` was written in full by the kernel before
        // this function ever runs, so the read is initialized.
        let entry = unsafe { &*(raw.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION) };

        let pid = entry.UniqueProcessId.0 as usize as u32;
        let parent_raw = entry.Reserved2 as usize as u32;
        let parent_pid = (parent_raw != 0).then(|| ProcessId::new(parent_raw));

        let create_time_bytes: [u8; 8] = entry.Reserved1
            [CREATE_TIME_OFFSET..CREATE_TIME_OFFSET + 8]
            .try_into()
            .expect("slice of Reserved1 is exactly 8 bytes");
        let create_time = i64::from_ne_bytes(create_time_bytes) as u64;

        let name_len_units = (entry.ImageName.Length / 2) as usize;
        let image_name = if entry.ImageName.Buffer.is_null() || name_len_units == 0 {
            String::new()
        } else {
            let name_len_bytes = name_len_units * 2;
            let name_offset = entry.ImageName.Buffer.0 as usize;
            let buffer_start = raw.as_ptr() as usize;
            // The kernel packs each entry's variable-length data (here, the
            // image name) after the fixed header, inside this same
            // allocation — never as a separate pointer. Bounds-check before
            // trusting it.
            if name_offset >= buffer_start
                && name_offset + name_len_bytes <= buffer_start + raw.len()
            {
                // SAFETY: bounds-checked above to lie fully within `raw`,
                // which is valid for its whole length and immutable here;
                // `UNICODE_STRING.Buffer` is a UTF-16 code-unit pointer and
                // `name_len_units` matches `Length / 2`.
                let slice = unsafe {
                    std::slice::from_raw_parts(
                        entry.ImageName.Buffer.0 as *const u16,
                        name_len_units,
                    )
                };
                String::from_utf16_lossy(slice)
            } else {
                String::new()
            }
        };

        out.push(ProcessSnapshotEntry {
            pid: ProcessId::new(pid),
            parent_pid,
            create_time,
            session_id: entry.SessionId,
            image_name,
        });

        if entry.NextEntryOffset == 0 {
            break;
        }
        offset += entry.NextEntryOffset as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::super::processes::Process;

    #[test]
    fn snapshot_includes_current_process_with_plausible_create_time() {
        let snapshot = Process::snapshot().expect("snapshot should succeed");
        let current = std::process::id();

        let entry = snapshot
            .iter()
            .find(|e| u32::from(e.pid) == current)
            .expect("current process must appear in its own snapshot");

        // FILETIME for 2020-01-01 00:00:00 UTC, as a sanity floor — this test
        // process was obviously created after that.
        const FILETIME_2020: u64 = 132_223_104_000_000_000;
        assert!(
            entry.create_time > FILETIME_2020,
            "create_time {} looks implausible for a process running right now",
            entry.create_time
        );
        assert!(!snapshot.is_empty());
    }

    #[test]
    fn snapshot_finds_a_parent_for_the_current_process() {
        // The test harness itself has a parent (cargo/the shell); this just
        // exercises that parent_pid decodes to *something* nonzero for a
        // normal process, without asserting a specific PID.
        let snapshot = Process::snapshot().expect("snapshot should succeed");
        let current = std::process::id();
        let entry = snapshot
            .iter()
            .find(|e| u32::from(e.pid) == current)
            .expect("current process must appear in its own snapshot");
        assert!(entry.parent_pid.is_some());
    }
}
