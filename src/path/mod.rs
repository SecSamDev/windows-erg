//! NT device path to DOS drive path conversion.
//!
//! The kernel and ETW report paths in the NT namespace
//! (`\Device\HarddiskVolume3\Windows\System32\cmd.exe`), not the familiar DOS
//! form (`C:\Windows\System32\cmd.exe`). This module converts between them
//! using the same drive-letter mapping `QueryDosDeviceW` exposes, plus the
//! `\??\` and `\SystemRoot\` NT path forms.
//!
//! # Example
//!
//! ```no_run
//! use windows_erg::path::nt_path_to_dos;
//!
//! let dos = nt_path_to_dos(r"\Device\HarddiskVolume3\Windows\System32\cmd.exe");
//! assert!(dos.is_some());
//! ```

use std::collections::HashMap;
use std::sync::RwLock;
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::core::PCWSTR;

use crate::utils::to_utf16_nul;

const DEVICE_PREFIX: &str = r"\Device\";
const NT_ALIAS_PREFIX: &str = r"\??\";
const SYSTEM_ROOT_PREFIX: &str = r"\SystemRoot\";

/// Cache of `\Device\HarddiskVolumeX` (and similar) roots to drive letters.
///
/// An `RwLock` rather than a `OnceLock` so a drive mounted after the cache
/// was first built (a USB drive, a new network mapping) can be picked up
/// with [`refresh_device_map`], rather than requiring a process restart.
static DEVICE_PATH_CACHE: RwLock<Option<HashMap<String, char>>> = RwLock::new(None);

/// Query `QueryDosDeviceW` for every drive letter and build the device-root map.
fn build_device_map() -> HashMap<String, char> {
    let mut map = HashMap::new();
    let mut buffer = vec![0u16; 32768];

    for drive_char in 'A'..='Z' {
        let drive = format!("{drive_char}:");
        let drive_wide = to_utf16_nul(&drive);

        let len = unsafe { QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut buffer)) };
        if len == 0 {
            continue;
        }

        let mut device_path = buffer[..len as usize].to_vec();
        while device_path.last() == Some(&0) {
            device_path.pop();
        }
        map.insert(String::from_utf16_lossy(&device_path), drive_char);
    }

    map
}

/// Run `f` against the cached device map, building it on first use.
fn with_device_map<T>(f: impl FnOnce(&HashMap<String, char>) -> T) -> T {
    {
        let guard = DEVICE_PATH_CACHE
            .read()
            .expect("device path cache lock poisoned");
        if let Some(map) = guard.as_ref() {
            return f(map);
        }
    }

    let mut guard = DEVICE_PATH_CACHE
        .write()
        .expect("device path cache lock poisoned");
    if guard.is_none() {
        *guard = Some(build_device_map());
    }
    f(guard.as_ref().expect("just initialized above"))
}

/// Rebuild the device-root-to-drive-letter cache.
///
/// Call after a drive is mounted or unmounted at runtime; without this, a
/// path on a drive that did not exist when the cache was first built will
/// not resolve until the process restarts.
pub fn refresh_device_map() {
    let mut guard = DEVICE_PATH_CACHE
        .write()
        .expect("device path cache lock poisoned");
    *guard = Some(build_device_map());
}

/// Convert an NT-namespace path to its DOS equivalent, writing into `out`.
///
/// Clears `out` first. Returns `true` and leaves the DOS path in `out` on
/// success; returns `false` and leaves `out` empty when `input` cannot be
/// resolved (an unmapped device root, a `\??\Volume{guid}\...` path, or a
/// `\SystemRoot\` path with no `SystemRoot` environment variable).
///
/// Handles, in order:
/// - Paths already in DOS form (`C:\...`) — copied through unchanged.
/// - `\??\C:\...` — the NT-namespace alias for a DOS path, unwrapped directly.
/// - `\SystemRoot\...` — resolved against the `SystemRoot` environment variable.
/// - `\Device\HarddiskVolumeN\...` — resolved through the drive-letter cache.
pub fn nt_path_to_dos_into(input: &str, out: &mut String) -> bool {
    out.clear();

    if input.is_empty() {
        return false;
    }

    // Already a DOS path, e.g. "C:\Windows\System32\cmd.exe".
    if is_dos_drive_path(input) {
        out.push_str(input);
        return true;
    }

    if let Some(rest) = input.strip_prefix(NT_ALIAS_PREFIX) {
        if is_dos_drive_path(rest) {
            out.push_str(rest);
            return true;
        }
        // \??\Volume{guid}\... etc — no drive-letter mapping available here.
        return false;
    }

    if let Some(rest) = input.strip_prefix(SYSTEM_ROOT_PREFIX) {
        let Some(windir) = std::env::var_os("SystemRoot") else {
            return false;
        };
        out.push_str(&windir.to_string_lossy());
        out.push('\\');
        out.push_str(rest);
        return true;
    }

    if let Some(rest) = input.strip_prefix(DEVICE_PREFIX) {
        let root_len = rest.find('\\').unwrap_or(rest.len());
        let device_root = &input[..DEVICE_PREFIX.len() + root_len];

        let drive_char = with_device_map(|map| map.get(device_root).copied());
        let Some(drive_char) = drive_char else {
            return false;
        };

        out.push(drive_char);
        out.push(':');
        if root_len < rest.len() {
            out.push_str(&rest[root_len..]);
        } else {
            out.push('\\');
        }
        return true;
    }

    false
}

/// Convert an NT-namespace path to its DOS equivalent.
///
/// Allocates a new `String`. Prefer [`nt_path_to_dos_into`] on a hot path.
pub fn nt_path_to_dos(input: &str) -> Option<String> {
    let mut out = String::new();
    if nt_path_to_dos_into(input, &mut out) {
        Some(out)
    } else {
        None
    }
}

/// `true` if `path` already looks like a DOS drive path (`C:\...` or `C:/...`).
fn is_dos_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_dos_path_passes_through() {
        assert_eq!(
            nt_path_to_dos(r"C:\Windows\System32\cmd.exe"),
            Some(r"C:\Windows\System32\cmd.exe".to_string())
        );
    }

    #[test]
    fn nt_alias_dos_path_is_unwrapped() {
        assert_eq!(
            nt_path_to_dos(r"\??\C:\Windows\System32\cmd.exe"),
            Some(r"C:\Windows\System32\cmd.exe".to_string())
        );
    }

    #[test]
    fn nt_alias_volume_guid_is_unresolved() {
        assert_eq!(
            nt_path_to_dos(r"\??\Volume{12345678-1234-1234-1234-123456789012}\file.txt"),
            None
        );
    }

    #[test]
    fn system_root_path_resolves_against_env_var() {
        let saved = std::env::var_os("SystemRoot");
        unsafe {
            std::env::set_var("SystemRoot", r"C:\Windows");
        }
        assert_eq!(
            nt_path_to_dos(r"\SystemRoot\System32\ntoskrnl.exe"),
            Some(r"C:\Windows\System32\ntoskrnl.exe".to_string())
        );
        unsafe {
            match saved {
                Some(v) => std::env::set_var("SystemRoot", v),
                None => std::env::remove_var("SystemRoot"),
            }
        }
    }

    #[test]
    fn unknown_device_root_is_unresolved() {
        assert_eq!(nt_path_to_dos(r"\Device\NoSuchVolumeAtAll\file.txt"), None);
    }

    #[test]
    fn empty_input_is_unresolved() {
        assert_eq!(nt_path_to_dos(""), None);
    }

    #[test]
    fn into_variant_clears_output_on_failure() {
        let mut out = String::from("stale");
        assert!(!nt_path_to_dos_into(
            r"\Device\NoSuchVolumeAtAll\file.txt",
            &mut out
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn device_root_with_no_trailing_path_maps_to_bare_drive() {
        // Build a private map rather than mutating the shared cache, so this
        // test is safe to run concurrently with the others in this module.
        let map = build_device_map();
        let (device_root, drive_char) = map
            .iter()
            .next()
            .map(|(root, ch)| (root.clone(), *ch))
            .expect("at least one drive should be mapped on any Windows host");

        assert_eq!(
            nt_path_to_dos(&device_root),
            Some(format!("{drive_char}:\\"))
        );
    }

    #[test]
    fn refresh_device_map_does_not_panic_and_still_resolves() {
        refresh_device_map();
        assert!(nt_path_to_dos(r"C:\Windows\System32\cmd.exe").is_some());
    }

    #[test]
    fn current_process_nt_path_maps_to_current_exe() {
        use crate::process::Process;

        let nt_path = Process::current()
            .path()
            .expect("current process path should resolve");
        let expected = std::env::current_exe().expect("current_exe should succeed");

        // Process::path already returns a DOS path (it goes through this same
        // module); this just proves the two entry points agree.
        assert_eq!(nt_path, expected);
    }
}
