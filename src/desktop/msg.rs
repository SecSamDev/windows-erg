//! Window message numbers a [`WindowHandler`](super::WindowHandler) sees,
//! so callers do not depend on the `windows` crate.

use windows::Win32::UI::WindowsAndMessaging as wm;

/// First message number free for application use (`WM_APP`).
pub const WM_APP: u32 = wm::WM_APP;
/// Window being created.
pub const WM_CREATE: u32 = wm::WM_CREATE;
/// Window being destroyed.
pub const WM_DESTROY: u32 = wm::WM_DESTROY;
/// Close requested (title-bar X, Alt+F4).
pub const WM_CLOSE: u32 = wm::WM_CLOSE;
/// Client area resized; low/high word of lparam are width/height.
pub const WM_SIZE: u32 = wm::WM_SIZE;
/// Menu or control command; low word of wparam is the id.
pub const WM_COMMAND: u32 = wm::WM_COMMAND;
/// Common-control notification; decode with
/// [`decode_notify`](super::decode_notify).
pub const WM_NOTIFY: u32 = wm::WM_NOTIFY;
/// Timer tick.
pub const WM_TIMER: u32 = wm::WM_TIMER;
/// Monitor DPI changed; see [`suggested_rect`](super::suggested_rect).
pub const WM_DPICHANGED: u32 = wm::WM_DPICHANGED;
/// Context menu requested.
pub const WM_CONTEXTMENU: u32 = wm::WM_CONTEXTMENU;
/// Left mouse button released.
pub const WM_LBUTTONUP: u32 = wm::WM_LBUTTONUP;
/// Session ending.
pub const WM_ENDSESSION: u32 = wm::WM_ENDSESSION;

/// Low 16 bits of a message parameter.
pub fn loword(value: usize) -> u16 {
    (value & 0xFFFF) as u16
}

/// Bits 16..32 of a message parameter.
pub fn hiword(value: usize) -> u16 {
    ((value >> 16) & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_split_a_parameter() {
        assert_eq!(loword(0x0012_0034), 0x34);
        assert_eq!(hiword(0x0012_0034), 0x12);
    }
}
