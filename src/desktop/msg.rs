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
/// Paint the client area; wrap the handling in a
/// [`PaintGuard`](super::PaintGuard).
pub const WM_PAINT: u32 = wm::WM_PAINT;
/// Erase the background; return 1 from a window that paints all of itself.
pub const WM_ERASEBKGND: u32 = wm::WM_ERASEBKGND;
/// The mouse moved; see [`mouse_position`](super::mouse_position).
pub const WM_MOUSEMOVE: u32 = wm::WM_MOUSEMOVE;
/// The mouse left the window (after
/// [`track_mouse_leave`](super::WindowHandle::track_mouse_leave)).
pub const WM_MOUSELEAVE: u32 = windows::Win32::UI::Controls::WM_MOUSELEAVE;
/// Left mouse button pressed.
pub const WM_LBUTTONDOWN: u32 = wm::WM_LBUTTONDOWN;
/// Mouse wheel turned; high word of wparam is the signed delta.
pub const WM_MOUSEWHEEL: u32 = wm::WM_MOUSEWHEEL;
/// A key was pressed; wparam is the virtual-key code.
pub const WM_KEYDOWN: u32 = wm::WM_KEYDOWN;
/// A system setting changed; see
/// [`is_theme_change`](super::is_theme_change).
pub const WM_SETTINGCHANGE: u32 = wm::WM_SETTINGCHANGE;
/// Minimum and maximum window size are asked for.
pub const WM_GETMINMAXINFO: u32 = wm::WM_GETMINMAXINFO;
/// The window is about to be shown or hidden; wparam is nonzero when shown.
pub const WM_SHOWWINDOW: u32 = wm::WM_SHOWWINDOW;
/// Set the mouse cursor; return 1 after setting one.
pub const WM_SETCURSOR: u32 = wm::WM_SETCURSOR;

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
