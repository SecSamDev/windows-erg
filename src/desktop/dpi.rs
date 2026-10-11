//! Per-monitor DPI awareness.

use windows::Win32::Foundation::{HWND, RECT};
use windows::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForWindow, SetProcessDpiAwarenessContext,
};

use super::types::{WindowHandle, WindowRect};

/// The DPI at 100% scaling.
pub const DEFAULT_DPI: u32 = 96;

/// Make the process per-monitor DPI aware (v2). Returns false when it was
/// already set (by a manifest, for example) or the system does not support it.
pub fn set_process_dpi_aware_per_monitor_v2() -> bool {
    // SAFETY: process-wide setting with a predefined context value.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) }.is_ok()
}

/// The DPI of the monitor a window is on, or [`DEFAULT_DPI`] if unknown.
pub fn dpi_for_window(window: WindowHandle) -> u32 {
    // SAFETY: GetDpiForWindow returns 0 for an invalid handle.
    match unsafe { GetDpiForWindow(HWND::from(window)) } {
        0 => DEFAULT_DPI,
        dpi => dpi,
    }
}

/// Scale a length given at 96 DPI to `dpi`.
pub fn scale(value: i32, dpi: u32) -> i32 {
    (i64::from(value) * i64::from(dpi) / i64::from(DEFAULT_DPI)) as i32
}

/// The rectangle Windows suggests in a `WM_DPICHANGED` message.
///
/// # Safety
///
/// `lparam` must be the lparam of a `WM_DPICHANGED` message currently being
/// handled.
pub unsafe fn suggested_rect(lparam: isize) -> WindowRect {
    // SAFETY: for WM_DPICHANGED, lparam points to a RECT (caller's contract).
    unsafe { *(lparam as *const RECT) }.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_is_proportional() {
        assert_eq!(scale(100, 96), 100);
        assert_eq!(scale(100, 144), 150);
        assert_eq!(scale(10, 192), 20);
    }
}
