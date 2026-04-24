//! Desktop window and tray icon operations.
//!
//! This module provides:
//! - Window enumeration for top-level and child windows
//! - Query helpers for visibility, title, class, rectangle, and cloaked state
//! - Notification area (tray) icon lifecycle and balloon notifications

mod tray;
mod types;
mod windows;

pub use tray::{TrayIcon, TrayIconBuilder, TrayNotification};
pub use types::{BalloonIcon, CloakState, TrayIconId, WindowHandle, WindowInfo, WindowRect};

use crate::Result;

/// Enumerate desktop windows (top-level and child windows).
pub fn enumerate_windows() -> Result<Vec<WindowInfo>> {
    windows::enumerate_windows()
}

/// Enumerate desktop windows (top-level and child windows) with a reusable output buffer.
///
/// Returns the number of windows added to the output buffer.
pub fn enumerate_windows_with_buffer(out_windows: &mut Vec<WindowInfo>) -> Result<usize> {
    windows::enumerate_windows_with_buffer(out_windows)
}

/// Enumerate desktop windows (top-level and child windows) with in-enumeration filtering.
///
/// Returns the number of windows added to the output buffer.
pub fn enumerate_windows_with_filter<F>(
    out_windows: &mut Vec<WindowInfo>,
    filter: F,
) -> Result<usize>
where
    F: Fn(&WindowInfo) -> bool,
{
    windows::enumerate_windows_with_filter(out_windows, filter)
}

/// Enumerate child windows for a specific parent window.
pub fn enumerate_child_windows(parent: WindowHandle) -> Result<Vec<WindowInfo>> {
    windows::enumerate_child_windows(parent)
}

/// Enumerate child windows for a specific parent window with a reusable output buffer.
///
/// Returns the number of windows added to the output buffer.
pub fn enumerate_child_windows_with_buffer(
    parent: WindowHandle,
    out_windows: &mut Vec<WindowInfo>,
) -> Result<usize> {
    windows::enumerate_child_windows_with_buffer(parent, out_windows)
}

/// Enumerate child windows for a specific parent window with in-enumeration filtering.
///
/// Returns the number of windows added to the output buffer.
pub fn enumerate_child_windows_with_filter<F>(
    parent: WindowHandle,
    out_windows: &mut Vec<WindowInfo>,
    filter: F,
) -> Result<usize>
where
    F: Fn(&WindowInfo) -> bool,
{
    windows::enumerate_child_windows_with_filter(parent, out_windows, filter)
}
