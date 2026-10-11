//! Desktop window and tray icon operations.
//!
//! This module provides:
//! - Window enumeration for top-level and child windows
//! - Query helpers for visibility, title, class, rectangle, and cloaked state
//! - Notification area (tray) icon lifecycle, balloon notifications and
//!   click callbacks
//! - Window classes and windows bound to a [`WindowHandler`], message posting
//!   from other threads, and the message loop
//! - Common controls (virtual list view with custom draw, tab strip, status
//!   bar), popup menus, per-monitor DPI and a single-instance guard
//! - Direct2D/DirectWrite drawing ([`Canvas`]), light/dark theming and the
//!   clipboard

mod canvas;
pub mod clipboard;
mod controls;
mod dpi;
mod instance;
mod menu;
pub mod msg;
mod theme;
mod tray;
mod types;
mod window;
mod windows;

pub use canvas::{Align, Canvas, Color, Frame, RectF, TextStyle, Weight};
pub use controls::{
    ControlNotify, DrawStage, GuiFont, ListView, ListViewCustomDraw, ListViewTextRequest,
    StatusBar, TabControl, decode_notify, init_common_controls,
};
pub use dpi::{
    DEFAULT_DPI, dpi_for_window, scale, set_process_dpi_aware_per_monitor_v2, suggested_rect,
};
pub use instance::SingleInstance;
pub use menu::PopupMenu;
pub use theme::{
    Backdrop, ControlTheme, allow_dark_menus, is_theme_change, set_backdrop, set_control_theme,
    set_dark_title_bar, system_prefers_dark,
};
pub use tray::{TrayEvent, TrayIcon, TrayIconBuilder, TrayNotification, taskbar_created_message};
pub use types::{BalloonIcon, CloakState, TrayIconId, WindowHandle, WindowInfo, WindowRect};
pub use window::{
    MessagePoster, PaintGuard, Window, WindowBuilder, WindowClass, WindowClassBuilder,
    WindowHandler, ctrl_down, mouse_position, post_quit, run_message_loop,
};

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
