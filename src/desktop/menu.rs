//! Popup (context) menus.

use windows::Win32::Foundation::{HWND, LPARAM, POINT, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, HMENU, MF_SEPARATOR, MF_STRING,
    PostMessageW, SetForegroundWindow, SetMenuDefaultItem, TPM_NONOTIFY, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, TrackPopupMenu, WM_NULL,
};
use windows::core::PCWSTR;

use crate::Result;
use crate::utils::to_utf16_nul;

use super::types::WindowHandle;
use super::window::op_error;

/// A popup menu, destroyed on drop.
#[derive(Debug)]
pub struct PopupMenu {
    hmenu: HMENU,
}

impl PopupMenu {
    /// Create an empty popup menu.
    pub fn new() -> Result<Self> {
        // SAFETY: no arguments; the handle is owned by the returned value.
        let hmenu = unsafe { CreatePopupMenu() }
            .map_err(|e| op_error("CreatePopupMenu", "popup menu", e.code().0))?;
        Ok(Self { hmenu })
    }

    /// Append a text item that returns `id` when chosen. `id` must not be 0.
    pub fn append(&self, id: u32, text: &str) -> Result<()> {
        let wide = to_utf16_nul(text);
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        unsafe { AppendMenuW(self.hmenu, MF_STRING, id as usize, PCWSTR(wide.as_ptr())) }
            .map_err(|e| op_error("AppendMenuW", "menu item", e.code().0))
    }

    /// Append a separator.
    pub fn separator(&self) -> Result<()> {
        // SAFETY: a separator takes no text.
        unsafe { AppendMenuW(self.hmenu, MF_SEPARATOR, 0, PCWSTR::null()) }
            .map_err(|e| op_error("AppendMenuW", "menu separator", e.code().0))
    }

    /// Show the item `id` in bold, as the default action.
    pub fn set_default(&self, id: u32) -> Result<()> {
        // SAFETY: by-command lookup on an owned menu.
        unsafe { SetMenuDefaultItem(self.hmenu, id, 0) }
            .map_err(|e| op_error("SetMenuDefaultItem", "menu item", e.code().0))
    }

    /// Show the menu at the cursor and wait for a choice. Returns the chosen
    /// id, or `None` when the menu was dismissed.
    ///
    /// Follows the documented notification-area pattern: the owner is
    /// brought to the foreground first, so the menu closes when the user
    /// clicks elsewhere, and a `WM_NULL` is posted afterwards.
    pub fn track_at_cursor(&self, owner: WindowHandle) -> Option<u32> {
        let mut point = POINT::default();
        // SAFETY: `point` is a valid out pointer.
        unsafe { GetCursorPos(&mut point) }.ok()?;
        self.track_at(owner, point.x, point.y)
    }

    /// Show the menu at screen position `(x, y)`; see [`Self::track_at_cursor`].
    pub fn track_at(&self, owner: WindowHandle, x: i32, y: i32) -> Option<u32> {
        let hwnd = HWND::from(owner);
        // SAFETY: plain calls on a window handle and an owned menu; with
        // TPM_RETURNCMD the BOOL carries the chosen command id.
        let chosen = unsafe {
            let _ = SetForegroundWindow(hwnd);
            let chosen = TrackPopupMenu(
                self.hmenu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
                x,
                y,
                0,
                hwnd,
                None,
            );
            let _ = PostMessageW(hwnd, WM_NULL, WPARAM(0), LPARAM(0));
            chosen
        };
        u32::try_from(chosen.0).ok().filter(|id| *id != 0)
    }
}

impl Drop for PopupMenu {
    fn drop(&mut self) {
        // SAFETY: the menu is owned and destroyed once.
        unsafe {
            let _ = DestroyMenu(self.hmenu);
        }
    }
}
