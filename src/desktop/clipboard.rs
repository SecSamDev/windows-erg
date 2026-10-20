//! Plain-text clipboard access.

use windows::Win32::Foundation::{HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;

use crate::Result;

use super::types::WindowHandle;
use super::window::op_error;

/// Closes the clipboard when dropped.
struct Opened;

impl Opened {
    fn open(owner: Option<WindowHandle>) -> Result<Self> {
        let hwnd = owner.map(HWND::from).unwrap_or_default();
        // SAFETY: opens the clipboard for this thread; closed on drop.
        unsafe { OpenClipboard(Some(hwnd)) }
            .map_err(|e| op_error("OpenClipboard", "clipboard", e.code().0))?;
        Ok(Opened)
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: the clipboard was opened by `open`.
        let _ = unsafe { CloseClipboard() };
    }
}

/// Replace the clipboard's content with `text`.
pub fn set_text(owner: Option<WindowHandle>, text: &str) -> Result<()> {
    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let bytes = wide.len() * std::mem::size_of::<u16>();
    let _open = Opened::open(owner)?;
    // SAFETY: the clipboard is open by this thread.
    unsafe { EmptyClipboard() }.map_err(|e| op_error("EmptyClipboard", "clipboard", e.code().0))?;
    // SAFETY: a movable block the clipboard takes ownership of on success.
    let memory = unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) }
        .map_err(|e| op_error("GlobalAlloc", "clipboard", e.code().0))?;
    // SAFETY: the block holds `bytes` bytes; it is unlocked before handing over.
    unsafe {
        let target = GlobalLock(memory) as *mut u16;
        if target.is_null() {
            return Err(op_error("GlobalLock", "clipboard", 0));
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), target, wide.len());
        let _ = GlobalUnlock(memory);
    }
    // SAFETY: on success the system owns `memory`; on failure it leaks a
    // few bytes rather than risk freeing a block the system may hold.
    unsafe { SetClipboardData(u32::from(CF_UNICODETEXT.0), Some(HANDLE(memory.0))) }
        .map_err(|e| op_error("SetClipboardData", "clipboard", e.code().0))?;
    Ok(())
}

/// The clipboard's text, if it holds any.
pub fn get_text(owner: Option<WindowHandle>) -> Result<Option<String>> {
    let _open = Opened::open(owner)?;
    // SAFETY: the clipboard is open by this thread.
    let Ok(handle) = (unsafe { GetClipboardData(u32::from(CF_UNICODETEXT.0)) }) else {
        return Ok(None);
    };
    let memory = HGLOBAL(handle.0);
    // SAFETY: CF_UNICODETEXT data is a NUL-terminated UTF-16 string, valid
    // while the clipboard is open and the block is locked.
    let text = unsafe {
        let source = GlobalLock(memory) as *const u16;
        if source.is_null() {
            return Ok(None);
        }
        let mut len = 0;
        while *source.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(source, len));
        let _ = GlobalUnlock(memory);
        text
    };
    Ok(Some(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        let text = "BattleGuard · détection #42\nline two";
        set_text(None, text).expect("set");
        assert_eq!(get_text(None).expect("get").as_deref(), Some(text));
    }
}
