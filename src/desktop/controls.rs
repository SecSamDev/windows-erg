//! Common controls: virtual list views, tab strips and status bars.

use std::ffi::c_void;

use windows::Win32::Foundation::{HWND, LPARAM, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{CreateFontIndirectW, DeleteObject, HFONT};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    ICC_BAR_CLASSES, ICC_LISTVIEW_CLASSES, ICC_TAB_CLASSES, INITCOMMONCONTROLSEX,
    InitCommonControlsEx, LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVM_GETNEXTITEM,
    LVM_INSERTCOLUMNW, LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMCOUNT, LVN_GETDISPINFOW,
    LVNI_SELECTED, LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_OWNERDATA, LVS_REPORT,
    LVS_SHOWSELALWAYS, LVS_SINGLESEL, LVSICF_NOSCROLL, NM_DBLCLK, NMHDR, NMLVDISPINFOW,
    SB_SETTEXTW, SBARS_SIZEGRIP, STATUSCLASSNAMEW, TCIF_TEXT, TCITEMW, TCM_ADJUSTRECT,
    TCM_GETCURSEL, TCM_GETITEMCOUNT, TCM_INSERTITEMW, TCN_SELCHANGE, WC_LISTVIEWW, WC_TABCONTROLW,
};
use windows::Win32::UI::HiDpi::SystemParametersInfoForDpi;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, HMENU, NONCLIENTMETRICSW, SPI_GETNONCLIENTMETRICS, SendMessageW,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_SETFONT, WM_SIZE, WS_CHILD, WS_CLIPSIBLINGS,
    WS_EX_CLIENTEDGE, WS_TABSTOP, WS_VISIBLE,
};
use windows::core::{PCWSTR, PWSTR};

use crate::Result;
use crate::utils::to_utf16_nul;

use super::types::{WindowHandle, WindowRect};
use super::window::op_error;

/// Register the list-view, tab and status-bar classes. Call once before
/// creating any control.
pub fn init_common_controls() -> Result<()> {
    let init = INITCOMMONCONTROLSEX {
        dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES,
    };
    // SAFETY: `init` is a valid, sized structure.
    if unsafe { InitCommonControlsEx(&init) }.as_bool() {
        Ok(())
    } else {
        Err(op_error("InitCommonControlsEx", "common controls", 0))
    }
}

/// The system message font at a given DPI, deleted on drop. Keep it alive
/// for as long as any control uses it.
#[derive(Debug)]
pub struct GuiFont {
    hfont: HFONT,
}

impl GuiFont {
    /// The font Windows uses for message boxes, sized for `dpi`.
    pub fn message_font(dpi: u32) -> Result<Self> {
        let mut metrics = NONCLIENTMETRICSW {
            cbSize: std::mem::size_of::<NONCLIENTMETRICSW>() as u32,
            ..Default::default()
        };
        // SAFETY: `metrics` is a valid, sized out structure.
        unsafe {
            SystemParametersInfoForDpi(
                SPI_GETNONCLIENTMETRICS.0,
                metrics.cbSize,
                Some(&mut metrics as *mut _ as *mut c_void),
                0,
                dpi,
            )
        }
        .map_err(|e| op_error("SystemParametersInfoForDpi", "message font", e.code().0))?;
        // SAFETY: the LOGFONTW comes straight from the system.
        let hfont = unsafe { CreateFontIndirectW(&metrics.lfMessageFont) };
        if hfont.is_invalid() {
            return Err(op_error("CreateFontIndirectW", "message font", 0));
        }
        Ok(Self { hfont })
    }

    /// Apply the font to a window or control.
    pub fn apply(&self, window: WindowHandle) {
        // SAFETY: WM_SETFONT takes the font handle and a redraw flag.
        unsafe {
            SendMessageW(
                HWND::from(window),
                WM_SETFONT,
                WPARAM(self.hfont.0 as usize),
                LPARAM(1),
            );
        }
    }
}

impl Drop for GuiFont {
    fn drop(&mut self) {
        // SAFETY: the font is owned and deleted once.
        unsafe {
            let _ = DeleteObject(self.hfont);
        }
    }
}

/// A report-style, virtual (`LVS_OWNERDATA`) list view. It stores no
/// text: it asks its parent for each visible cell through
/// [`ControlNotify::ListViewGetText`].
#[derive(Debug, Clone, Copy)]
pub struct ListView {
    hwnd: HWND,
    columns: i32,
}

impl ListView {
    /// Create a list view as a child of `parent` with the control `id`.
    pub fn create(parent: WindowHandle, id: u16) -> Result<Self> {
        let style = WS_CHILD
            | WS_VISIBLE
            | WS_TABSTOP
            | WINDOW_STYLE(LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS | LVS_SINGLESEL);
        let hwnd = create_child(
            WC_LISTVIEWW,
            parent,
            id,
            style,
            WS_EX_CLIENTEDGE,
            "list view",
        )?;
        let extended = (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as isize;
        // SAFETY: sets extended styles on the control just created.
        unsafe {
            SendMessageW(
                hwnd,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                WPARAM(extended as usize),
                LPARAM(extended),
            );
        }
        Ok(Self { hwnd, columns: 0 })
    }

    /// The control's handle.
    pub fn handle(&self) -> WindowHandle {
        self.hwnd.into()
    }

    /// Append a column with a header and a width in physical pixels.
    pub fn add_column(&mut self, header: &str, width: i32) -> Result<()> {
        let mut text = to_utf16_nul(header);
        let column = LVCOLUMNW {
            mask: LVCF_TEXT | LVCF_WIDTH,
            cx: width,
            pszText: PWSTR(text.as_mut_ptr()),
            ..Default::default()
        };
        // SAFETY: `column` and its text outlive the synchronous send.
        let index = unsafe {
            SendMessageW(
                self.hwnd,
                LVM_INSERTCOLUMNW,
                WPARAM(self.columns as usize),
                LPARAM(&column as *const _ as isize),
            )
        };
        if index.0 < 0 {
            return Err(op_error("LVM_INSERTCOLUMNW", header.to_string(), 0));
        }
        self.columns += 1;
        Ok(())
    }

    /// Set how many rows the list has, and repaint it. The selection and
    /// scroll position are kept.
    pub fn set_item_count(&self, count: usize) {
        // SAFETY: plain message to an owned control.
        unsafe {
            SendMessageW(
                self.hwnd,
                LVM_SETITEMCOUNT,
                WPARAM(count),
                LPARAM(LVSICF_NOSCROLL as isize),
            );
        }
        self.handle().invalidate();
    }

    /// The selected row, if any.
    pub fn selected_index(&self) -> Option<usize> {
        // SAFETY: -1 as wparam starts the search before the first item.
        let index = unsafe {
            SendMessageW(
                self.hwnd,
                LVM_GETNEXTITEM,
                WPARAM(usize::MAX),
                LPARAM(LVNI_SELECTED as isize),
            )
        };
        usize::try_from(index.0).ok()
    }
}

/// A tab strip. Pages are separate windows the caller shows and hides.
#[derive(Debug, Clone, Copy)]
pub struct TabControl {
    hwnd: HWND,
}

impl TabControl {
    /// Create a tab strip as a child of `parent` with the control `id`.
    pub fn create(parent: WindowHandle, id: u16) -> Result<Self> {
        let style = WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_TABSTOP;
        let hwnd = create_child(
            WC_TABCONTROLW,
            parent,
            id,
            style,
            WINDOW_EX_STYLE(0),
            "tab control",
        )?;
        Ok(Self { hwnd })
    }

    /// The control's handle.
    pub fn handle(&self) -> WindowHandle {
        self.hwnd.into()
    }

    /// Append a tab.
    pub fn add_tab(&self, label: &str) -> Result<()> {
        // SAFETY: plain message to an owned control.
        let count = unsafe { SendMessageW(self.hwnd, TCM_GETITEMCOUNT, WPARAM(0), LPARAM(0)) };
        let mut text = to_utf16_nul(label);
        let item = TCITEMW {
            mask: TCIF_TEXT,
            pszText: PWSTR(text.as_mut_ptr()),
            ..Default::default()
        };
        // SAFETY: `item` and its text outlive the synchronous send.
        let index = unsafe {
            SendMessageW(
                self.hwnd,
                TCM_INSERTITEMW,
                WPARAM(count.0 as usize),
                LPARAM(&item as *const _ as isize),
            )
        };
        if index.0 < 0 {
            return Err(op_error("TCM_INSERTITEMW", label.to_string(), 0));
        }
        Ok(())
    }

    /// The selected tab, if any.
    pub fn selected(&self) -> Option<usize> {
        // SAFETY: plain message to an owned control.
        let index = unsafe { SendMessageW(self.hwnd, TCM_GETCURSEL, WPARAM(0), LPARAM(0)) };
        usize::try_from(index.0).ok()
    }

    /// The page area inside the strip when the strip occupies `bounds`
    /// (parent client coordinates).
    pub fn display_rect(&self, bounds: WindowRect) -> WindowRect {
        let mut rect = RECT {
            left: bounds.left,
            top: bounds.top,
            right: bounds.right,
            bottom: bounds.bottom,
        };
        // SAFETY: TCM_ADJUSTRECT with FALSE converts a window rect into a
        // display rect in place.
        unsafe {
            SendMessageW(
                self.hwnd,
                TCM_ADJUSTRECT,
                WPARAM(0),
                LPARAM(&mut rect as *mut _ as isize),
            );
        }
        rect.into()
    }
}

/// A status bar docked at the bottom of its parent.
#[derive(Debug, Clone, Copy)]
pub struct StatusBar {
    hwnd: HWND,
}

impl StatusBar {
    /// Create a status bar as a child of `parent` with the control `id`.
    pub fn create(parent: WindowHandle, id: u16) -> Result<Self> {
        let style = WS_CHILD | WS_VISIBLE | WINDOW_STYLE(SBARS_SIZEGRIP);
        let hwnd = create_child(
            STATUSCLASSNAMEW,
            parent,
            id,
            style,
            WINDOW_EX_STYLE(0),
            "status bar",
        )?;
        Ok(Self { hwnd })
    }

    /// The control's handle.
    pub fn handle(&self) -> WindowHandle {
        self.hwnd.into()
    }

    /// Set the bar's text.
    pub fn set_text(&self, text: &str) {
        let wide = to_utf16_nul(text);
        // SAFETY: `wide` outlives the synchronous send; part 0.
        unsafe {
            SendMessageW(
                self.hwnd,
                SB_SETTEXTW,
                WPARAM(0),
                LPARAM(wide.as_ptr() as isize),
            );
        }
    }

    /// Re-dock after the parent was resized. Call from the parent's `WM_SIZE`.
    pub fn parent_resized(&self) {
        // SAFETY: a status bar repositions itself on WM_SIZE.
        unsafe {
            SendMessageW(self.hwnd, WM_SIZE, WPARAM(0), LPARAM(0));
        }
    }

    /// The bar's current height in pixels.
    pub fn height(&self) -> i32 {
        self.handle().window_rect().map(|r| r.height()).unwrap_or(0)
    }
}

/// A decoded `WM_NOTIFY` from a common control.
#[derive(Debug)]
pub enum ControlNotify<'a> {
    /// A virtual list view needs the text of one cell.
    ListViewGetText(ListViewTextRequest<'a>),
    /// The selected tab changed.
    TabChanged {
        /// Id of the tab control.
        control_id: usize,
    },
    /// A control was double-clicked.
    DoubleClick {
        /// Id of the control.
        control_id: usize,
    },
    /// Any other notification.
    Other {
        /// Id of the control.
        control_id: usize,
        /// Notification code.
        code: u32,
    },
}

/// One cell's text, requested by a virtual list view.
#[derive(Debug)]
pub struct ListViewTextRequest<'a> {
    /// Id of the list view.
    pub control_id: usize,
    /// Row index.
    pub row: usize,
    /// Column index.
    pub column: usize,
    buffer: &'a mut [u16],
}

impl ListViewTextRequest<'_> {
    /// Answer with `text`, truncated to the control's buffer.
    pub fn set_text(&mut self, text: &str) {
        let Some(last) = self.buffer.len().checked_sub(1) else {
            return;
        };
        let mut written = 0;
        for (slot, unit) in self.buffer[..last].iter_mut().zip(text.encode_utf16()) {
            *slot = unit;
            written += 1;
        }
        self.buffer[written] = 0;
    }
}

/// Decode a `WM_NOTIFY` message's lparam.
///
/// # Safety
///
/// `lparam` must be the lparam of a `WM_NOTIFY` message currently being
/// handled, and the result must not outlive that handling.
pub unsafe fn decode_notify<'a>(lparam: isize) -> Option<ControlNotify<'a>> {
    let header = lparam as *const NMHDR;
    if header.is_null() {
        return None;
    }
    // SAFETY: WM_NOTIFY's lparam points to an NMHDR (caller's contract).
    let header = unsafe { &*header };
    let control_id = header.idFrom;
    let notify = match header.code {
        LVN_GETDISPINFOW => {
            // SAFETY: LVN_GETDISPINFOW's NMHDR heads an NMLVDISPINFOW.
            let info = unsafe { &*(lparam as *const NMLVDISPINFOW) };
            let item = &info.item;
            if !item.mask.contains(LVIF_TEXT) || item.pszText.is_null() || item.cchTextMax <= 0 {
                return None;
            }
            // SAFETY: the control lends a writable buffer of `cchTextMax`
            // UTF-16 units for the duration of the notification.
            let buffer =
                unsafe { std::slice::from_raw_parts_mut(item.pszText.0, item.cchTextMax as usize) };
            ControlNotify::ListViewGetText(ListViewTextRequest {
                control_id,
                row: usize::try_from(item.iItem).ok()?,
                column: usize::try_from(item.iSubItem).ok()?,
                buffer,
            })
        }
        TCN_SELCHANGE => ControlNotify::TabChanged { control_id },
        NM_DBLCLK => ControlNotify::DoubleClick { control_id },
        code => ControlNotify::Other { control_id, code },
    };
    Some(notify)
}

fn create_child(
    class: PCWSTR,
    parent: WindowHandle,
    id: u16,
    style: WINDOW_STYLE,
    ex_style: WINDOW_EX_STYLE,
    what: &'static str,
) -> Result<HWND> {
    // SAFETY: `None` asks for the executable's own module handle.
    let instance = unsafe { GetModuleHandleW(None) }
        .map_err(|e| op_error("GetModuleHandleW", what, e.code().0))?;
    // SAFETY: a predefined control class; for a child window the menu
    // parameter carries the control id.
    unsafe {
        CreateWindowExW(
            ex_style,
            class,
            PCWSTR::null(),
            style,
            0,
            0,
            0,
            0,
            HWND::from(parent),
            HMENU(usize::from(id) as *mut c_void),
            instance,
            None,
        )
    }
    .map_err(|e| op_error("CreateWindowExW", what, e.code().0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::UI::Controls::LVITEMW;

    #[test]
    fn list_view_text_request_writes_and_truncates() {
        let mut buffer = [0xFFFFu16; 5];
        let mut info = NMLVDISPINFOW {
            hdr: NMHDR {
                hwndFrom: HWND::default(),
                idFrom: 7,
                code: LVN_GETDISPINFOW,
            },
            item: LVITEMW {
                mask: LVIF_TEXT,
                iItem: 3,
                iSubItem: 2,
                pszText: PWSTR(buffer.as_mut_ptr()),
                cchTextMax: buffer.len() as i32,
                ..Default::default()
            },
        };
        // SAFETY: `info` is a well-formed notification that outlives the decode.
        let notify = unsafe { decode_notify(&mut info as *mut _ as isize) };
        let Some(ControlNotify::ListViewGetText(mut request)) = notify else {
            panic!("expected a text request");
        };
        assert_eq!((request.control_id, request.row, request.column), (7, 3, 2));
        request.set_text("abcdefg");
        assert_eq!(String::from_utf16_lossy(&buffer[..4]), "abcd");
        assert_eq!(buffer[4], 0);
    }

    #[test]
    fn tab_change_and_unknown_codes_decode() {
        let mut header = NMHDR {
            hwndFrom: HWND::default(),
            idFrom: 2,
            code: TCN_SELCHANGE,
        };
        // SAFETY: `header` is a well-formed NMHDR that outlives the decode.
        let notify = unsafe { decode_notify(&mut header as *mut _ as isize) };
        assert!(matches!(
            notify,
            Some(ControlNotify::TabChanged { control_id: 2 })
        ));

        header.code = 12345;
        // SAFETY: as above.
        let notify = unsafe { decode_notify(&mut header as *mut _ as isize) };
        assert!(matches!(
            notify,
            Some(ControlNotify::Other {
                control_id: 2,
                code: 12345
            })
        ));
    }
}
