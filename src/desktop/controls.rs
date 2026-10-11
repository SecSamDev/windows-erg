//! Common controls: virtual list views, tab strips and status bars.

use std::ffi::c_void;

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontIndirectW, CreateSolidBrush, DT_CENTER, DT_END_ELLIPSIS, DT_NOPREFIX, DT_SINGLELINE,
    DT_VCENTER, DeleteObject, DrawTextW, FillRect, GetStockObject, HFONT, NULL_PEN, RoundRect,
    SelectObject, SetBkMode, SetTextColor, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    CDDS_ITEMPREPAINT, CDDS_PREPAINT, CDDS_SUBITEM, CDIS_SELECTED, CDRF_DODEFAULT, CDRF_NEWFONT,
    CDRF_NOTIFYITEMDRAW, CDRF_NOTIFYSUBITEMDRAW, CDRF_SKIPDEFAULT, ICC_BAR_CLASSES,
    ICC_LISTVIEW_CLASSES, ICC_TAB_CLASSES, INITCOMMONCONTROLSEX, InitCommonControlsEx,
    LIST_VIEW_ITEM_STATE_FLAGS, LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_STATE, LVIF_TEXT,
    LVIR_BOUNDS, LVIS_FOCUSED, LVIS_SELECTED, LVITEMW, LVM_ENSUREVISIBLE, LVM_GETHEADER,
    LVM_GETNEXTITEM, LVM_GETSUBITEMRECT, LVM_INSERTCOLUMNW, LVM_SETBKCOLOR,
    LVM_SETEXTENDEDLISTVIEWSTYLE, LVM_SETITEMCOUNT, LVM_SETITEMSTATE, LVM_SETTEXTBKCOLOR,
    LVM_SETTEXTCOLOR, LVN_GETDISPINFOW, LVN_ITEMCHANGED, LVN_KEYDOWN, LVNI_SELECTED,
    LVS_EX_DOUBLEBUFFER, LVS_EX_FULLROWSELECT, LVS_OWNERDATA, LVS_REPORT, LVS_SHOWSELALWAYS,
    LVS_SINGLESEL, LVSICF_NOSCROLL, NM_CUSTOMDRAW, NM_DBLCLK, NMHDR, NMLISTVIEW, NMLVCUSTOMDRAW,
    NMLVDISPINFOW, NMLVKEYDOWN, SB_SETTEXTW, SBARS_SIZEGRIP, STATUSCLASSNAMEW, TCIF_TEXT, TCITEMW,
    TCM_ADJUSTRECT, TCM_GETCURSEL, TCM_GETITEMCOUNT, TCM_INSERTITEMW, TCN_SELCHANGE, WC_LISTVIEWW,
    WC_TABCONTROLW,
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

    /// Select `row` (and give it the focus mark), or clear the selection
    /// with `None`.
    pub fn select(&self, row: Option<usize>) {
        let mask = LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0 | LVIS_FOCUSED.0);
        let (index, state) = match row {
            Some(row) => (row as isize, mask),
            None => (-1, LIST_VIEW_ITEM_STATE_FLAGS(0)),
        };
        let item = LVITEMW {
            mask: LVIF_STATE,
            state,
            stateMask: mask,
            ..Default::default()
        };
        // SAFETY: `item` lives for the synchronous send; -1 means every row.
        unsafe {
            SendMessageW(
                self.hwnd,
                LVM_SETITEMSTATE,
                WPARAM(index as usize),
                LPARAM(&item as *const _ as isize),
            );
        }
    }

    /// Scroll so `row` is visible.
    pub fn ensure_visible(&self, row: usize) {
        // SAFETY: plain message; FALSE = the whole row must be visible.
        unsafe {
            SendMessageW(self.hwnd, LVM_ENSUREVISIBLE, WPARAM(row), LPARAM(0));
        }
    }

    /// The column header control (to theme it).
    pub fn header(&self) -> WindowHandle {
        // SAFETY: plain message returning a child handle.
        let header = unsafe { SendMessageW(self.hwnd, LVM_GETHEADER, WPARAM(0), LPARAM(0)) };
        WindowHandle::new(header.0 as *mut std::ffi::c_void)
    }

    /// One cell's rectangle in the list's client pixels.
    pub fn cell_rect(&self, row: usize, column: usize) -> Option<WindowRect> {
        let mut rect = RECT {
            left: LVIR_BOUNDS as i32,
            top: column as i32,
            ..Default::default()
        };
        // SAFETY: LVM_GETSUBITEMRECT reads `top` (column) and `left` (part),
        // then fills `rect`.
        let ok = unsafe {
            SendMessageW(
                self.hwnd,
                LVM_GETSUBITEMRECT,
                WPARAM(row),
                LPARAM(&mut rect as *mut _ as isize),
            )
        };
        (ok.0 != 0).then(|| rect.into())
    }

    /// Text and background colours as `COLORREF`s (`0x00BBGGRR`).
    pub fn set_colors(&self, text: u32, background: u32) {
        // SAFETY: plain messages to an owned control.
        unsafe {
            SendMessageW(
                self.hwnd,
                LVM_SETTEXTCOLOR,
                WPARAM(0),
                LPARAM(text as isize),
            );
            SendMessageW(
                self.hwnd,
                LVM_SETTEXTBKCOLOR,
                WPARAM(0),
                LPARAM(background as isize),
            );
            SendMessageW(
                self.hwnd,
                LVM_SETBKCOLOR,
                WPARAM(0),
                LPARAM(background as isize),
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
    /// A list view row is about to be drawn; see [`ListViewCustomDraw`].
    ListViewCustomDraw(ListViewCustomDraw<'a>),
    /// A list view row became selected.
    SelectionChanged {
        /// Id of the list view.
        control_id: usize,
        /// The newly selected row.
        row: usize,
    },
    /// A key was pressed in a list view (it does not reach the parent's
    /// `WM_KEYDOWN`); `key` is the virtual-key code.
    KeyDown {
        /// Id of the list view.
        control_id: usize,
        /// Virtual-key code (`'C'` is 0x43).
        key: u16,
    },
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

/// Where a list view is in drawing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawStage {
    /// Before the control paints; answer [`ListViewCustomDraw::notify_rows`]
    /// to get the row stages.
    PrePaint,
    /// Before one row.
    Row,
    /// Before one cell of a row (after [`ListViewCustomDraw::notify_cells`]).
    Cell,
    /// Any other stage.
    Other,
}

/// One custom-draw notification from a list view. Answer it with one of
/// its associated return values from the window handler.
#[derive(Debug)]
pub struct ListViewCustomDraw<'a> {
    /// Id of the list view.
    pub control_id: usize,
    raw: &'a mut NMLVCUSTOMDRAW,
}

impl ListViewCustomDraw<'_> {
    /// The drawing stage.
    pub fn stage(&self) -> DrawStage {
        let stage = self.raw.nmcd.dwDrawStage;
        if stage == CDDS_PREPAINT {
            DrawStage::PrePaint
        } else if stage.0 == CDDS_ITEMPREPAINT.0 | CDDS_SUBITEM.0 {
            DrawStage::Cell
        } else if stage == CDDS_ITEMPREPAINT {
            DrawStage::Row
        } else {
            DrawStage::Other
        }
    }

    /// The row being drawn.
    pub fn row(&self) -> usize {
        self.raw.nmcd.dwItemSpec
    }

    /// The column being drawn (0 outside the cell stage).
    pub fn column(&self) -> usize {
        usize::try_from(self.raw.iSubItem).unwrap_or(0)
    }

    /// Whether the row is drawn selected.
    pub fn selected(&self) -> bool {
        self.raw.nmcd.uItemState.contains(CDIS_SELECTED)
    }

    /// Text colour for this row or cell (`COLORREF`).
    pub fn set_text_color(&mut self, color: u32) {
        self.raw.clrText = COLORREF(color);
    }

    /// Background colour behind the text of this row or cell (`COLORREF`).
    pub fn set_background(&mut self, color: u32) {
        self.raw.clrTextBk = COLORREF(color);
    }

    /// Paint a rounded "pill" with centred text into `rect` (pixels), using
    /// the list's current font. Answer [`Self::skip_default`] afterwards so
    /// the cell's own text is not drawn over it.
    pub fn paint_pill(&self, rect: WindowRect, fill: u32, text_color: u32, text: &str) {
        let hdc = self.raw.nmcd.hdc;
        let mut rc = RECT {
            left: rect.left,
            top: rect.top,
            right: rect.right,
            bottom: rect.bottom,
        };
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        let radius = rect.height();
        // SAFETY: GDI calls on the HDC the control lent for this
        // notification; every object selected in is selected back out.
        unsafe {
            let brush = CreateSolidBrush(COLORREF(fill));
            let old_brush = SelectObject(hdc, brush);
            let old_pen = SelectObject(hdc, GetStockObject(NULL_PEN));
            let _ = RoundRect(
                hdc,
                rc.left,
                rc.top,
                rc.right + 1,
                rc.bottom + 1,
                radius,
                radius,
            );
            SelectObject(hdc, old_pen);
            SelectObject(hdc, old_brush);
            let _ = DeleteObject(brush);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, COLORREF(text_color));
            DrawTextW(
                hdc,
                &mut wide,
                &mut rc,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
            );
        }
    }

    /// Fill `rect` (pixels) with a solid colour.
    pub fn fill(&self, rect: WindowRect, color: u32) {
        let rc = RECT {
            left: rect.left,
            top: rect.top,
            right: rect.right,
            bottom: rect.bottom,
        };
        // SAFETY: GDI calls on the lent HDC; the brush is deleted after use.
        unsafe {
            let brush = CreateSolidBrush(COLORREF(color));
            FillRect(self.raw.nmcd.hdc, &rc, brush);
            let _ = DeleteObject(brush);
        }
    }

    /// Answer for [`DrawStage::PrePaint`]: ask for each row.
    pub fn notify_rows() -> isize {
        CDRF_NOTIFYITEMDRAW as isize
    }

    /// Answer for [`DrawStage::Row`]: ask for each cell of the row.
    pub fn notify_cells() -> isize {
        CDRF_NOTIFYSUBITEMDRAW as isize
    }

    /// Answer after changing colours: draw normally with them.
    pub fn new_colors() -> isize {
        CDRF_NEWFONT as isize
    }

    /// Answer: draw normally.
    pub fn draw_default() -> isize {
        CDRF_DODEFAULT as isize
    }

    /// Answer after painting the cell yourself.
    pub fn skip_default() -> isize {
        CDRF_SKIPDEFAULT as isize
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
        NM_CUSTOMDRAW => {
            // SAFETY: a list view's NM_CUSTOMDRAW heads an NMLVCUSTOMDRAW,
            // writable for the duration of the notification.
            let raw = unsafe { &mut *(lparam as *mut NMLVCUSTOMDRAW) };
            ControlNotify::ListViewCustomDraw(ListViewCustomDraw { control_id, raw })
        }
        LVN_ITEMCHANGED => {
            // SAFETY: LVN_ITEMCHANGED's NMHDR heads an NMLISTVIEW.
            let change = unsafe { &*(lparam as *const NMLISTVIEW) };
            let selected = LVIS_SELECTED.0;
            let became_selected = change.uChanged.contains(LVIF_STATE)
                && change.uNewState & selected != 0
                && change.uOldState & selected == 0;
            match usize::try_from(change.iItem) {
                Ok(row) if became_selected => ControlNotify::SelectionChanged { control_id, row },
                _ => ControlNotify::Other {
                    control_id,
                    code: LVN_ITEMCHANGED,
                },
            }
        }
        LVN_KEYDOWN => {
            // SAFETY: LVN_KEYDOWN's NMHDR heads an NMLVKEYDOWN, which is
            // packed: the field is read unaligned.
            let key = unsafe {
                std::ptr::read_unaligned(std::ptr::addr_of!(
                    (*(lparam as *const NMLVKEYDOWN)).wVKey
                ))
            };
            ControlNotify::KeyDown { control_id, key }
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
    fn custom_draw_stages_and_colours_decode() {
        use windows::Win32::UI::Controls::NMCUSTOMDRAW;

        let mut raw = NMLVCUSTOMDRAW {
            nmcd: NMCUSTOMDRAW {
                hdr: NMHDR {
                    hwndFrom: HWND::default(),
                    idFrom: 4,
                    code: NM_CUSTOMDRAW,
                },
                dwDrawStage: CDDS_PREPAINT,
                ..Default::default()
            },
            ..Default::default()
        };
        let decode = |raw: &mut NMLVCUSTOMDRAW| {
            // SAFETY: `raw` is a well-formed notification that outlives the decode.
            match unsafe { decode_notify(raw as *mut _ as isize) } {
                Some(ControlNotify::ListViewCustomDraw(draw)) => {
                    (draw.stage(), draw.row(), draw.column())
                }
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(decode(&mut raw).0, DrawStage::PrePaint);

        raw.nmcd.dwDrawStage = CDDS_ITEMPREPAINT;
        raw.nmcd.dwItemSpec = 9;
        assert_eq!(decode(&mut raw), (DrawStage::Row, 9, 0));

        raw.nmcd.dwDrawStage.0 |= CDDS_SUBITEM.0;
        raw.iSubItem = 2;
        assert_eq!(decode(&mut raw), (DrawStage::Cell, 9, 2));

        // SAFETY: as above.
        if let Some(ControlNotify::ListViewCustomDraw(mut draw)) =
            unsafe { decode_notify(&mut raw as *mut _ as isize) }
        {
            draw.set_text_color(0x0000_00FF);
        }
        assert_eq!(raw.clrText.0, 0x0000_00FF);
    }

    #[test]
    fn only_a_newly_selected_row_is_a_selection_change() {
        let mut change = NMLISTVIEW {
            hdr: NMHDR {
                hwndFrom: HWND::default(),
                idFrom: 5,
                code: LVN_ITEMCHANGED,
            },
            iItem: 3,
            uChanged: LVIF_STATE,
            uNewState: LVIS_SELECTED.0,
            uOldState: 0,
            ..Default::default()
        };
        // SAFETY: `change` is a well-formed notification that outlives the decode.
        let notify = unsafe { decode_notify(&mut change as *mut _ as isize) };
        assert!(matches!(
            notify,
            Some(ControlNotify::SelectionChanged {
                control_id: 5,
                row: 3
            })
        ));

        change.uOldState = LVIS_SELECTED.0;
        // SAFETY: as above.
        let notify = unsafe { decode_notify(&mut change as *mut _ as isize) };
        assert!(matches!(notify, Some(ControlNotify::Other { .. })));
    }

    #[test]
    fn list_key_presses_decode() {
        // NMLVKEYDOWN is packed; the control hands it over aligned, as here.
        #[repr(C, align(8))]
        struct Aligned(NMLVKEYDOWN);
        let mut key = Aligned(NMLVKEYDOWN {
            hdr: NMHDR {
                hwndFrom: HWND::default(),
                idFrom: 6,
                code: LVN_KEYDOWN,
            },
            wVKey: 0x43,
            flags: 0,
        });
        // SAFETY: `key` is a well-formed, aligned notification that
        // outlives the decode.
        let notify = unsafe { decode_notify(&mut key.0 as *mut _ as isize) };
        assert!(matches!(
            notify,
            Some(ControlNotify::KeyDown {
                control_id: 6,
                key: 0x43
            })
        ));
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
