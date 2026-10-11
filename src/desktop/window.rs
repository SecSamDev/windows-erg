//! Window classes, owned windows, message posting and the message loop.

use std::ffi::c_void;

use windows::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, RECT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{COLOR_WINDOW, HBRUSH, InvalidateRect};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, CW_USEDEFAULT, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GWLP_USERDATA, GetClientRect, GetMessageW, GetWindowLongPtrW, GetWindowRect, HICON,
    HWND_MESSAGE, IDC_ARROW, IMAGE_ICON, IsDialogMessageW, IsWindow, IsWindowVisible,
    LR_DEFAULTSIZE, LR_SHARED, LoadCursorW, LoadImageW, MSG, MoveWindow, PostMessageW,
    PostQuitMessage, RegisterClassExW, SW_HIDE, SW_RESTORE, SW_SHOW, SetForegroundWindow,
    SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage, WINDOW_EX_STYLE, WINDOW_STYLE,
    WM_NCCREATE, WM_NCDESTROY, WNDCLASSEXW, WS_OVERLAPPEDWINDOW,
};
use windows::core::PCWSTR;

use crate::error::{DesktopError, DesktopOperationError, Error, InvalidParameterError, Result};
use crate::utils::to_utf16_nul;

use super::types::{WindowHandle, WindowRect};

/// Receives the messages of a window created with [`WindowBuilder::create`].
///
/// The handler takes `&self` because Win32 re-enters a window procedure
/// whenever the handler itself calls something that sends a message
/// (showing a window sends `WM_SIZE`, for example). Keep mutable state in
/// `Cell`/`RefCell` fields and hold a borrow only for as long as it is used.
pub trait WindowHandler {
    /// Handle one message. Return `Some(result)` when the message was
    /// handled, or `None` to fall through to `DefWindowProcW`.
    fn handle(&self, window: WindowHandle, msg: u32, wparam: usize, lparam: isize)
    -> Option<isize>;
}

/// A registered window class whose procedure dispatches to a [`WindowHandler`].
#[derive(Debug, Clone)]
pub struct WindowClass {
    name: Vec<u16>,
}

impl WindowClass {
    /// Start building a window class named `name`.
    pub fn builder(name: impl Into<String>) -> WindowClassBuilder {
        WindowClassBuilder {
            name: name.into(),
            icon_resource: None,
        }
    }
}

/// Builder for [`WindowClass`].
#[derive(Debug, Clone)]
pub struct WindowClassBuilder {
    name: String,
    icon_resource: Option<u16>,
}

impl WindowClassBuilder {
    /// Use the icon with this resource id from the executable as the class icon.
    pub fn icon_resource(mut self, id: u16) -> Self {
        self.icon_resource = Some(id);
        self
    }

    /// Register the class. Registering a name that already exists in this
    /// process is not an error: the existing class is reused.
    pub fn register(self) -> Result<WindowClass> {
        validate_name("class_name", &self.name)?;
        let instance = module_instance("RegisterClassExW")?;
        let name = to_utf16_nul(&self.name);
        let icon = match self.icon_resource {
            Some(id) => load_icon_resource(id, 0)?,
            None => HICON::default(),
        };
        // SAFETY: IDC_ARROW is a predefined system cursor; no module handle is needed.
        let cursor = unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default();

        let class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(handler_window_proc),
            hInstance: instance.into(),
            hIcon: icon,
            hIconSm: icon,
            hCursor: cursor,
            // The documented `COLOR_WINDOW + 1` system-colour brush.
            hbrBackground: HBRUSH((COLOR_WINDOW.0 + 1) as isize as *mut c_void),
            lpszClassName: PCWSTR(name.as_ptr()),
            ..Default::default()
        };

        // SAFETY: `class` and the name buffer it points to outlive the call.
        let atom = unsafe { RegisterClassExW(&class) };
        if atom == 0 {
            // SAFETY: reads the calling thread's last-error value.
            let code = unsafe { GetLastError() };
            if code != ERROR_CLASS_ALREADY_EXISTS {
                return Err(op_error("RegisterClassExW", self.name, code.0 as i32));
            }
        }

        Ok(WindowClass { name })
    }
}

/// Builder for a window bound to a [`WindowHandler`].
#[derive(Debug, Clone)]
pub struct WindowBuilder<'a> {
    class: &'a WindowClass,
    title: String,
    size: Option<(i32, i32)>,
    message_only: bool,
}

impl<'a> WindowBuilder<'a> {
    /// Start building a window of `class`.
    pub fn new(class: &'a WindowClass) -> Self {
        Self {
            class,
            title: String::new(),
            size: None,
            message_only: false,
        }
    }

    /// Window title.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Initial outer size in physical pixels. The system picks one otherwise.
    pub fn size(mut self, width: i32, height: i32) -> Self {
        self.size = Some((width, height));
        self
    }

    /// Create a message-only window (never visible, receives posted messages).
    pub fn message_only(mut self) -> Self {
        self.message_only = true;
        self
    }

    /// Create the window, hidden. `handler` receives every message from
    /// `WM_NCCREATE` on and is dropped after `WM_NCDESTROY`.
    pub fn create(self, handler: Box<dyn WindowHandler>) -> Result<Window> {
        let instance = module_instance("CreateWindowExW")?;
        let title = to_utf16_nul(&self.title);
        let (width, height) = self.size.unwrap_or((CW_USEDEFAULT, CW_USEDEFAULT));
        let (style, parent) = if self.message_only {
            (WINDOW_STYLE(0), HWND_MESSAGE)
        } else {
            (WS_OVERLAPPEDWINDOW, HWND::default())
        };

        // Double-boxed so the window procedure gets a thin pointer back.
        let slot: *mut Box<dyn WindowHandler> = Box::into_raw(Box::new(handler));

        // SAFETY: the class and title buffers outlive the call. `slot` is a
        // valid heap pointer; the window procedure takes ownership of it on
        // WM_NCCREATE and frees it on WM_NCDESTROY.
        let created = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(self.class.name.as_ptr()),
                PCWSTR(title.as_ptr()),
                style,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                width,
                height,
                parent,
                None,
                instance,
                Some(slot as *const c_void),
            )
        };

        // On failure the handler is leaked rather than freed: whether
        // WM_NCCREATE ran (and WM_NCDESTROY already freed it) is unknowable
        // here, and a leak is the only safe outcome.
        let hwnd = created.map_err(|e| op_error("CreateWindowExW", self.title, e.code().0))?;
        Ok(Window { hwnd })
    }
}

/// An owned top-level or message-only window. Dropping it destroys the window.
#[derive(Debug)]
pub struct Window {
    hwnd: HWND,
}

impl Window {
    /// The window's handle, for the operations on [`WindowHandle`].
    pub fn handle(&self) -> WindowHandle {
        self.hwnd.into()
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // SAFETY: IsWindow accepts any value; DestroyWindow runs only on a
        // window that still exists, from the thread that owns `Window`
        // (`Window` is neither Send nor Sync).
        unsafe {
            if IsWindow(self.hwnd).as_bool() {
                let _ = DestroyWindow(self.hwnd);
            }
        }
    }
}

impl WindowHandle {
    /// Show the window, restoring it if minimised.
    pub fn show(self) {
        // SAFETY: ShowWindow validates the handle; the return value is the
        // previous visibility, not an error.
        unsafe {
            let _ = ShowWindow(HWND::from(self), SW_SHOW);
            let _ = ShowWindow(HWND::from(self), SW_RESTORE);
        }
    }

    /// Hide the window.
    pub fn hide(self) {
        // SAFETY: as in `show`.
        unsafe {
            let _ = ShowWindow(HWND::from(self), SW_HIDE);
        }
    }

    /// Whether the window is visible.
    pub fn is_visible(self) -> bool {
        // SAFETY: IsWindowVisible validates the handle.
        unsafe { IsWindowVisible(HWND::from(self)) }.as_bool()
    }

    /// Bring the window to the foreground. Windows may refuse; that is not an error.
    pub fn set_foreground(self) -> bool {
        // SAFETY: SetForegroundWindow validates the handle.
        unsafe { SetForegroundWindow(HWND::from(self)) }.as_bool()
    }

    /// Set the window (or control) text.
    pub fn set_text(self, text: &str) -> Result<()> {
        let wide = to_utf16_nul(text);
        // SAFETY: `wide` is NUL-terminated and outlives the call.
        unsafe { SetWindowTextW(HWND::from(self), PCWSTR(wide.as_ptr())) }
            .map_err(|e| op_error("SetWindowTextW", "window text", e.code().0))
    }

    /// The client area, in client coordinates (left and top are 0).
    pub fn client_rect(self) -> Result<WindowRect> {
        let mut rect = RECT::default();
        // SAFETY: `rect` is a valid out pointer.
        unsafe { GetClientRect(HWND::from(self), &mut rect) }
            .map_err(|e| op_error("GetClientRect", "window", e.code().0))?;
        Ok(rect.into())
    }

    /// The outer rectangle, in screen coordinates.
    pub fn window_rect(self) -> Result<WindowRect> {
        let mut rect = RECT::default();
        // SAFETY: `rect` is a valid out pointer.
        unsafe { GetWindowRect(HWND::from(self), &mut rect) }
            .map_err(|e| op_error("GetWindowRect", "window", e.code().0))?;
        Ok(rect.into())
    }

    /// Move and resize: screen coordinates for a top-level window, parent
    /// client coordinates for a child.
    pub fn set_bounds(self, rect: WindowRect) -> Result<()> {
        // SAFETY: MoveWindow validates the handle.
        unsafe {
            MoveWindow(
                HWND::from(self),
                rect.left,
                rect.top,
                rect.width(),
                rect.height(),
                true,
            )
        }
        .map_err(|e| op_error("MoveWindow", "window", e.code().0))
    }

    /// Mark the whole client area for repainting.
    pub fn invalidate(self) {
        // SAFETY: InvalidateRect validates the handle; `None` means the whole area.
        unsafe {
            let _ = InvalidateRect(HWND::from(self), None, false);
        }
    }

    /// Destroy the window. Only the thread that created it may do this.
    pub fn destroy(self) -> Result<()> {
        // SAFETY: DestroyWindow validates the handle and fails from another thread.
        unsafe { DestroyWindow(HWND::from(self)) }
            .map_err(|e| op_error("DestroyWindow", "window", e.code().0))
    }

    /// A handle another thread can use to post messages to this window.
    pub fn poster(self) -> MessagePoster {
        MessagePoster {
            hwnd: self.0 as usize,
        }
    }
}

/// Posts messages to a window from any thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessagePoster {
    hwnd: usize,
}

impl MessagePoster {
    /// Post `msg` to the window's queue. Fails once the window is destroyed.
    pub fn post(self, msg: u32, wparam: usize, lparam: isize) -> Result<()> {
        // SAFETY: PostMessageW validates the handle; it is safe from any thread.
        unsafe {
            PostMessageW(
                HWND(self.hwnd as *mut c_void),
                msg,
                WPARAM(wparam),
                LPARAM(lparam),
            )
        }
        .map_err(|e| op_error("PostMessageW", "window", e.code().0))
    }
}

/// Run the calling thread's message loop until [`post_quit`]. Returns the
/// exit code passed to it, or -1 if `GetMessageW` fails.
///
/// When `dialog` is given, keyboard navigation (Tab between controls) is
/// handled for that window.
pub fn run_message_loop(dialog: Option<WindowHandle>) -> i32 {
    let mut msg = MSG::default();
    loop {
        // SAFETY: `msg` is a valid out pointer; a null HWND reads every
        // message of this thread.
        let got = unsafe { GetMessageW(&mut msg, None, 0, 0) };
        match got.0 {
            0 => return msg.wParam.0 as i32,
            -1 => return -1,
            _ => {}
        }
        if let Some(dialog) = dialog {
            // SAFETY: `msg` was just filled by GetMessageW.
            if unsafe { IsDialogMessageW(HWND::from(dialog), &msg) }.as_bool() {
                continue;
            }
        }
        // SAFETY: `msg` was just filled by GetMessageW.
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// Ask the calling thread's message loop to end with `code`.
pub fn post_quit(code: i32) {
    // SAFETY: only posts WM_QUIT to the calling thread.
    unsafe { PostQuitMessage(code) }
}

/// Load an icon from the executable's resources. `size` 0 uses the system
/// default icon size. The icon is shared and must not be destroyed.
pub(crate) fn load_icon_resource(id: u16, size: i32) -> Result<HICON> {
    let instance = module_instance("LoadImageW")?;
    let flags = if size == 0 {
        LR_SHARED | LR_DEFAULTSIZE
    } else {
        LR_SHARED
    };
    // SAFETY: an integer resource id passed as MAKEINTRESOURCEW; LoadImageW
    // only reads the module's resource table.
    let handle = unsafe {
        LoadImageW(
            instance,
            PCWSTR(id as usize as *const u16),
            IMAGE_ICON,
            size,
            size,
            flags,
        )
    }
    .map_err(|e| op_error("LoadImageW", format!("icon resource {id}"), e.code().0))?;
    Ok(HICON(handle.0))
}

fn module_instance(operation: &'static str) -> Result<windows::Win32::Foundation::HMODULE> {
    // SAFETY: `None` asks for the executable's own module handle.
    unsafe { GetModuleHandleW(None) }
        .map_err(|e| op_error(operation, "GetModuleHandleW", e.code().0))
}

pub(crate) fn op_error(
    operation: &'static str,
    target: impl Into<std::borrow::Cow<'static, str>>,
    code: i32,
) -> Error {
    Error::Desktop(DesktopError::OperationFailed(
        DesktopOperationError::with_code(operation, target, code),
    ))
}

pub(crate) fn validate_name(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidParameter(InvalidParameterError::new(
            field,
            "value cannot be empty",
        )));
    }
    if value.contains('\0') {
        return Err(Error::InvalidParameter(InvalidParameterError::new(
            field,
            "value cannot contain NUL characters",
        )));
    }
    Ok(())
}

unsafe extern "system" fn handler_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_NCCREATE {
        // SAFETY: for WM_NCCREATE, lparam points to the CREATESTRUCTW whose
        // lpCreateParams is the slot `WindowBuilder::create` passed.
        let slot = unsafe { (*(lparam.0 as *const CREATESTRUCTW)).lpCreateParams };
        // SAFETY: stores the slot pointer in this window's user data.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, slot as isize) };
    }

    // SAFETY: reads this window's user data, set above or still zero.
    let slot = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut Box<dyn WindowHandler>;
    let result = if slot.is_null() {
        None
    } else {
        // SAFETY: the slot stays valid until WM_NCDESTROY below; only shared
        // references are made, so re-entrant calls are sound.
        unsafe { (*slot).handle(hwnd.into(), msg, wparam.0, lparam.0) }
    };

    if msg == WM_NCDESTROY && !slot.is_null() {
        // SAFETY: WM_NCDESTROY is the last message; the slot is detached
        // first, then freed exactly once.
        unsafe {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            drop(Box::from_raw(slot));
        }
    }

    match result {
        Some(value) => LRESULT(value),
        // SAFETY: default processing for an unhandled message.
        None => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names_are_validated() {
        assert!(WindowClass::builder("").register().is_err());
        assert!(WindowClass::builder("a\0b").register().is_err());
    }
}
