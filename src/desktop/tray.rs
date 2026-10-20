use std::cell::RefCell;

use windows::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_NONE,
    NIIF_NOSOUND, NIIF_RESPECT_QUIET_TIME, NIIF_WARNING, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NIM_SETVERSION, NIN_BALLOONUSERCLICK, NIN_SELECT, NOTIFY_ICON_DATA_FLAGS, NOTIFY_ICON_MESSAGE,
    NOTIFYICON_VERSION_4, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetSystemMetrics, HICON, HWND_MESSAGE,
    IDI_APPLICATION, LoadIconW, RegisterClassW, RegisterWindowMessageW, SM_CXSMICON,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_CONTEXTMENU, WNDCLASSW,
};
use windows::core::{PCWSTR, w};

use crate::error::{DesktopError, DesktopOperationError, Error, InvalidParameterError, Result};
use crate::utils::to_utf16_nul;

use super::types::{BalloonIcon, TrayIconId, WindowHandle};
use super::window::load_icon_resource;

const DEFAULT_TRAY_WINDOW_CLASS_NAME: &str = "windows_erg_tray_window";
const DEFAULT_TRAY_WINDOW_NAME: &str = "windows_erg_tray_window";

/// `NIN_KEYSELECT` (`NIN_SELECT | NINF_KEY`): the icon chosen with the keyboard.
const NIN_KEYSELECT: u32 = NIN_SELECT | 0x1;

/// Balloon notification payload for a tray icon.
#[derive(Debug, Clone)]
pub struct TrayNotification {
    /// Notification title.
    pub title: String,
    /// Notification body text.
    pub body: String,
    /// Notification icon style.
    pub icon: BalloonIcon,
    /// Hold the balloon while the user is in quiet time, full-screen or
    /// presenting (`NIIF_RESPECT_QUIET_TIME`).
    pub respect_quiet_time: bool,
    /// Show the balloon without the notification sound (`NIIF_NOSOUND`).
    pub silent: bool,
}

impl TrayNotification {
    /// Create a notification payload.
    pub fn new(title: impl Into<String>, body: impl Into<String>, icon: BalloonIcon) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            icon,
            respect_quiet_time: false,
            silent: false,
        }
    }

    /// Hold the balloon during quiet time (full-screen apps, presentations).
    pub fn respect_quiet_time(mut self) -> Self {
        self.respect_quiet_time = true;
        self
    }

    /// Suppress the notification sound.
    pub fn silent(mut self) -> Self {
        self.silent = true;
        self
    }
}

/// What the user did to a tray icon that has a callback message
/// ([`TrayIconBuilder::callback_message`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayEvent {
    /// Clicked, or chosen with the keyboard.
    Select,
    /// Asked for the context menu, at screen position `(x, y)`.
    ContextMenu {
        /// Horizontal anchor.
        x: i32,
        /// Vertical anchor.
        y: i32,
    },
    /// Clicked the balloon.
    BalloonClicked,
    /// Anything else (mouse moves, button down/up, balloon shown or hidden).
    Other(u32),
}

impl TrayEvent {
    /// Decode the parameters of a callback message (`NOTIFYICON_VERSION_4`
    /// layout: event in the low word of lparam, anchor point in wparam).
    pub fn decode(wparam: usize, lparam: isize) -> Self {
        let event = (lparam as usize & 0xFFFF) as u32;
        match event {
            NIN_SELECT | NIN_KEYSELECT => TrayEvent::Select,
            WM_CONTEXTMENU => TrayEvent::ContextMenu {
                x: i32::from((wparam & 0xFFFF) as u16 as i16),
                y: i32::from(((wparam >> 16) & 0xFFFF) as u16 as i16),
            },
            NIN_BALLOONUSERCLICK => TrayEvent::BalloonClicked,
            other => TrayEvent::Other(other),
        }
    }
}

/// The message Explorer broadcasts when the taskbar is (re)created. A tray
/// owner that receives it must call [`TrayIcon::re_add`].
pub fn taskbar_created_message() -> u32 {
    // SAFETY: registers (or looks up) a constant, NUL-terminated name.
    unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) }
}

/// Notification area icon with RAII lifecycle management.
#[derive(Debug)]
pub struct TrayIcon {
    hwnd: HWND,
    id: TrayIconId,
    icon_added: bool,
    owns_window: bool,
    callback_message: Option<u32>,
    hicon: HICON,
    tooltip: RefCell<String>,
}

impl TrayIcon {
    /// Create a tray icon with an internally managed hidden message window.
    ///
    /// This is a convenience wrapper around [`TrayIconBuilder`], using
    /// default internal class and window names.
    pub fn new(id: TrayIconId, tooltip: &str) -> Result<Self> {
        TrayIconBuilder::new(id, tooltip).create()
    }

    /// Create a tray icon builder.
    ///
    /// Use this when you need to customize the internal message window class name
    /// and/or window name used for tray icon ownership.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use windows_erg::desktop::{TrayIcon, TrayIconId};
    ///
    /// # fn main() -> windows_erg::Result<()> {
    /// let _tray = TrayIcon::builder(TrayIconId::new(1), "demo")
    ///     .window_class_name("my_app_tray_window_class")
    ///     .window_name("my_app_tray_window")
    ///     .create()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder(id: TrayIconId, tooltip: impl Into<String>) -> TrayIconBuilder {
        TrayIconBuilder::new(id, tooltip)
    }

    /// Create a tray icon bound to an existing window handle.
    pub fn from_window(owner: WindowHandle, id: TrayIconId, tooltip: &str) -> Result<Self> {
        TrayIconBuilder::new(id, tooltip)
            .owner_window(owner)
            .create()
    }

    /// Show a tray balloon notification.
    pub fn show_notification(&self, notification: &TrayNotification) -> Result<()> {
        let mut data = self.base_notify_data();
        data.uFlags = NIF_INFO;
        data.szInfo = fixed_text(&notification.body);
        data.szInfoTitle = fixed_text(&notification.title);
        let mut flags = match notification.icon {
            BalloonIcon::None => NIIF_NONE,
            BalloonIcon::Info => NIIF_INFO,
            BalloonIcon::Warning => NIIF_WARNING,
            BalloonIcon::Error => NIIF_ERROR,
        };
        if notification.respect_quiet_time {
            flags |= NIIF_RESPECT_QUIET_TIME;
        }
        if notification.silent {
            flags |= NIIF_NOSOUND;
        }
        data.dwInfoFlags = flags;

        notify(NIM_MODIFY, &data, "NIM_MODIFY notification")
    }

    /// Update tray icon tooltip text.
    pub fn update_tooltip(&self, tooltip: &str) -> Result<()> {
        let mut data = self.base_notify_data();
        data.uFlags = NIF_TIP | self.show_tip_flag();
        data.szTip = fixed_text(tooltip);

        notify(NIM_MODIFY, &data, "NIM_MODIFY tooltip")?;
        *self.tooltip.borrow_mut() = tooltip.to_string();
        Ok(())
    }

    /// Show the icon with this resource id from the executable instead.
    pub fn set_icon_resource(&mut self, id: u16) -> Result<()> {
        // SAFETY: GetSystemMetrics only reads a metric.
        let hicon = load_icon_resource(id, unsafe { GetSystemMetrics(SM_CXSMICON) })?;
        let mut data = self.base_notify_data();
        data.uFlags = NIF_ICON;
        data.hIcon = hicon;
        notify(NIM_MODIFY, &data, "NIM_MODIFY icon")?;
        self.hicon = hicon;
        Ok(())
    }

    /// Add the icon again after Explorer restarted (on the message from
    /// [`taskbar_created_message`]), with its last tooltip.
    pub fn re_add(&mut self) -> Result<()> {
        self.icon_added = false;
        let tooltip = self.tooltip.borrow().clone();
        self.add_icon(&tooltip)
    }

    /// Explicitly remove the tray icon.
    pub fn remove(&mut self) -> Result<()> {
        if !self.icon_added {
            return Ok(());
        }

        let data = self.base_notify_data();
        notify(NIM_DELETE, &data, "NIM_DELETE")?;
        self.icon_added = false;
        Ok(())
    }

    fn add_icon(&mut self, tooltip: &str) -> Result<()> {
        let mut data = self.base_notify_data();
        let mut flags = NIF_ICON | NIF_TIP | self.show_tip_flag();
        data.hIcon = self.hicon;
        data.szTip = fixed_text(tooltip);
        if let Some(message) = self.callback_message {
            flags |= NIF_MESSAGE;
            data.uCallbackMessage = message;
        }
        data.uFlags = flags;

        notify(NIM_ADD, &data, "NIM_ADD")?;
        self.icon_added = true;
        *self.tooltip.borrow_mut() = tooltip.to_string();

        if self.callback_message.is_some() {
            let mut version = self.base_notify_data();
            version.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            notify(NIM_SETVERSION, &version, "NIM_SETVERSION")?;
        }
        Ok(())
    }

    /// Version 4 icons show the standard tooltip only with `NIF_SHOWTIP`.
    fn show_tip_flag(&self) -> NOTIFY_ICON_DATA_FLAGS {
        if self.callback_message.is_some() {
            NIF_SHOWTIP
        } else {
            NOTIFY_ICON_DATA_FLAGS(0)
        }
    }

    fn base_notify_data(&self) -> NOTIFYICONDATAW {
        NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.hwnd,
            uID: self.id.as_u32(),
            ..Default::default()
        }
    }
}

/// Builder for creating tray icons with custom internal window names.
#[derive(Debug, Clone)]
pub struct TrayIconBuilder {
    id: TrayIconId,
    tooltip: String,
    owner: Option<WindowHandle>,
    window_class_name: String,
    window_name: String,
    callback_message: Option<u32>,
    icon_resource: Option<u16>,
}

impl TrayIconBuilder {
    /// Create a new tray icon builder with default class and window names.
    pub fn new(id: TrayIconId, tooltip: impl Into<String>) -> Self {
        Self {
            id,
            tooltip: tooltip.into(),
            owner: None,
            window_class_name: DEFAULT_TRAY_WINDOW_CLASS_NAME.to_string(),
            window_name: DEFAULT_TRAY_WINDOW_NAME.to_string(),
            callback_message: None,
            icon_resource: None,
        }
    }

    /// Bind the tray icon to an existing owner window.
    ///
    /// When set, custom class and window names are ignored because this builder
    /// does not create an internal message-only window.
    pub fn owner_window(mut self, owner: WindowHandle) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Set the class name used when creating an internal message-only tray window.
    pub fn window_class_name(mut self, name: impl Into<String>) -> Self {
        self.window_class_name = name.into();
        self
    }

    /// Set the window name used when creating an internal message-only tray window.
    pub fn window_name(mut self, name: impl Into<String>) -> Self {
        self.window_name = name.into();
        self
    }

    /// Send user actions on the icon to the owner window as `message`
    /// (decode with [`TrayEvent::decode`]). Uses `NOTIFYICON_VERSION_4`.
    /// Only useful with [`Self::owner_window`]: the internal window ignores them.
    pub fn callback_message(mut self, message: u32) -> Self {
        self.callback_message = Some(message);
        self
    }

    /// Use the icon with this resource id from the executable instead of
    /// the generic application icon.
    pub fn icon_resource(mut self, id: u16) -> Self {
        self.icon_resource = Some(id);
        self
    }

    /// Create the tray icon instance.
    pub fn create(self) -> Result<TrayIcon> {
        validate_window_name("window_class_name", &self.window_class_name)?;
        validate_window_name("window_name", &self.window_name)?;

        let hicon = match self.icon_resource {
            // SAFETY: GetSystemMetrics only reads a metric.
            Some(id) => load_icon_resource(id, unsafe { GetSystemMetrics(SM_CXSMICON) })?,
            None => load_default_icon(),
        };

        let hwnd = match self.owner {
            Some(owner) => owner.into(),
            None => create_message_window(&self.window_class_name, &self.window_name)?,
        };

        let mut icon = TrayIcon {
            hwnd,
            id: self.id,
            icon_added: false,
            owns_window: self.owner.is_none(),
            callback_message: self.callback_message,
            hicon,
            tooltip: RefCell::new(String::new()),
        };

        icon.add_icon(&self.tooltip)?;
        Ok(icon)
    }
}

impl Drop for TrayIcon {
    fn drop(&mut self) {
        let _ = self.remove();

        if self.owns_window && !self.hwnd.0.is_null() {
            // SAFETY: the window was created by this icon and is destroyed once.
            unsafe {
                let _ = DestroyWindow(self.hwnd);
            }
        }
    }
}

fn notify(message: NOTIFY_ICON_MESSAGE, data: &NOTIFYICONDATAW, what: &'static str) -> Result<()> {
    // SAFETY: `data` is a valid, sized NOTIFYICONDATAW.
    if unsafe { Shell_NotifyIconW(message, data) }.as_bool() {
        return Ok(());
    }
    // SAFETY: reads the calling thread's last-error value.
    let code = unsafe { GetLastError().0 as i32 };
    Err(Error::Desktop(DesktopError::OperationFailed(
        DesktopOperationError::with_code("Shell_NotifyIconW", what, code),
    )))
}

fn create_message_window(class_name: &str, window_name: &str) -> Result<HWND> {
    // SAFETY: `None` asks for the executable's own module handle.
    let instance = unsafe { GetModuleHandleW(None) }.map_err(|e| {
        Error::Desktop(DesktopError::OperationFailed(
            DesktopOperationError::with_code("GetModuleHandleW", "tray window class", e.code().0),
        ))
    })?;

    let class_name_wide = to_utf16_nul(class_name);
    let window_name_wide = to_utf16_nul(window_name);

    let wnd_class = WNDCLASSW {
        lpfnWndProc: Some(tray_window_proc),
        hInstance: instance.into(),
        lpszClassName: PCWSTR(class_name_wide.as_ptr()),
        ..Default::default()
    };

    // SAFETY: `wnd_class` and its name buffer outlive the call.
    let class_atom = unsafe { RegisterClassW(&wnd_class) };
    if class_atom == 0 {
        // SAFETY: reads the calling thread's last-error value.
        let code = unsafe { GetLastError() };
        if code != ERROR_CLASS_ALREADY_EXISTS {
            return Err(Error::Desktop(DesktopError::OperationFailed(
                DesktopOperationError::with_code(
                    "RegisterClassW",
                    class_name.to_string(),
                    code.0 as i32,
                ),
            )));
        }
    }

    // SAFETY: the name buffers outlive the call; a message-only window.
    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name_wide.as_ptr()),
            PCWSTR(window_name_wide.as_ptr()),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance.into()),
            None,
        )
    }
    .map_err(|e| {
        Error::Desktop(DesktopError::OperationFailed(
            DesktopOperationError::with_code("CreateWindowExW", "tray message window", e.code().0),
        ))
    })?;

    Ok(hwnd)
}

fn load_default_icon() -> HICON {
    // SAFETY: a predefined system icon; no module handle is needed.
    unsafe { LoadIconW(None, IDI_APPLICATION).unwrap_or_default() }
}

unsafe extern "system" fn tray_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: default processing for the internal message window.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Returns `text` as a NUL-terminated, truncated UTF-16 buffer. Returned by
/// value because `NOTIFYICONDATAW` is packed on x86, where `&mut` to its
/// fields would be unaligned.
fn fixed_text<const N: usize>(text: &str) -> [u16; N] {
    let mut destination = [0u16; N];
    for (slot, ch) in destination
        .iter_mut()
        .take(N.saturating_sub(1))
        .zip(text.encode_utf16())
    {
        *slot = ch;
    }
    destination
}

fn validate_window_name(field: &'static str, value: &str) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_4_callbacks_decode() {
        assert_eq!(TrayEvent::decode(0, NIN_SELECT as isize), TrayEvent::Select);
        assert_eq!(
            TrayEvent::decode(0, NIN_KEYSELECT as isize),
            TrayEvent::Select
        );
        // Icon id 3 in the high word must not change the event.
        let lparam = ((3 << 16) | WM_CONTEXTMENU) as isize;
        let wparam = (200usize << 16) | 100;
        assert_eq!(
            TrayEvent::decode(wparam, lparam),
            TrayEvent::ContextMenu { x: 100, y: 200 }
        );
        assert_eq!(
            TrayEvent::decode(0, NIN_BALLOONUSERCLICK as isize),
            TrayEvent::BalloonClicked
        );
        assert_eq!(TrayEvent::decode(0, 0x200), TrayEvent::Other(0x200));
    }

    #[test]
    fn negative_anchor_coordinates_survive() {
        // A secondary monitor left of the primary has negative x.
        let wparam = (50usize << 16) | 0xFFF6; // x = -10
        assert_eq!(
            TrayEvent::decode(wparam, WM_CONTEXTMENU as isize),
            TrayEvent::ContextMenu { x: -10, y: 50 }
        );
    }
}
