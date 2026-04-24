use windows::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_NONE, NIIF_WARNING, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, HICON, HWND_MESSAGE, IDI_APPLICATION,
    LoadIconW, RegisterClassW, WINDOW_EX_STYLE, WINDOW_STYLE, WNDCLASSW,
};
use windows::core::PCWSTR;

use crate::error::{DesktopError, DesktopOperationError, Error, InvalidParameterError, Result};
use crate::utils::to_utf16_nul;

use super::types::{BalloonIcon, TrayIconId, WindowHandle};

const DEFAULT_TRAY_WINDOW_CLASS_NAME: &str = "windows_erg_tray_window";
const DEFAULT_TRAY_WINDOW_NAME: &str = "windows_erg_tray_window";

/// Balloon notification payload for a tray icon.
#[derive(Debug, Clone)]
pub struct TrayNotification {
    /// Notification title.
    pub title: String,
    /// Notification body text.
    pub body: String,
    /// Notification icon style.
    pub icon: BalloonIcon,
}

impl TrayNotification {
    /// Create a notification payload.
    pub fn new(title: impl Into<String>, body: impl Into<String>, icon: BalloonIcon) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            icon,
        }
    }
}

/// Notification area icon with RAII lifecycle management.
#[derive(Debug)]
pub struct TrayIcon {
    hwnd: HWND,
    id: TrayIconId,
    icon_added: bool,
    owns_window: bool,
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
        let mut icon = TrayIcon {
            hwnd: owner.into(),
            id,
            icon_added: false,
            owns_window: false,
        };

        icon.add_icon(tooltip)?;
        Ok(icon)
    }

    /// Show a tray balloon notification.
    pub fn show_notification(&self, notification: &TrayNotification) -> Result<()> {
        let mut data = self.base_notify_data();
        data.uFlags = NIF_INFO;
        copy_text_to_fixed(&notification.body, &mut data.szInfo);
        copy_text_to_fixed(&notification.title, &mut data.szInfoTitle);
        data.dwInfoFlags = match notification.icon {
            BalloonIcon::None => NIIF_NONE,
            BalloonIcon::Info => NIIF_INFO,
            BalloonIcon::Warning => NIIF_WARNING,
            BalloonIcon::Error => NIIF_ERROR,
        };

        let ok = unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) }.as_bool();
        if ok {
            return Ok(());
        }

        let code = unsafe { GetLastError().0 as i32 };
        Err(Error::Desktop(DesktopError::OperationFailed(
            DesktopOperationError::with_code("Shell_NotifyIconW", "NIM_MODIFY notification", code),
        )))
    }

    /// Update tray icon tooltip text.
    pub fn update_tooltip(&self, tooltip: &str) -> Result<()> {
        let mut data = self.base_notify_data();
        data.uFlags = NIF_TIP;
        copy_text_to_fixed(tooltip, &mut data.szTip);

        let ok = unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) }.as_bool();
        if ok {
            return Ok(());
        }

        let code = unsafe { GetLastError().0 as i32 };
        Err(Error::Desktop(DesktopError::OperationFailed(
            DesktopOperationError::with_code("Shell_NotifyIconW", "NIM_MODIFY tooltip", code),
        )))
    }

    /// Explicitly remove the tray icon.
    pub fn remove(&mut self) -> Result<()> {
        if !self.icon_added {
            return Ok(());
        }

        let data = self.base_notify_data();
        let ok = unsafe { Shell_NotifyIconW(NIM_DELETE, &data) }.as_bool();
        if !ok {
            let code = unsafe { GetLastError().0 as i32 };
            return Err(Error::Desktop(DesktopError::OperationFailed(
                DesktopOperationError::with_code("Shell_NotifyIconW", "NIM_DELETE", code),
            )));
        }

        self.icon_added = false;
        Ok(())
    }

    fn add_icon(&mut self, tooltip: &str) -> Result<()> {
        let mut data = self.base_notify_data();
        data.uFlags = NIF_ICON | NIF_TIP;
        data.hIcon = load_default_icon();
        copy_text_to_fixed(tooltip, &mut data.szTip);

        let ok = unsafe { Shell_NotifyIconW(NIM_ADD, &data) }.as_bool();
        if !ok {
            let code = unsafe { GetLastError().0 as i32 };
            return Err(Error::Desktop(DesktopError::OperationFailed(
                DesktopOperationError::with_code("Shell_NotifyIconW", "NIM_ADD", code),
            )));
        }

        self.icon_added = true;
        Ok(())
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

    /// Create the tray icon instance.
    pub fn create(self) -> Result<TrayIcon> {
        validate_window_name("window_class_name", &self.window_class_name)?;
        validate_window_name("window_name", &self.window_name)?;

        let hwnd = match self.owner {
            Some(owner) => owner.into(),
            None => create_message_window(&self.window_class_name, &self.window_name)?,
        };

        let mut icon = TrayIcon {
            hwnd,
            id: self.id,
            icon_added: false,
            owns_window: self.owner.is_none(),
        };

        icon.add_icon(&self.tooltip)?;
        Ok(icon)
    }
}

impl Drop for TrayIcon {
    fn drop(&mut self) {
        let _ = self.remove();

        if self.owns_window && !self.hwnd.0.is_null() {
            unsafe {
                let _ = DestroyWindow(self.hwnd);
            }
        }
    }
}

fn create_message_window(class_name: &str, window_name: &str) -> Result<HWND> {
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

    let class_atom = unsafe { RegisterClassW(&wnd_class) };
    if class_atom == 0 {
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
            HWND_MESSAGE,
            None,
            instance,
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
    unsafe { LoadIconW(None, IDI_APPLICATION).unwrap_or_default() }
}

unsafe extern "system" fn tray_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn copy_text_to_fixed<const N: usize>(text: &str, destination: &mut [u16; N]) {
    destination.fill(0);
    let mut encoded = text.encode_utf16();

    for slot in destination.iter_mut().take(N.saturating_sub(1)) {
        if let Some(ch) = encoded.next() {
            *slot = ch;
        } else {
            break;
        }
    }
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
