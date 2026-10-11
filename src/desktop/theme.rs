//! Light and dark appearance: the system preference, the title bar, the
//! window backdrop, themed common controls and menus.

use windows::Win32::Foundation::{BOOL, HWND};
use windows::Win32::Graphics::Dwm::{
    DWM_SYSTEMBACKDROP_TYPE, DWMSBT_MAINWINDOW, DWMSBT_NONE, DWMWA_SYSTEMBACKDROP_TYPE,
    DWMWA_USE_IMMERSIVE_DARK_MODE, DwmSetWindowAttribute,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::UI::Controls::SetWindowTheme;
use windows::Win32::UI::WindowsAndMessaging::WM_SETTINGCHANGE;
use windows::core::{PCSTR, PCWSTR, w};

use crate::registry::{self, Hive};

use super::types::WindowHandle;

const PERSONALIZE_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

/// Whether the user chose dark mode for apps (Settings > Personalization >
/// Colors). Light when the value is missing.
pub fn system_prefers_dark() -> bool {
    registry::read_u32(Hive::CurrentUser, PERSONALIZE_KEY, "AppsUseLightTheme")
        .is_ok_and(|light| light == 0)
}

/// Whether a `WM_SETTINGCHANGE` announces a light/dark switch
/// (`"ImmersiveColorSet"`).
pub fn is_theme_change(msg: u32, lparam: isize) -> bool {
    if msg != WM_SETTINGCHANGE || lparam == 0 {
        return false;
    }
    // SAFETY: for WM_SETTINGCHANGE a non-null lparam is a NUL-terminated
    // UTF-16 string valid while the message is handled.
    let area = unsafe { PCWSTR(lparam as *const u16).to_string() };
    area.is_ok_and(|area| area == "ImmersiveColorSet")
}

/// Dark or light title bar (Windows 10 2004 and later; ignored before).
pub fn set_dark_title_bar(window: WindowHandle, dark: bool) {
    let value = BOOL::from(dark);
    // SAFETY: a BOOL attribute with its exact size.
    let _ = unsafe {
        DwmSetWindowAttribute(
            HWND::from(window),
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &value as *const BOOL as *const _,
            std::mem::size_of::<BOOL>() as u32,
        )
    };
}

/// A system backdrop for the window frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backdrop {
    /// No system backdrop.
    None,
    /// Mica (Windows 11 22H2 and later; ignored before).
    Mica,
}

/// Set the window's system backdrop.
pub fn set_backdrop(window: WindowHandle, backdrop: Backdrop) {
    let value: DWM_SYSTEMBACKDROP_TYPE = match backdrop {
        Backdrop::None => DWMSBT_NONE,
        Backdrop::Mica => DWMSBT_MAINWINDOW,
    };
    // SAFETY: an enum attribute with its exact size.
    let _ = unsafe {
        DwmSetWindowAttribute(
            HWND::from(window),
            DWMWA_SYSTEMBACKDROP_TYPE,
            &value as *const DWM_SYSTEMBACKDROP_TYPE as *const _,
            std::mem::size_of::<DWM_SYSTEMBACKDROP_TYPE>() as u32,
        )
    };
}

/// Appearance of a common control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlTheme {
    /// The light items-view look of Windows 11 lists (no column lines).
    Light,
    /// The dark items-view look Explorer uses in dark mode, for a header.
    Dark,
    /// Explorer's dark look, for a list view: dark scroll bars too.
    DarkExplorer,
}

/// Theme a common control (a list view, its header, a scroll bar).
///
/// For the dark themes the control is first opted in to dark mode
/// with uxtheme's `AllowDarkModeForWindow` (ordinal 133, undocumented like
/// [`allow_dark_menus`]); without it a header keeps dark text on its dark
/// background. Skipped where the export is missing.
pub fn set_control_theme(control: WindowHandle, theme: ControlTheme) {
    allow_dark_mode_for_window(control, theme != ControlTheme::Light);
    let name = match theme {
        ControlTheme::Light => w!("ItemsView"),
        ControlTheme::Dark => w!("DarkMode_ItemsView"),
        ControlTheme::DarkExplorer => w!("DarkMode_Explorer"),
    };
    // SAFETY: a constant theme name; failure keeps the current look.
    let _ = unsafe { SetWindowTheme(HWND::from(control), name, PCWSTR::null()) };
}

fn uxtheme_ordinal(ordinal: usize) -> Option<unsafe extern "system" fn() -> isize> {
    // SAFETY: loads a system DLL by name.
    let module = unsafe { LoadLibraryW(w!("uxtheme.dll")) }.ok()?;
    // SAFETY: an ordinal lookup (MAKEINTRESOURCEA(ordinal)).
    unsafe { GetProcAddress(module, PCSTR(ordinal as *const u8)) }
}

fn allow_dark_mode_for_window(control: WindowHandle, allow: bool) {
    let Some(proc) = uxtheme_ordinal(133) else {
        return;
    };
    // SAFETY: export 133 is `BOOL AllowDarkModeForWindow(HWND, BOOL)` since
    // Windows 10 1809.
    let allow_dark: unsafe extern "system" fn(HWND, BOOL) -> BOOL =
        unsafe { std::mem::transmute(proc) };
    // SAFETY: plain call on a window handle.
    let _ = unsafe { allow_dark(HWND::from(control), BOOL::from(allow)) };
}

/// Let popup menus follow dark mode.
///
/// There is no documented API for this. It calls uxtheme's
/// `SetPreferredAppMode` (ordinal 135, Windows 10 1903 and later), as
/// Explorer and many desktop apps do, and does nothing when that export is
/// missing.
pub fn allow_dark_menus(dark: bool) {
    let Some(proc) = uxtheme_ordinal(135) else {
        return;
    };
    // PreferredAppMode: 0 default, 1 allow dark, 2 force dark, 3 force light.
    // SAFETY: export 135 has this signature since Windows 10 1903.
    let set_preferred_app_mode: unsafe extern "system" fn(i32) -> i32 =
        unsafe { std::mem::transmute(proc) };
    // SAFETY: plain call with a valid mode.
    unsafe { set_preferred_app_mode(if dark { 2 } else { 3 }) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_changes_are_recognised() {
        let name: Vec<u16> = "ImmersiveColorSet\0".encode_utf16().collect();
        assert!(is_theme_change(WM_SETTINGCHANGE, name.as_ptr() as isize));
        let other: Vec<u16> = "Policy\0".encode_utf16().collect();
        assert!(!is_theme_change(WM_SETTINGCHANGE, other.as_ptr() as isize));
        assert!(!is_theme_change(WM_SETTINGCHANGE, 0));
        assert!(!is_theme_change(0, name.as_ptr() as isize));
    }

    #[test]
    fn the_preference_reads_without_failing() {
        let _ = system_prefers_dark();
    }
}
