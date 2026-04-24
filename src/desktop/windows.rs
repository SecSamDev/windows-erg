use crate::error::{DesktopError, DesktopOperationError, Error, Result};
use windows::Win32::Foundation::{BOOL, GetLastError, HWND, LPARAM, RECT};
use windows::Win32::Graphics::Dwm::{DWMWA_CLOAKED, DwmGetWindowAttribute};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetClassNameW, GetParent, GetWindowRect, GetWindowTextLengthW,
    GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
};

use super::types::{CloakState, WindowHandle, WindowInfo, WindowRect};

/// Enumerate desktop windows (top-level and child windows).
pub fn enumerate_windows() -> Result<Vec<WindowInfo>> {
    let mut out_windows = Vec::with_capacity(256);
    enumerate_windows_with_buffer(&mut out_windows)?;
    Ok(out_windows)
}

/// Enumerate desktop windows (top-level and child windows) with a reusable output buffer.
pub fn enumerate_windows_with_buffer(out_windows: &mut Vec<WindowInfo>) -> Result<usize> {
    enumerate_windows_with_filter(out_windows, |_| true)
}

/// Enumerate desktop windows (top-level and child windows) with in-enumeration filtering.
pub fn enumerate_windows_with_filter<F>(
    out_windows: &mut Vec<WindowInfo>,
    filter: F,
) -> Result<usize>
where
    F: Fn(&WindowInfo) -> bool,
{
    out_windows.clear();

    let mut top_level = Vec::with_capacity(128);
    collect_top_level_window_handles(&mut top_level)?;

    for hwnd in top_level {
        let window = build_window_info(hwnd);
        if filter(&window) {
            out_windows.push(window);
        }

        let mut child_handles = Vec::with_capacity(64);
        collect_child_window_handles(hwnd, &mut child_handles)?;

        for child in child_handles {
            let window = build_window_info(child);
            if filter(&window) {
                out_windows.push(window);
            }
        }
    }

    Ok(out_windows.len())
}

/// Enumerate child windows for a specific parent window.
pub fn enumerate_child_windows(parent: WindowHandle) -> Result<Vec<WindowInfo>> {
    let mut out_windows = Vec::with_capacity(128);
    enumerate_child_windows_with_buffer(parent, &mut out_windows)?;
    Ok(out_windows)
}

/// Enumerate child windows for a specific parent window with a reusable output buffer.
pub fn enumerate_child_windows_with_buffer(
    parent: WindowHandle,
    out_windows: &mut Vec<WindowInfo>,
) -> Result<usize> {
    enumerate_child_windows_with_filter(parent, out_windows, |_| true)
}

/// Enumerate child windows for a specific parent window with in-enumeration filtering.
pub fn enumerate_child_windows_with_filter<F>(
    parent: WindowHandle,
    out_windows: &mut Vec<WindowInfo>,
    filter: F,
) -> Result<usize>
where
    F: Fn(&WindowInfo) -> bool,
{
    out_windows.clear();

    let mut child_handles = Vec::with_capacity(128);
    collect_child_window_handles(parent.into(), &mut child_handles)?;

    for hwnd in child_handles {
        let window = build_window_info(hwnd);
        if filter(&window) {
            out_windows.push(window);
        }
    }

    Ok(out_windows.len())
}

fn build_window_info(hwnd: HWND) -> WindowInfo {
    let mut pid = 0u32;
    unsafe {
        let _ = GetWindowThreadProcessId(hwnd, Some(&mut pid));
    }

    let parent = unsafe { GetParent(hwnd).ok() };
    let rect = query_window_rect(hwnd).unwrap_or(WindowRect {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    });

    WindowInfo {
        handle: hwnd.into(),
        parent: parent.and_then(|value| {
            if value.0.is_null() {
                None
            } else {
                Some(value.into())
            }
        }),
        process_id: crate::types::ProcessId::new(pid),
        class_name: query_class_name(hwnd),
        title: query_window_text(hwnd),
        rect,
        is_visible: unsafe { IsWindowVisible(hwnd).as_bool() },
        cloak_state: query_cloak_state(hwnd),
    }
}

fn query_window_rect(hwnd: HWND) -> Option<WindowRect> {
    let mut rect = RECT::default();
    let ok = unsafe { GetWindowRect(hwnd, &mut rect) }.is_ok();
    if ok { Some(rect.into()) } else { None }
}

fn query_window_text(hwnd: HWND) -> String {
    let length = unsafe { GetWindowTextLengthW(hwnd) };
    if length <= 0 {
        return String::new();
    }

    let mut buffer = vec![0u16; length as usize + 1];
    let copied = unsafe { GetWindowTextW(hwnd, &mut buffer) };
    if copied <= 0 {
        return String::new();
    }

    String::from_utf16_lossy(&buffer[..copied as usize])
}

fn query_class_name(hwnd: HWND) -> String {
    let mut buffer = [0u16; 256];
    let copied = unsafe { GetClassNameW(hwnd, &mut buffer) };
    if copied <= 0 {
        return String::new();
    }

    String::from_utf16_lossy(&buffer[..copied as usize])
}

fn query_cloak_state(hwnd: HWND) -> CloakState {
    let mut cloak_raw = 0u32;
    let result = unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED,
            (&mut cloak_raw as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    };

    if result.is_ok() {
        CloakState::from_raw(cloak_raw)
    } else {
        CloakState::NotCloaked
    }
}

fn collect_top_level_window_handles(out_handles: &mut Vec<HWND>) -> Result<()> {
    out_handles.clear();

    let ok = unsafe {
        EnumWindows(
            Some(collect_window_callback),
            LPARAM(out_handles as *mut Vec<HWND> as isize),
        )
    }
    .is_ok();

    if ok {
        return Ok(());
    }

    let code = unsafe { GetLastError().0 as i32 };
    if code == 0 {
        return Ok(());
    }

    Err(Error::Desktop(DesktopError::OperationFailed(
        DesktopOperationError::with_code("EnumWindows", "desktop", code),
    )))
}

fn collect_child_window_handles(parent: HWND, out_handles: &mut Vec<HWND>) -> Result<()> {
    out_handles.clear();

    let ok = unsafe {
        EnumChildWindows(
            parent,
            Some(collect_window_callback),
            LPARAM(out_handles as *mut Vec<HWND> as isize),
        )
    }
    .as_bool();

    if ok {
        return Ok(());
    }

    let code = unsafe { GetLastError().0 as i32 };
    if code == 0 {
        return Ok(());
    }

    Err(Error::Desktop(DesktopError::OperationFailed(
        DesktopOperationError::with_code(
            "EnumChildWindows",
            format!("parent={:p}", parent.0),
            code,
        ),
    )))
}

unsafe extern "system" fn collect_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let out_handles = unsafe { &mut *(lparam.0 as *mut Vec<HWND>) };
    out_handles.push(hwnd);
    BOOL(1)
}
