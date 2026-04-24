use std::fmt;
use std::ffi::c_void;

use windows::Win32::Foundation::{HWND, RECT};

use crate::types::ProcessId;

/// Strongly-typed window handle wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WindowHandle(pub *mut c_void);

impl WindowHandle {
    /// Create a new window handle.
    pub fn new(raw: *mut c_void) -> Self {
        Self(raw)
    }

    /// Get the raw HWND value.
    pub fn as_ptr(self) -> *mut c_void {
        self.0
    }
}

impl From<HWND> for WindowHandle {
    fn from(value: HWND) -> Self {
        Self(value.0)
    }
}

impl From<WindowHandle> for HWND {
    fn from(value: WindowHandle) -> Self {
        HWND(value.0)
    }
}

impl fmt::Display for WindowHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:p}", self.0)
    }
}

/// Strongly-typed tray icon identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrayIconId(pub u32);

impl TrayIconId {
    /// Create a new tray icon ID.
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Get the raw tray icon identifier.
    pub fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for TrayIconId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Rectangle coordinates for a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowRect {
    /// Left coordinate in screen space.
    pub left: i32,
    /// Top coordinate in screen space.
    pub top: i32,
    /// Right coordinate in screen space.
    pub right: i32,
    /// Bottom coordinate in screen space.
    pub bottom: i32,
}

impl WindowRect {
    /// Width of the rectangle.
    pub fn width(self) -> i32 {
        self.right - self.left
    }

    /// Height of the rectangle.
    pub fn height(self) -> i32 {
        self.bottom - self.top
    }
}

impl From<RECT> for WindowRect {
    fn from(value: RECT) -> Self {
        Self {
            left: value.left,
            top: value.top,
            right: value.right,
            bottom: value.bottom,
        }
    }
}

/// DWM cloaking state for a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloakState {
    /// Window is not cloaked.
    NotCloaked,
    /// Cloaked by application logic.
    App,
    /// Cloaked by the shell.
    Shell,
    /// Cloaked by inherited state.
    Inherited,
    /// Unknown cloaking bitmask.
    Unknown(u32),
}

impl CloakState {
    /// Convert a DWM cloaking bitmask to the ergonomic cloak state.
    pub fn from_raw(raw: u32) -> Self {
        if raw == 0 {
            return CloakState::NotCloaked;
        }

        if raw & 0x1 != 0 {
            return CloakState::App;
        }

        if raw & 0x2 != 0 {
            return CloakState::Shell;
        }

        if raw & 0x4 != 0 {
            return CloakState::Inherited;
        }

        CloakState::Unknown(raw)
    }

    /// Returns true when the window is cloaked.
    pub fn is_cloaked(self) -> bool {
        !matches!(self, CloakState::NotCloaked)
    }
}

/// Icon style for tray balloon notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalloonIcon {
    /// No icon.
    None,
    /// Information icon.
    Info,
    /// Warning icon.
    Warning,
    /// Error icon.
    Error,
}

/// Snapshot of a desktop window.
#[derive(Debug, Clone)]
pub struct WindowInfo {
    /// Window handle.
    pub handle: WindowHandle,
    /// Parent handle if available.
    pub parent: Option<WindowHandle>,
    /// Owning process ID.
    pub process_id: ProcessId,
    /// Window class name.
    pub class_name: String,
    /// Window title text.
    pub title: String,
    /// Window rectangle in screen coordinates.
    pub rect: WindowRect,
    /// Whether the window is visible.
    pub is_visible: bool,
    /// DWM cloaked state.
    pub cloak_state: CloakState,
}
