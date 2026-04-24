//! # windows-erg
//!
//! Ergonomic, idiomatic Rust wrappers for Windows APIs.
//!
//! This library provides safe, easy-to-use abstractions over Windows system APIs,
//! built on top of the `windows-rs` crate. It handles the complexity of:
//! - Automatic handle management (RAII)
//! - Permission handling
//! - Error conversion and context
//! - Type safety
//!
//! ## Quick Start
//!
//! ```no_run
//! use windows_erg::process::Process;
//!
//! // List all running processes
//! for proc_info in Process::list()? {
//!     println!("{}: {}", proc_info.pid, proc_info.name);
//! }
//! # Ok::<(), windows_erg::Error>(())
//! ```
//!
//! ## Raw File Example
//!
//! ```no_run
//! use windows_erg::file;
//!
//! // Requires administrator privileges in most environments.
//! file::raw_copy(
//!     r"C:\\Windows\\System32\\drivers\\etc\\hosts",
//!     r"C:\\Temp\\hosts.copy"
//! )?;
//! # Ok::<(), windows_erg::Error>(())
//! ```
//!
//! ## Modules
//!
//! - [`process`] - Process management (list, info, kill, spawn)
//! - [`desktop`] - Desktop windows and tray icon operations
//! - [`registry`] - Registry operations
//! - [`evt`] - Windows Event Log querying and reading
//! - [`etw`] - Event Tracing for Windows (ETW)
//! - [`file`] - Raw file operations
//! - [`pipes`] - Windows named and anonymous pipe API (in progress)
//! - [`service`] - Windows Service Control Manager operations

#![warn(missing_docs)]
#![cfg(windows)]

pub mod desktop;
pub mod error;
pub mod etw;
pub mod evt;
pub mod file;
pub mod mitigation;
pub mod pipes;
pub mod process;
pub mod proxy;
pub mod registry;
pub mod security;
pub mod service;
pub mod system;
pub mod types;
/// Shared utility helpers for UTF-16/Wide conversions and owned Win32 handle RAII.
pub mod utils;
/// Shared wait-object primitives for cancellation and coordination.
pub mod wait;

pub use error::{Error, Result};
pub use types::{ProcessId, ThreadId};
pub use wait::Wait;

/// Check if the current process is running with elevated (administrator) privileges.
///
/// # Examples
///
/// ```no_run
/// use windows_erg::is_elevated;
///
/// if is_elevated()? {
///     println!("Running as administrator");
/// } else {
///     println!("Not running as administrator");
/// }
/// # Ok::<(), windows_erg::Error>(())
/// ```
pub fn is_elevated() -> Result<bool> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        )?;

        Ok(elevation.TokenIsElevated != 0)
    }
}

/// Ensure the current process has elevated privileges, returning an error if not.
///
/// # Errors
///
/// Returns [`Error::AccessDenied`] if not running with administrator privileges.
///
/// # Examples
///
/// ```no_run
/// use windows_erg::require_elevation;
///
/// // This will fail if not running as admin
/// require_elevation()?;
/// # Ok::<(), windows_erg::Error>(())
/// ```
pub fn require_elevation() -> Result<()> {
    if !is_elevated()? {
        return Err(Error::AccessDenied(error::AccessDeniedError::new(
            "operation",
            "elevation",
        )));
    }
    Ok(())
}
