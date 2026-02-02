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
//! ## Modules
//!
//! - [`process`] - Process management (list, info, kill, spawn)
//! - [`registry`] - Registry operations
//! - [`thread`] - Thread management
//! - [`evt`] - Windows Event Log
//! - [`etw`] - Event Tracing for Windows
//! - [`proxy`] - Network proxy configuration
//! - [`mitigation`] - Process security mitigations
//! - [`file`] - Raw file operations

#![warn(missing_docs)]
#![cfg(windows)]

pub mod registry;
pub mod process;
pub mod error;

pub use error::{Error, Result};

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
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
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
