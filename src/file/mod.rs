//! Raw file operations.
//!
//! This module provides low-level file copying using raw disk reads,
//! which can bypass some filesystem-level filters.
//!
//! # Permissions
//!
//! Raw reads typically require elevated privileges (administrator).
//! Without sufficient privileges, operations usually fail with
//! [`crate::Error::FileOperation`].
//!
//! # Path Requirements
//!
//! Source paths must be absolute Windows drive paths (for example `C:\\path\\file.txt`).
//! Paths without a drive prefix are rejected as invalid parameters.
//!
//! # Examples
//!
//! ```no_run
//! use windows_erg::file;
//!
//! file::raw_copy(
//!     r"C:\\Windows\\System32\\drivers\\etc\\hosts",
//!     r"C:\\Temp\\hosts.copy"
//! )?;
//! # Ok::<(), windows_erg::Error>(())
//! ```
//!
//! ```no_run
//! use windows_erg::file::RawFile;
//!
//! let mut raw = RawFile::builder()
//!     .path(r"C:\\Windows\\System32\\drivers\\etc\\hosts")
//!     .clusters_per_read(8)
//!     .open()?;
//!
//! raw.copy_to(r"C:\\Temp\\hosts.builder.copy")?;
//! # Ok::<(), windows_erg::Error>(())
//! ```

mod builder;
mod raw;
mod win;

pub use builder::RawFileBuilder;
pub use raw::RawFile;

use std::path::Path;

use crate::Result;
use crate::security::{
    ApplyMode, DescriptorEditResult, PermissionEditPlan, PermissionTarget, SecurityDescriptor,
};

/// Copy a file using raw disk reads.
///
/// This operation may require elevated privileges.
///
/// # Errors
///
/// Returns an error when:
/// - the source path is invalid for raw reads,
/// - the process lacks privileges for raw volume access,
/// - the destination cannot be created or written,
/// - retrieval pointer metadata cannot be read from the source file.
pub fn raw_copy<P: AsRef<Path>, Q: AsRef<Path>>(source: P, destination: Q) -> Result<()> {
    let raw = RawFile::open(source)?;
    raw.copy_to(destination)
}

/// Create a raw file builder.
///
/// Use this for advanced tuning such as cluster read size and metadata buffer sizing.
pub fn builder() -> RawFileBuilder {
    RawFileBuilder::new()
}

/// Read a file security descriptor.
pub fn read_security_descriptor<P: AsRef<Path>>(path: P) -> Result<SecurityDescriptor> {
    let target = PermissionTarget::file(path.as_ref().to_string_lossy().to_string());
    target.read_descriptor()
}

/// Write a file security descriptor.
pub fn write_security_descriptor<P: AsRef<Path>>(
    path: P,
    descriptor: &SecurityDescriptor,
) -> Result<()> {
    let target = PermissionTarget::file(path.as_ref().to_string_lossy().to_string());
    target.write_descriptor(descriptor)
}

/// Apply a permission edit plan to a file target.
pub fn apply_permissions<P: AsRef<Path>>(
    path: P,
    plan: &PermissionEditPlan,
    mode: ApplyMode,
) -> Result<DescriptorEditResult> {
    let target = PermissionTarget::file(path.as_ref().to_string_lossy().to_string());
    plan.execute_against_target(&target, mode)
}
