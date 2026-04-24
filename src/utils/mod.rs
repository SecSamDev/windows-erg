//! Shared utility helpers.
//!
//! This namespace contains reusable internals that are safe to expose publicly
//! for advanced callers, while remaining focused on low-level interop concerns.

/// Shared Win32 handle ownership helpers.
pub mod handles;
/// Shared UTF-16 and wide-string conversion helpers.
pub mod strings;

/// Shared owned Win32 handle RAII wrapper.
pub use handles::OwnedHandle;
/// Shared UTF-16 and PWSTR conversion helpers.
pub use strings::{pwstr_to_string, pwstr_to_string_len, to_utf16, to_utf16_nul, to_utf16_nul_in};