//! Common types used across multiple modules.

use std::fmt;

/// Strongly-typed process identifier.
///
/// Used to prevent accidentally mixing process IDs with other u32 values.
/// Implements Copy, PartialEq, Hash for easy use in collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(pub u32);

impl ProcessId {
    /// Create a new process ID.
    pub fn new(id: u32) -> Self {
        ProcessId(id)
    }

    /// Get the raw process ID value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl From<u32> for ProcessId {
    fn from(id: u32) -> Self {
        ProcessId(id)
    }
}

impl From<ProcessId> for u32 {
    fn from(id: ProcessId) -> Self {
        id.0
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl PartialEq<u32> for ProcessId {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<ProcessId> for u32 {
    fn eq(&self, other: &ProcessId) -> bool {
        *self == other.0
    }
}

/// Strongly-typed thread identifier.
///
/// Used to prevent accidentally mixing thread IDs with other u32 values.
/// Implements Copy, PartialEq, Hash for easy use in collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ThreadId(pub u32);

impl ThreadId {
    /// Create a new thread ID.
    pub fn new(id: u32) -> Self {
        ThreadId(id)
    }

    /// Get the raw thread ID value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl From<u32> for ThreadId {
    fn from(id: u32) -> Self {
        ThreadId(id)
    }
}

impl From<ThreadId> for u32 {
    fn from(id: ThreadId) -> Self {
        id.0
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<u32> for ThreadId {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<ThreadId> for u32 {
    fn eq(&self, other: &ThreadId) -> bool {
        *self == other.0
    }
}
