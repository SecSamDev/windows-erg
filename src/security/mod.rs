//! Security and permission primitives.
//!
//! This module provides foundational, strongly-typed building blocks for
//! permission manipulation. The initial implementation focuses on safe,
//! in-memory modeling and edit planning.

pub mod acl;
mod backends;
pub mod descriptor;
pub mod editor;
pub mod rights;
pub mod sid;
pub mod target;

pub use acl::{AccessMask, Ace, AceType, Dacl, InheritanceFlags};
pub use descriptor::{SecurityDescriptor, SecurityTarget};
pub use editor::{
    ApplyMode, DescriptorEditResult, PermissionDiff, PermissionEditPlan, PermissionEditPolicy,
    PermissionEditResult, PermissionEditor,
};
pub use rights::{FileAccess, RegistryAccess};
pub use sid::Sid;
pub use target::PermissionTarget;
