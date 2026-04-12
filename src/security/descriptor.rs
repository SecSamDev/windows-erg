//! Security descriptor domain model.

use super::{Dacl, Sid};

/// Resource target represented by a security descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityTarget {
    /// File or directory path.
    FilePath(String),
    /// Registry key path.
    RegistryPath(String),
    /// In-memory descriptor with no external binding.
    Detached,
}

/// Security descriptor model containing owner/group and DACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor {
    target: SecurityTarget,
    owner: Option<Sid>,
    group: Option<Sid>,
    dacl: Dacl,
}

impl SecurityDescriptor {
    /// Create a detached descriptor with empty DACL.
    pub fn new() -> Self {
        Self {
            target: SecurityTarget::Detached,
            owner: None,
            group: None,
            dacl: Dacl::new(),
        }
    }

    /// Create descriptor bound to a file path.
    pub fn for_file_path(path: impl Into<String>) -> Self {
        Self {
            target: SecurityTarget::FilePath(path.into()),
            owner: None,
            group: None,
            dacl: Dacl::new(),
        }
    }

    /// Create descriptor bound to a registry path.
    pub fn for_registry_path(path: impl Into<String>) -> Self {
        Self {
            target: SecurityTarget::RegistryPath(path.into()),
            owner: None,
            group: None,
            dacl: Dacl::new(),
        }
    }

    /// Set owner SID.
    pub fn with_owner(mut self, owner: Sid) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Set group SID.
    pub fn with_group(mut self, group: Sid) -> Self {
        self.group = Some(group);
        self
    }

    /// Set DACL.
    pub fn with_dacl(mut self, dacl: Dacl) -> Self {
        self.dacl = dacl;
        self
    }

    /// Returns target information.
    pub fn target(&self) -> &SecurityTarget {
        &self.target
    }

    /// Returns owner SID if present.
    pub fn owner(&self) -> Option<&Sid> {
        self.owner.as_ref()
    }

    /// Returns group SID if present.
    pub fn group(&self) -> Option<&Sid> {
        self.group.as_ref()
    }

    /// Returns descriptor DACL.
    pub fn dacl(&self) -> &Dacl {
        &self.dacl
    }

    /// Returns mutable descriptor DACL.
    pub fn dacl_mut(&mut self) -> &mut Dacl {
        &mut self.dacl
    }
}

impl Default for SecurityDescriptor {
    fn default() -> Self {
        Self::new()
    }
}
