//! Permission edit planning and in-memory application.

use super::{AccessMask, Ace, AceType, Dacl, PermissionTarget, SecurityDescriptor, Sid};
use crate::Result;
use crate::error::{Error, PermissionEditError, SecurityError, SecurityUnsupportedError};

/// How edits should be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    /// Validate only, do not change the DACL.
    ValidateOnly,
    /// Apply edits and return the updated DACL.
    Apply,
    /// Compute and return a diff with no mutation.
    DryRunDiff,
}

/// Safety and behavior policy for permission edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionEditPolicy {
    /// Keep inherited ACEs unchanged when revoking or replacing trustees.
    pub preserve_inherited: bool,
    /// Fail when both grant and deny are requested for same trustee/mask.
    pub reject_conflicting_changes: bool,
}

impl Default for PermissionEditPolicy {
    fn default() -> Self {
        Self {
            preserve_inherited: true,
            reject_conflicting_changes: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PermissionOperation {
    Grant {
        trustee: Sid,
        access: AccessMask,
    },
    Deny {
        trustee: Sid,
        access: AccessMask,
    },
    Revoke {
        trustee: Sid,
        access: Option<AccessMask>,
    },
    ReplaceTrustee {
        old_trustee: Sid,
        new_trustee: Sid,
    },
}

/// A planned permission edit operation list.
#[derive(Debug, Clone)]
pub struct PermissionEditor {
    policy: PermissionEditPolicy,
    operations: Vec<PermissionOperation>,
}

impl PermissionEditor {
    /// Create a new permission editor with default safety policy.
    pub fn new() -> Self {
        Self {
            policy: PermissionEditPolicy::default(),
            operations: Vec::new(),
        }
    }

    /// Set a custom edit policy.
    pub fn policy(mut self, policy: PermissionEditPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Add an allow ACE for trustee.
    pub fn grant(mut self, trustee: Sid, access: AccessMask) -> Self {
        self.operations
            .push(PermissionOperation::Grant { trustee, access });
        self
    }

    /// Add a deny ACE for trustee.
    pub fn deny(mut self, trustee: Sid, access: AccessMask) -> Self {
        self.operations
            .push(PermissionOperation::Deny { trustee, access });
        self
    }

    /// Revoke access for trustee.
    ///
    /// If `access` is `None`, all explicit ACEs for trustee are removed.
    pub fn revoke(mut self, trustee: Sid, access: Option<AccessMask>) -> Self {
        self.operations
            .push(PermissionOperation::Revoke { trustee, access });
        self
    }

    /// Replace all matching trustee SIDs.
    pub fn replace_trustee(mut self, old_trustee: Sid, new_trustee: Sid) -> Self {
        self.operations.push(PermissionOperation::ReplaceTrustee {
            old_trustee,
            new_trustee,
        });
        self
    }

    /// Validate operations and return a plan.
    pub fn build(self) -> Result<PermissionEditPlan> {
        if self.policy.reject_conflicting_changes {
            for op in &self.operations {
                if let PermissionOperation::Grant { trustee, access } = op {
                    let conflict = self.operations.iter().any(|other| {
                        matches!(other, PermissionOperation::Deny { trustee: t, access: a } if t == trustee && a == access)
                    });

                    if conflict {
                        return Err(Error::Security(SecurityError::PermissionEdit(
                            PermissionEditError::new(
                                "grant/deny",
                                "conflicting allow and deny operation for same trustee and mask",
                            ),
                        )));
                    }
                }
            }
        }

        Ok(PermissionEditPlan {
            policy: self.policy,
            operations: self.operations,
        })
    }
}

impl Default for PermissionEditor {
    fn default() -> Self {
        Self::new()
    }
}

/// Built permission edit plan.
#[derive(Debug, Clone)]
pub struct PermissionEditPlan {
    policy: PermissionEditPolicy,
    operations: Vec<PermissionOperation>,
}

impl PermissionEditPlan {
    /// Apply plan according to mode.
    pub fn execute(&self, current: &Dacl, mode: ApplyMode) -> PermissionEditResult {
        let mut next = current.clone();

        if matches!(mode, ApplyMode::ValidateOnly) {
            return PermissionEditResult {
                mode,
                updated_dacl: None,
                diff: PermissionDiff::between(current, current),
            };
        }

        for op in &self.operations {
            match op {
                PermissionOperation::Grant { trustee, access } => {
                    next.entries_mut()
                        .push(Ace::new(trustee.clone(), AceType::Allow, *access));
                }
                PermissionOperation::Deny { trustee, access } => {
                    next.entries_mut()
                        .push(Ace::new(trustee.clone(), AceType::Deny, *access));
                }
                PermissionOperation::Revoke { trustee, access } => {
                    next.entries_mut().retain(|ace| {
                        if self.policy.preserve_inherited && ace.inherited {
                            return true;
                        }

                        if &ace.trustee != trustee {
                            return true;
                        }

                        match access {
                            Some(mask) => ace.access_mask != *mask,
                            None => false,
                        }
                    });
                }
                PermissionOperation::ReplaceTrustee {
                    old_trustee,
                    new_trustee,
                } => {
                    for ace in next.entries_mut().iter_mut() {
                        if self.policy.preserve_inherited && ace.inherited {
                            continue;
                        }
                        if ace.trustee == *old_trustee {
                            ace.trustee = new_trustee.clone();
                        }
                    }
                }
            }
        }

        next.canonicalize();

        PermissionEditResult {
            mode,
            updated_dacl: if matches!(mode, ApplyMode::Apply) {
                Some(next.clone())
            } else {
                None
            },
            diff: PermissionDiff::between(current, &next),
        }
    }

    /// Apply plan against a full security descriptor.
    pub fn execute_on_descriptor(
        &self,
        current: &SecurityDescriptor,
        mode: ApplyMode,
    ) -> DescriptorEditResult {
        let dacl_result = self.execute(current.dacl(), mode);
        let mut updated = None;

        if let Some(next_dacl) = dacl_result.updated_dacl.clone() {
            let mut descriptor = current.clone();
            *descriptor.dacl_mut() = next_dacl;
            updated = Some(descriptor);
        }

        DescriptorEditResult {
            mode: dacl_result.mode,
            updated_descriptor: updated,
            diff: dacl_result.diff,
        }
    }

    /// Execute and optionally persist against a target backend.
    ///
    /// `Apply` mode requires backend write support.
    pub fn execute_for_target(
        &self,
        target: &PermissionTarget,
        current: &SecurityDescriptor,
        mode: ApplyMode,
    ) -> Result<DescriptorEditResult> {
        let result = self.execute_on_descriptor(current, mode);

        if matches!(mode, ApplyMode::Apply) {
            if let Some(updated) = &result.updated_descriptor {
                target.write_descriptor(updated)?;
            } else {
                return Err(Error::Security(SecurityError::Unsupported(
                    SecurityUnsupportedError::new(
                        "permission_target",
                        "apply_without_updated_descriptor",
                    ),
                )));
            }
        }

        Ok(result)
    }

    /// Read descriptor from target, execute plan, and optionally persist.
    pub fn execute_against_target(
        &self,
        target: &PermissionTarget,
        mode: ApplyMode,
    ) -> Result<DescriptorEditResult> {
        let current = target.read_descriptor()?;
        self.execute_for_target(target, &current, mode)
    }
}

/// Result of plan execution.
#[derive(Debug, Clone)]
pub struct PermissionEditResult {
    /// Execution mode.
    pub mode: ApplyMode,
    /// Updated DACL (only for Apply mode).
    pub updated_dacl: Option<Dacl>,
    /// Structured diff against original DACL.
    pub diff: PermissionDiff,
}

/// Result of descriptor-level plan execution.
#[derive(Debug, Clone)]
pub struct DescriptorEditResult {
    /// Execution mode.
    pub mode: ApplyMode,
    /// Updated descriptor (only for Apply mode).
    pub updated_descriptor: Option<SecurityDescriptor>,
    /// Structured diff against original DACL.
    pub diff: PermissionDiff,
}

/// A basic diff of ACL changes.
#[derive(Debug, Clone, Default)]
pub struct PermissionDiff {
    /// ACEs newly added.
    pub added: Vec<Ace>,
    /// ACEs removed.
    pub removed: Vec<Ace>,
}

impl PermissionDiff {
    fn between(before: &Dacl, after: &Dacl) -> Self {
        let mut added = Vec::new();
        let mut removed = Vec::new();

        for ace in after.entries() {
            if !before.entries().contains(ace) {
                added.push(ace.clone());
            }
        }

        for ace in before.entries() {
            if !after.entries().contains(ace) {
                removed.push(ace.clone());
            }
        }

        Self { added, removed }
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessMask, ApplyMode, PermissionEditor};
    use crate::security::{Ace, AceType, Dacl, SecurityDescriptor, Sid};

    #[test]
    fn build_rejects_conflicting_grant_and_deny() {
        let sid = Sid::parse("S-1-5-32-545").expect("valid sid");
        let err = PermissionEditor::new()
            .grant(sid.clone(), AccessMask::from_bits(0x1))
            .deny(sid, AccessMask::from_bits(0x1))
            .build()
            .expect_err("expected conflict");

        assert!(err.to_string().contains("conflicting allow and deny"));
    }

    #[test]
    fn dry_run_diff_reports_added_ace() {
        let sid = Sid::parse("S-1-5-32-545").expect("valid sid");
        let dacl = Dacl::new();

        let plan = PermissionEditor::new()
            .grant(sid.clone(), AccessMask::from_bits(0x2))
            .build()
            .expect("build plan");

        let result = plan.execute(&dacl, ApplyMode::DryRunDiff);
        assert_eq!(result.diff.added.len(), 1);
        assert!(result.updated_dacl.is_none());
        assert_eq!(
            result.diff.added[0],
            Ace::new(sid, AceType::Allow, AccessMask::from_bits(0x2))
        );
    }

    #[test]
    fn execute_on_descriptor_updates_descriptor_dacl() {
        let sid = Sid::parse("S-1-5-32-545").expect("valid sid");
        let descriptor = SecurityDescriptor::new().with_dacl(Dacl::new());

        let plan = PermissionEditor::new()
            .grant(sid, AccessMask::from_bits(0x4))
            .build()
            .expect("build plan");

        let result = plan.execute_on_descriptor(&descriptor, ApplyMode::Apply);
        assert!(result.updated_descriptor.is_some());
        assert_eq!(result.diff.added.len(), 1);
    }
}
