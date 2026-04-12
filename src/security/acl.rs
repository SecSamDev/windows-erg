//! ACL and ACE model types.

use super::Sid;

/// Access mask wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessMask(u32);

impl AccessMask {
    /// No access rights.
    pub const NONE: AccessMask = AccessMask(0);

    /// Create a mask from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        AccessMask(bits)
    }

    /// Return underlying raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns true when all bits in `other` are set.
    pub const fn contains(self, other: AccessMask) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for AccessMask {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        AccessMask(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for AccessMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for AccessMask {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        AccessMask(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for AccessMask {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl std::ops::Not for AccessMask {
    type Output = Self;

    fn not(self) -> Self::Output {
        AccessMask(!self.0)
    }
}

/// ACE type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AceType {
    /// Allows access bits.
    Allow,
    /// Denies access bits.
    Deny,
}

/// ACE inheritance flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct InheritanceFlags {
    /// Child objects inherit this ACE.
    pub object_inherit: bool,
    /// Child containers inherit this ACE.
    pub container_inherit: bool,
    /// ACE does not apply to current object.
    pub inherit_only: bool,
    /// Inheritance is not propagated further.
    pub no_propagate_inherit: bool,
}

/// Access control entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// Trustee SID.
    pub trustee: Sid,
    /// Allow or deny.
    pub ace_type: AceType,
    /// Rights for this ACE.
    pub access_mask: AccessMask,
    /// Inheritance behavior.
    pub inheritance: InheritanceFlags,
    /// True when inherited from parent.
    pub inherited: bool,
}

impl Ace {
    /// Create a new ACE.
    pub fn new(trustee: Sid, ace_type: AceType, access_mask: AccessMask) -> Self {
        Self {
            trustee,
            ace_type,
            access_mask,
            inheritance: InheritanceFlags::default(),
            inherited: false,
        }
    }

    /// Mark ACE as inherited or explicit.
    pub fn inherited(mut self, inherited: bool) -> Self {
        self.inherited = inherited;
        self
    }

    /// Set inheritance flags.
    pub fn with_inheritance(mut self, inheritance: InheritanceFlags) -> Self {
        self.inheritance = inheritance;
        self
    }
}

/// Discretionary access control list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dacl {
    entries: Vec<Ace>,
}

impl Dacl {
    /// Create an empty DACL.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Create a DACL from entries.
    pub fn from_entries(entries: Vec<Ace>) -> Self {
        Self { entries }
    }

    /// Return entries.
    pub fn entries(&self) -> &[Ace] {
        &self.entries
    }

    /// Return mutable entries.
    pub fn entries_mut(&mut self) -> &mut Vec<Ace> {
        &mut self.entries
    }

    /// Canonicalize ACE ordering.
    ///
    /// Order is explicit deny, explicit allow, inherited deny, inherited allow.
    pub fn canonicalize(&mut self) {
        self.entries.sort_by_key(|ace| {
            let inherited_rank = if ace.inherited { 1u8 } else { 0u8 };
            let type_rank = match ace.ace_type {
                AceType::Deny => 0u8,
                AceType::Allow => 1u8,
            };
            (inherited_rank, type_rank)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessMask, Ace, AceType, Dacl};
    use crate::security::Sid;

    #[test]
    fn canonicalize_places_explicit_deny_first() {
        let user = Sid::parse("S-1-5-32-545").expect("valid sid");

        let mut dacl = Dacl::from_entries(vec![
            Ace::new(user.clone(), AceType::Allow, AccessMask::from_bits(0x2)),
            Ace::new(user.clone(), AceType::Deny, AccessMask::from_bits(0x1)),
            Ace::new(user.clone(), AceType::Allow, AccessMask::from_bits(0x4)).inherited(true),
        ]);

        dacl.canonicalize();

        assert_eq!(dacl.entries()[0].ace_type, AceType::Deny);
        assert!(!dacl.entries()[0].inherited);
    }
}
