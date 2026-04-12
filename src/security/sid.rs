//! SID (Security Identifier) primitives.

use crate::Result;
use crate::error::{Error, SecurityError, SidParseError};
use std::fmt::Write;

/// A validated Windows Security Identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    raw: Vec<u8>,
    string: String,
}

impl Sid {
    /// Create a SID from binary data.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (sid_string, consumed) = sid_to_string_with_size(data).ok_or_else(|| {
            Error::Security(SecurityError::SidParse(SidParseError::new(
                "binary_sid",
                "SID data is malformed or truncated",
            )))
        })?;

        if consumed != data.len() {
            return Err(Error::Security(SecurityError::SidParse(
                SidParseError::new("binary_sid", "SID buffer contains trailing bytes"),
            )));
        }

        Ok(Self {
            raw: data.to_vec(),
            string: sid_string,
        })
    }

    /// Parse a SID from string form (`S-1-...`).
    pub fn parse(value: &str) -> Result<Self> {
        let raw = sid_string_to_bytes(value)?;
        Ok(Self {
            raw,
            string: value.to_string(),
        })
    }

    /// Parse a SID from either canonical SID string (`S-1-...`) or SDDL trustee alias.
    pub fn from_sddl_trustee(value: &str) -> Result<Self> {
        if value.starts_with("S-") {
            return Self::parse(value);
        }

        let sid_string = sddl_alias_to_sid(value).ok_or_else(|| {
            Error::Security(SecurityError::SidParse(SidParseError::new(
                value.to_string(),
                "unrecognized SDDL trustee alias",
            )))
        })?;

        Self::parse(sid_string)
    }

    /// Returns the canonical SID string.
    pub fn as_str(&self) -> &str {
        &self.string
    }

    /// Returns the binary SID representation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Returns a well-known SDDL alias for this SID when one exists.
    pub fn to_sddl_alias(&self) -> Option<&'static str> {
        sid_to_sddl_alias(self.as_str())
    }

    /// Case-insensitive compare for SID strings.
    pub fn eq_case_insensitive(&self, other: &str) -> bool {
        self.string.eq_ignore_ascii_case(other)
    }
}

fn sddl_alias_to_sid(value: &str) -> Option<&'static str> {
    match value {
        "SY" => Some("S-1-5-18"),     // LocalSystem
        "BA" => Some("S-1-5-32-544"), // Builtin Administrators
        "BU" => Some("S-1-5-32-545"), // Builtin Users
        "BG" => Some("S-1-5-32-546"), // Builtin Guests
        "PU" => Some("S-1-5-32-547"), // Power Users
        "AO" => Some("S-1-5-32-548"), // Account Operators
        "SO" => Some("S-1-5-32-549"), // Server Operators
        "PO" => Some("S-1-5-32-550"), // Print Operators
        "BO" => Some("S-1-5-32-551"), // Backup Operators
        "RE" => Some("S-1-5-32-552"), // Replicator
        "WD" => Some("S-1-1-0"),      // Everyone
        "AU" => Some("S-1-5-11"),     // Authenticated Users
        "AN" => Some("S-1-5-7"),      // Anonymous
        "NU" => Some("S-1-5-2"),      // Network
        "IU" => Some("S-1-5-4"),      // Interactive
        "SU" => Some("S-1-5-6"),      // Service
        "LS" => Some("S-1-5-19"),     // Local Service
        "NS" => Some("S-1-5-20"),     // Network Service
        "CO" => Some("S-1-3-0"),      // Creator Owner
        "CG" => Some("S-1-3-1"),      // Creator Group
        "OW" => Some("S-1-3-4"),      // Owner Rights
        "AC" => Some("S-1-15-2-1"),   // All Application Packages
        "S-1-5-80-0" => Some("S-1-5-80-0"),
        _ => None,
    }
}

fn sid_to_sddl_alias(value: &str) -> Option<&'static str> {
    match value {
        "S-1-5-18" => Some("SY"),
        "S-1-5-32-544" => Some("BA"),
        "S-1-5-32-545" => Some("BU"),
        "S-1-5-32-546" => Some("BG"),
        "S-1-5-32-547" => Some("PU"),
        "S-1-5-32-548" => Some("AO"),
        "S-1-5-32-549" => Some("SO"),
        "S-1-5-32-550" => Some("PO"),
        "S-1-5-32-551" => Some("BO"),
        "S-1-5-32-552" => Some("RE"),
        "S-1-1-0" => Some("WD"),
        "S-1-5-11" => Some("AU"),
        "S-1-5-7" => Some("AN"),
        "S-1-5-2" => Some("NU"),
        "S-1-5-4" => Some("IU"),
        "S-1-5-6" => Some("SU"),
        "S-1-5-19" => Some("LS"),
        "S-1-5-20" => Some("NS"),
        "S-1-3-0" => Some("CO"),
        "S-1-3-1" => Some("CG"),
        "S-1-3-4" => Some("OW"),
        "S-1-15-2-1" => Some("AC"),
        _ => None,
    }
}

impl std::fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string)
    }
}

fn sid_string_to_bytes(value: &str) -> Result<Vec<u8>> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() < 3 || !parts[0].eq_ignore_ascii_case("S") {
        return Err(Error::Security(SecurityError::SidParse(
            SidParseError::new(
                value.to_string(),
                "expected SID format S-Revision-IdentifierAuthority-SubAuthority...",
            ),
        )));
    }

    let revision = parts[1].parse::<u8>().map_err(|_| {
        Error::Security(SecurityError::SidParse(SidParseError::new(
            value.to_string(),
            "invalid SID revision",
        )))
    })?;

    let identifier_authority = parts[2].parse::<u64>().map_err(|_| {
        Error::Security(SecurityError::SidParse(SidParseError::new(
            value.to_string(),
            "invalid identifier authority",
        )))
    })?;

    if identifier_authority > 0x0000_FFFF_FFFF {
        return Err(Error::Security(SecurityError::SidParse(
            SidParseError::new(
                value.to_string(),
                "identifier authority must fit in 48 bits",
            ),
        )));
    }

    let sub_authority_count = parts.len().saturating_sub(3);
    if sub_authority_count > u8::MAX as usize {
        return Err(Error::Security(SecurityError::SidParse(
            SidParseError::new(value.to_string(), "too many sub-authorities"),
        )));
    }

    let mut out = Vec::with_capacity(8 + sub_authority_count * 4);
    out.push(revision);
    out.push(sub_authority_count as u8);

    let authority_be = identifier_authority.to_be_bytes();
    out.extend_from_slice(&authority_be[2..]);

    for part in parts.iter().skip(3) {
        let sub = part.parse::<u32>().map_err(|_| {
            Error::Security(SecurityError::SidParse(SidParseError::new(
                value.to_string(),
                "invalid sub-authority value",
            )))
        })?;
        out.extend_from_slice(&sub.to_le_bytes());
    }

    Ok(out)
}

fn sid_to_string_with_size(sid: &[u8]) -> Option<(String, usize)> {
    if sid.len() < 8 {
        return None;
    }

    let mut id = String::with_capacity(32);
    let subauthority_count = sid[1] as usize;

    let mut identifier_authority = (u16::from_be_bytes([sid[2], sid[3]]) as u64) << 32;
    identifier_authority |= u32::from_be_bytes([sid[4], sid[5], sid[6], sid[7]]) as u64;

    let _ = write!(&mut id, "S-{}-{}", sid[0], identifier_authority);

    let mut start = 8usize;
    for _ in 0..subauthority_count {
        if start + 4 > sid.len() {
            return None;
        }

        let authority =
            u32::from_le_bytes([sid[start], sid[start + 1], sid[start + 2], sid[start + 3]]);
        let _ = write!(&mut id, "-{}", authority);
        start += 4;
    }

    Some((id, start))
}

#[cfg(test)]
mod tests {
    use super::Sid;

    #[test]
    fn sid_round_trip_string_binary() {
        let sid = Sid::parse("S-1-5-32-544").expect("parse should succeed");
        let sid2 = Sid::from_bytes(sid.as_bytes()).expect("binary parse should succeed");
        assert_eq!(sid.as_str(), sid2.as_str());
        assert_eq!(sid.as_bytes(), sid2.as_bytes());
    }

    #[test]
    fn sid_parse_invalid_format() {
        let err = Sid::parse("not-a-sid").expect_err("expected parse error");
        assert!(err.to_string().contains("expected SID format"));
    }

    #[test]
    fn sid_parse_from_sddl_alias() {
        let sid = Sid::from_sddl_trustee("BA").expect("alias parse should succeed");
        assert_eq!(sid.as_str(), "S-1-5-32-544");
    }

    #[test]
    fn sid_to_sddl_alias_round_trip() {
        let sid = Sid::parse("S-1-5-32-545").expect("parse should succeed");
        assert_eq!(sid.to_sddl_alias(), Some("BU"));
    }
}
