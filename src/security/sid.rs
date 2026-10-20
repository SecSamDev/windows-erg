//! SID (Security Identifier) primitives.

use crate::Result;
use crate::error::{Error, SecurityError, SidParseError, WindowsApiError};
use std::ffi::c_void;
use std::fmt::Write;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_NONE_MAPPED};
use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
use windows::core::{PCWSTR, PWSTR};

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

    /// The account this SID names, looked up on the local system
    /// (`LookupAccountSidW`).
    ///
    /// `Ok(None)` when no account maps to it (`ERROR_NONE_MAPPED`): a deleted
    /// account, or one from a domain that cannot be reached. Names are
    /// localised: `S-1-5-18` is `NT AUTHORITY\SYSTEM` on an English system
    /// only.
    ///
    /// A domain account may need a domain controller and block until it
    /// answers; logged-on users and local accounts resolve locally. Cache
    /// the result rather than calling this per event.
    pub fn lookup_account(&self) -> Result<Option<Account>> {
        let sid = PSID(self.raw.as_ptr() as *mut c_void);
        let mut name_len = 0u32;
        let mut domain_len = 0u32;
        let mut kind = SID_NAME_USE::default();
        // SAFETY: a sizing call with no buffers and zero lengths, which
        // fills in both lengths. `sid` points at the valid SID in
        // `self.raw`, which the call only reads.
        let sizing = unsafe {
            LookupAccountSidW(
                PCWSTR::null(),
                sid,
                Some(PWSTR::null()),
                &mut name_len,
                Some(PWSTR::null()),
                &mut domain_len,
                &mut kind,
            )
        };
        match sizing {
            Err(e) if e.code() == ERROR_NONE_MAPPED.to_hresult() => return Ok(None),
            Err(e) if e.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() => {
                return Err(lookup_error(e));
            }
            _ => {}
        }

        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        // SAFETY: both buffers hold the number of UTF-16 units the sizing
        // call asked for, and the lengths passed say so. `sid` as above.
        let lookup = unsafe {
            LookupAccountSidW(
                PCWSTR::null(),
                sid,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut kind,
            )
        };
        match lookup {
            Err(e) if e.code() == ERROR_NONE_MAPPED.to_hresult() => return Ok(None),
            Err(e) => return Err(lookup_error(e)),
            Ok(()) => {}
        }

        // On success the lengths exclude the terminating NUL.
        let text = |buffer: &[u16], len: u32| {
            String::from_utf16_lossy(&buffer[..(len as usize).min(buffer.len())])
        };
        Ok(Some(Account {
            domain: text(&domain, domain_len),
            name: text(&name, name_len),
            kind: AccountKind::from_raw(kind),
        }))
    }
}

fn lookup_error(e: windows::core::Error) -> Error {
    Error::WindowsApi(WindowsApiError::with_context(e, "LookupAccountSidW"))
}

/// What a SID names, as `LookupAccountSidW` reports it (`SID_NAME_USE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountKind {
    /// A user account.
    User,
    /// A domain group.
    Group,
    /// A domain.
    Domain,
    /// A local group, such as `BUILTIN\Administrators`.
    Alias,
    /// A well-known group or account, such as `Everyone` or `SYSTEM`.
    WellKnownGroup,
    /// An account that was deleted.
    DeletedAccount,
    /// Not a valid account.
    Invalid,
    /// The type could not be determined.
    Unknown,
    /// A computer account.
    Computer,
    /// A mandatory integrity label.
    Label,
    /// A logon session.
    LogonSession,
}

impl AccountKind {
    fn from_raw(value: SID_NAME_USE) -> Self {
        match value.0 {
            1 => Self::User,
            2 => Self::Group,
            3 => Self::Domain,
            4 => Self::Alias,
            5 => Self::WellKnownGroup,
            6 => Self::DeletedAccount,
            7 => Self::Invalid,
            9 => Self::Computer,
            10 => Self::Label,
            11 => Self::LogonSession,
            _ => Self::Unknown,
        }
    }
}

/// The account a [`Sid`] names, from [`Sid::lookup_account`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Account {
    /// The domain or computer the account belongs to, or an authority such
    /// as `NT AUTHORITY`. Empty for a few well-known groups (`Everyone`).
    pub domain: String,
    /// The account name.
    pub name: String,
    /// What kind of account it is.
    pub kind: AccountKind,
}

/// `DOMAIN\name`, or `name` alone when the domain is empty.
impl std::fmt::Display for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.domain.is_empty() {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{}\\{}", self.domain, self.name)
        }
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
    use super::{Account, AccountKind, Sid};
    use crate::process::Process;
    use crate::security::ProcessToken;

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

    /// Real call. Names are localised, so only the kind is pinned.
    #[test]
    fn local_system_resolves_to_a_well_known_account() {
        let account = Sid::parse("S-1-5-18")
            .expect("parse")
            .lookup_account()
            .expect("lookup")
            .expect("SYSTEM always maps");
        assert_eq!(account.kind, AccountKind::WellKnownGroup);
        assert!(!account.name.is_empty());
        assert!(!account.domain.is_empty());
    }

    /// Real call: whoever runs the tests is a user account.
    #[test]
    fn the_current_user_resolves_to_a_user() {
        let token = ProcessToken::open(&Process::current()).expect("own token");
        let account = token
            .user_sid()
            .expect("own SID")
            .lookup_account()
            .expect("lookup")
            .expect("the current user maps");
        assert_eq!(account.kind, AccountKind::User);
        assert!(account.to_string().contains('\\'), "{account}");
    }

    #[test]
    fn an_unknown_sid_maps_to_nothing() {
        let sid = Sid::parse("S-1-5-21-1-2-3-999999").expect("parse");
        assert_eq!(sid.lookup_account().expect("lookup"), None);
    }

    #[test]
    fn account_display_joins_domain_and_name() {
        let mut account = Account {
            domain: "HOST".to_string(),
            name: "alice".to_string(),
            kind: AccountKind::User,
        };
        assert_eq!(account.to_string(), r"HOST\alice");
        account.domain.clear();
        assert_eq!(account.to_string(), "alice");
    }

    #[test]
    fn sid_to_sddl_alias_round_trip() {
        let sid = Sid::parse("S-1-5-32-545").expect("parse should succeed");
        assert_eq!(sid.to_sddl_alias(), Some("BU"));
    }
}
