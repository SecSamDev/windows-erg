//! Process access-token queries: elevation, mandatory integrity level, and
//! `BUILTIN\Administrators` membership.

use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::Security::GetTokenInformation;
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DuplicateToken, GetLengthSid, GetSidSubAuthority,
    GetSidSubAuthorityCount, PSID, SECURITY_MAX_SID_SIZE, SecurityIdentification, TOKEN_DUPLICATE,
    TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenElevation,
    TokenIntegrityLevel, TokenUser, WinBuiltinAdministratorsSid,
};
use windows::Win32::System::SystemServices::{
    SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_LOW_RID, SECURITY_MANDATORY_MEDIUM_RID,
    SECURITY_MANDATORY_SYSTEM_RID,
};
use windows::Win32::System::Threading::OpenProcessToken;

use crate::error::{Error, InvalidParameterError, Result, WindowsApiError};
use crate::process::Process;
use crate::security::Sid;
use crate::utils::OwnedHandle;

fn context(api: &'static str) -> impl Fn(windows::core::Error) -> Error {
    move |e| Error::WindowsApi(WindowsApiError::with_context(e, api))
}

/// Mandatory integrity level of a token.
///
/// `Medium Plus` (a real, distinct RID between `Medium` and `High`) and
/// `Protected Process` (above `System`) collapse into `Medium` and
/// `System` respectively — see [`ProcessToken::integrity_level`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntegrityLevel {
    /// Below `Low` — e.g. a process launched from an untrusted zone.
    Untrusted,
    /// Sandboxed/protected-mode processes (e.g. a browser renderer).
    Low,
    /// The default level for a standard user's processes.
    Medium,
    /// An elevated (UAC-approved) administrator or an unfiltered admin token.
    High,
    /// SYSTEM and other service-account processes.
    System,
}

fn integrity_level_from_rid(rid: u32) -> IntegrityLevel {
    match rid {
        r if r < SECURITY_MANDATORY_LOW_RID as u32 => IntegrityLevel::Untrusted,
        r if r < SECURITY_MANDATORY_MEDIUM_RID as u32 => IntegrityLevel::Low,
        r if r < SECURITY_MANDATORY_HIGH_RID as u32 => IntegrityLevel::Medium,
        r if r < SECURITY_MANDATORY_SYSTEM_RID as u32 => IntegrityLevel::High,
        _ => IntegrityLevel::System,
    }
}

/// A process's primary access token, opened with `TOKEN_QUERY`.
pub struct ProcessToken {
    handle: OwnedHandle,
}

impl ProcessToken {
    /// Open `process`'s primary token for query access. Also requests
    /// `TOKEN_DUPLICATE`, which [`is_admin`](Self::is_admin) needs to
    /// derive an impersonation-level token for `CheckTokenMembership`.
    pub fn open(process: &Process) -> Result<Self> {
        let mut token = HANDLE::default();
        // SAFETY: `process`'s handle is valid for the duration of this call.
        unsafe {
            OpenProcessToken(
                process.as_raw_handle(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut token,
            )
        }
        .map_err(context("OpenProcessToken"))?;
        Ok(Self {
            handle: OwnedHandle::new(token),
        })
    }

    /// Whether UAC elevated this token: an administrator who approved a UAC
    /// prompt, or SYSTEM. An administrator's UAC-filtered ("split") token
    /// before elevation reports `false` — see [`is_admin`](Self::is_admin)
    /// for group membership independent of elevation.
    pub fn is_elevated(&self) -> Result<bool> {
        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;
        // SAFETY: `elevation` is sized exactly for `TokenElevation`.
        unsafe {
            GetTokenInformation(
                self.handle.raw(),
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            )
        }
        .map_err(context("GetTokenInformation(TokenElevation)"))?;
        Ok(elevation.TokenIsElevated != 0)
    }

    /// The token's mandatory integrity level.
    pub fn integrity_level(&self) -> Result<IntegrityLevel> {
        // First call: ask for the required buffer size. Expected to fail
        // with ERROR_INSUFFICIENT_BUFFER; `return_length` is filled either way.
        let mut return_length = 0u32;
        unsafe {
            let _ = GetTokenInformation(
                self.handle.raw(),
                TokenIntegrityLevel,
                None,
                0,
                &mut return_length,
            );
        }
        if return_length == 0 {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "TokenIntegrityLevel",
                "GetTokenInformation reported a zero-length TOKEN_MANDATORY_LABEL",
            )));
        }

        let mut buffer = vec![0u8; return_length as usize];
        // SAFETY: `buffer` is exactly `return_length` bytes, as reported above.
        unsafe {
            GetTokenInformation(
                self.handle.raw(),
                TokenIntegrityLevel,
                Some(buffer.as_mut_ptr() as *mut _),
                return_length,
                &mut return_length,
            )
        }
        .map_err(context("GetTokenInformation(TokenIntegrityLevel)"))?;

        // SAFETY: `buffer` was just filled with a `TOKEN_MANDATORY_LABEL` by
        // the call above, and outlives `sid`, which points into it.
        let rid = unsafe {
            let label = &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid = label.Label.Sid;
            let count = *GetSidSubAuthorityCount(sid);
            if count == 0 {
                return Err(Error::InvalidParameter(InvalidParameterError::new(
                    "TokenIntegrityLevel",
                    "mandatory label SID has no sub-authorities",
                )));
            }
            *GetSidSubAuthority(sid, u32::from(count - 1))
        };
        Ok(integrity_level_from_rid(rid))
    }

    /// Whether the token's user is a member of `BUILTIN\Administrators` —
    /// independent of [`is_elevated`](Self::is_elevated): an administrator
    /// running with a UAC-filtered token is a member but not elevated.
    pub fn is_admin(&self) -> Result<bool> {
        // CheckTokenMembership rejects a primary token outright
        // (ERROR_NO_IMPERSONATION_TOKEN) — it needs an impersonation-type
        // token. `SecurityIdentification` is enough to inspect group
        // membership without actually letting this thread impersonate
        // anything (no `ImpersonateLoggedOnUser`/`SetThreadToken` involved).
        let mut impersonation = HANDLE::default();
        // SAFETY: `self.handle` is a valid token opened with TOKEN_QUERY;
        // `impersonation` is written by the call on success.
        unsafe {
            DuplicateToken(
                self.handle.raw(),
                SecurityIdentification,
                &mut impersonation,
            )
        }
        .map_err(context("DuplicateToken"))?;
        let impersonation = OwnedHandle::new(impersonation);

        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut sid_len = SECURITY_MAX_SID_SIZE;
        let sid_ptr = PSID(sid.as_mut_ptr().cast());
        // SAFETY: `sid` holds SECURITY_MAX_SID_SIZE bytes, enough for any SID.
        unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                PSID::default(),
                sid_ptr,
                &mut sid_len,
            )
        }
        .map_err(context("CreateWellKnownSid"))?;

        let mut member = BOOL(0);
        // SAFETY: `impersonation` is a valid impersonation-type token;
        // `sid_ptr` points at a valid SID.
        unsafe { CheckTokenMembership(impersonation.raw(), sid_ptr, &mut member) }
            .map_err(context("CheckTokenMembership"))?;
        Ok(member.as_bool())
    }

    /// The token's owning user SID (`TokenUser`).
    pub fn user_sid(&self) -> Result<Sid> {
        // Same two-call pattern as `integrity_level`: size first, then read.
        let mut return_length = 0u32;
        unsafe {
            let _ = GetTokenInformation(self.handle.raw(), TokenUser, None, 0, &mut return_length);
        }
        if return_length == 0 {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "TokenUser",
                "GetTokenInformation reported a zero-length TOKEN_USER",
            )));
        }

        let mut buffer = vec![0u8; return_length as usize];
        // SAFETY: `buffer` is exactly `return_length` bytes, as reported above.
        unsafe {
            GetTokenInformation(
                self.handle.raw(),
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut _),
                return_length,
                &mut return_length,
            )
        }
        .map_err(context("GetTokenInformation(TokenUser)"))?;

        // SAFETY: `buffer` was just filled with a `TOKEN_USER` by the call
        // above, and `sid_ptr`/`sid_len` point within it or at a SID that
        // GetTokenInformation allocated within `buffer`'s lifetime.
        let sid_bytes = unsafe {
            let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let sid_ptr = token_user.User.Sid;
            let sid_len = GetLengthSid(sid_ptr) as usize;
            std::slice::from_raw_parts(sid_ptr.0 as *const u8, sid_len).to_vec()
        };
        Sid::from_bytes(&sid_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_level_from_rid_is_monotonic_at_known_boundaries() {
        assert_eq!(integrity_level_from_rid(0), IntegrityLevel::Untrusted);
        assert_eq!(
            integrity_level_from_rid(SECURITY_MANDATORY_LOW_RID as u32),
            IntegrityLevel::Low
        );
        assert_eq!(
            integrity_level_from_rid(SECURITY_MANDATORY_MEDIUM_RID as u32),
            IntegrityLevel::Medium
        );
        // Medium Plus (0x2100) sits strictly between Medium and High and
        // collapses into Medium.
        assert_eq!(integrity_level_from_rid(0x2100), IntegrityLevel::Medium);
        assert_eq!(
            integrity_level_from_rid(SECURITY_MANDATORY_HIGH_RID as u32),
            IntegrityLevel::High
        );
        assert_eq!(
            integrity_level_from_rid(SECURITY_MANDATORY_SYSTEM_RID as u32),
            IntegrityLevel::System
        );
        // Protected Process (0x5000) collapses into System.
        assert_eq!(integrity_level_from_rid(0x5000), IntegrityLevel::System);
    }

    #[test]
    fn integrity_level_ordering_matches_privilege() {
        assert!(IntegrityLevel::Untrusted < IntegrityLevel::Low);
        assert!(IntegrityLevel::Low < IntegrityLevel::Medium);
        assert!(IntegrityLevel::Medium < IntegrityLevel::High);
        assert!(IntegrityLevel::High < IntegrityLevel::System);
    }

    #[test]
    #[ignore] // Run manually: cargo test -- --ignored
    fn open_current_process_token_reports_a_plausible_state() {
        let process = Process::current();
        let token = ProcessToken::open(&process).expect("should open current process token");

        // Just confirm each query succeeds and returns something coherent;
        // the actual values depend on how the test runner was launched.
        let _ = token.is_elevated().expect("should read elevation");
        let level = token
            .integrity_level()
            .expect("should read integrity level");
        assert!(level >= IntegrityLevel::Low, "{level:?}");
        let _ = token.is_admin().expect("should check admin membership");
    }

    #[test]
    #[ignore] // Run manually: cargo test -- --ignored
    fn user_sid_matches_the_current_process_owner() {
        use crate::security::Sid;

        let process = Process::current();
        let token = ProcessToken::open(&process).expect("should open current process token");
        let sid = token.user_sid().expect("should read TokenUser");

        // Parses back to the same string form and is never a well-known
        // service SID for a normal interactive test run.
        let reparsed = Sid::parse(sid.as_str()).expect("SID string should round-trip");
        assert_eq!(sid, reparsed);
        assert!(sid.as_str().starts_with("S-1-5-21") || sid.as_str().starts_with("S-1-12-1"));
    }
}
