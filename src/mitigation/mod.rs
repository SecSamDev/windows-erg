//! Process mitigation policies.
//!
//! This module provides ergonomic helpers for applying and querying process
//! mitigation policies.
//!
//! # Important limitations
//! - `SetProcessMitigationPolicy` only applies to the current process.
//! - Querying mitigations supports current and external processes (when allowed).

use std::borrow::Cow;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::SystemServices::{
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
    PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessMitigationPolicy, OpenProcess,
    PROCESS_MITIGATION_POLICY, PROCESS_QUERY_LIMITED_INFORMATION, ProcessChildProcessPolicy,
    ProcessDynamicCodePolicy, ProcessImageLoadPolicy, ProcessPayloadRestrictionPolicy,
    ProcessSignaturePolicy, SetProcessMitigationPolicy,
};

use crate::error::{AccessDeniedError, Error, MitigationError, MitigationOperationError, Result};
use crate::types::ProcessId;

const BINARY_SIGNED_MICROSOFT_SIGNED_ONLY: u32 = 0x1;

const DYNAMIC_CODE_PROHIBIT: u32 = 0x1;

const IMAGE_LOAD_NO_REMOTE: u32 = 0b01;
const IMAGE_LOAD_PREFER_SYSTEM32_IMAGES: u32 = 0b0100;

const PAYLOAD_RESTRICTION_ENABLE_EXPORT_ADDRESS_FILTER: u32 = 0b0001;
const PAYLOAD_RESTRICTION_ENABLE_EXPORT_ADDRESS_FILTER_PLUS: u32 = 0b000100;
const PAYLOAD_RESTRICTION_ENABLE_IMPORT_ADDRESS_FILTER: u32 = 0b00010000;
const PAYLOAD_RESTRICTION_ENABLE_ROP_STACK_PIVOT: u32 = 0b0001000000;
const PAYLOAD_RESTRICTION_ENABLE_ROP_CALLER_CHECK: u32 = 0b000100000000;
const PAYLOAD_RESTRICTION_ENABLE_ROP_SIM_EXEC: u32 = 0b010000000000;

const PAYLOAD_RESTRICTION_MASK: u32 = PAYLOAD_RESTRICTION_ENABLE_EXPORT_ADDRESS_FILTER
    | PAYLOAD_RESTRICTION_ENABLE_EXPORT_ADDRESS_FILTER_PLUS
    | PAYLOAD_RESTRICTION_ENABLE_IMPORT_ADDRESS_FILTER
    | PAYLOAD_RESTRICTION_ENABLE_ROP_STACK_PIVOT
    | PAYLOAD_RESTRICTION_ENABLE_ROP_CALLER_CHECK
    | PAYLOAD_RESTRICTION_ENABLE_ROP_SIM_EXEC;

const CHILD_RESTRICTION_NO_PROCESS_CREATION: u32 = 0b001;
const ERROR_INVALID_PARAMETER_HRESULT: i32 = -2147024809;

/// Supported process mitigations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessMitigation {
    /// Restrict binaries to Microsoft-signed images only.
    MicrosoftSignedOnly,
    /// Prevent loading images from remote locations.
    BlockRemoteImages,
    /// Prefer loading images from System32.
    PreferSystem32Images,
    /// Block dynamic code generation (ACG).
    DisableDynamicCode,
    /// Enable payload restrictions (EAF, IAF, ROP checks).
    RestrictPayload,
    /// Prevent this process from creating child processes.
    BlockChildProcessCreation,
}

impl ProcessMitigation {
    fn policy_name(self) -> &'static str {
        match self {
            ProcessMitigation::MicrosoftSignedOnly => "signature",
            ProcessMitigation::BlockRemoteImages => "image_load_no_remote",
            ProcessMitigation::PreferSystem32Images => "image_load_prefer_system32",
            ProcessMitigation::DisableDynamicCode => "dynamic_code",
            ProcessMitigation::RestrictPayload => "payload_restriction",
            ProcessMitigation::BlockChildProcessCreation => "child_process",
        }
    }
}

/// Query result for supported process mitigations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessMitigationStatus {
    /// Process ID that was queried.
    pub process_id: ProcessId,
    /// Whether Microsoft-signed-only policy is enabled.
    pub microsoft_signed_only: bool,
    /// Whether remote image loading is blocked.
    pub block_remote_images: bool,
    /// Whether System32 images are preferred.
    pub prefer_system32_images: bool,
    /// Whether dynamic code generation is blocked.
    pub disable_dynamic_code: bool,
    /// Whether payload restrictions are active.
    pub restrict_payload: bool,
    /// Whether child process creation is blocked.
    pub block_child_process_creation: bool,
}

/// Builder for mitigation application.
#[derive(Debug, Default, Clone)]
pub struct MitigationPlan {
    mitigations: Vec<ProcessMitigation>,
}

impl MitigationPlan {
    /// Create an empty mitigation plan.
    pub fn new() -> Self {
        Self {
            mitigations: Vec::with_capacity(8),
        }
    }

    /// Enable one mitigation in this plan.
    pub fn enable(mut self, mitigation: ProcessMitigation) -> Self {
        if !self.mitigations.contains(&mitigation) {
            self.mitigations.push(mitigation);
        }
        self
    }

    /// Apply all configured mitigations to the current process.
    pub fn apply_to_current(&self) -> Result<()> {
        let has_signature = self
            .mitigations
            .contains(&ProcessMitigation::MicrosoftSignedOnly);
        let has_block_remote = self
            .mitigations
            .contains(&ProcessMitigation::BlockRemoteImages);
        let has_prefer_system32 = self
            .mitigations
            .contains(&ProcessMitigation::PreferSystem32Images);
        let has_dynamic_code = self
            .mitigations
            .contains(&ProcessMitigation::DisableDynamicCode);
        let has_payload = self
            .mitigations
            .contains(&ProcessMitigation::RestrictPayload);
        let has_child_block = self
            .mitigations
            .contains(&ProcessMitigation::BlockChildProcessCreation);

        if has_signature {
            apply_single_mitigation(ProcessMitigation::MicrosoftSignedOnly)?;
        }

        if has_block_remote || has_prefer_system32 {
            apply_image_load_mitigation(has_block_remote, has_prefer_system32)?;
        }

        if has_dynamic_code {
            apply_single_mitigation(ProcessMitigation::DisableDynamicCode)?;
        }

        if has_payload {
            apply_single_mitigation(ProcessMitigation::RestrictPayload)?;
        }

        if has_child_block {
            apply_single_mitigation(ProcessMitigation::BlockChildProcessCreation)?;
        }

        Ok(())
    }
}

/// Query mitigation status for the current process.
pub fn query_current() -> Result<ProcessMitigationStatus> {
    query_process(ProcessId::new(unsafe { GetCurrentProcessId() }))
}

/// Query mitigation status for a specific process.
pub fn query_process(process_id: ProcessId) -> Result<ProcessMitigationStatus> {
    let process = QueryProcessHandle::open(process_id)?;
    query_from_handle(process_id, process.handle)
}

fn apply_single_mitigation(mitigation: ProcessMitigation) -> Result<()> {
    match mitigation {
        ProcessMitigation::MicrosoftSignedOnly => {
            let mut policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
            policy.Anonymous.Anonymous._bitfield = BINARY_SIGNED_MICROSOFT_SIGNED_ONLY;
            set_policy(
                ProcessSignaturePolicy,
                &policy as *const _ as *const _,
                std::mem::size_of_val(&policy),
                mitigation.policy_name(),
            )
        }
        ProcessMitigation::BlockRemoteImages => apply_image_load_mitigation(true, false),
        ProcessMitigation::PreferSystem32Images => apply_image_load_mitigation(false, true),
        ProcessMitigation::DisableDynamicCode => {
            let mut policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
            policy.Anonymous.Anonymous._bitfield = DYNAMIC_CODE_PROHIBIT;
            set_policy(
                ProcessDynamicCodePolicy,
                &policy as *const _ as *const _,
                std::mem::size_of_val(&policy),
                mitigation.policy_name(),
            )
        }
        ProcessMitigation::RestrictPayload => apply_payload_mitigation(),
        ProcessMitigation::BlockChildProcessCreation => {
            let mut policy = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default();
            policy.Anonymous.Anonymous._bitfield = CHILD_RESTRICTION_NO_PROCESS_CREATION;
            set_policy(
                ProcessChildProcessPolicy,
                &policy as *const _ as *const _,
                std::mem::size_of_val(&policy),
                mitigation.policy_name(),
            )
        }
    }
}

fn apply_image_load_mitigation(
    block_remote_images: bool,
    prefer_system32_images: bool,
) -> Result<()> {
    let mut policy = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
    let mut flags = 0u32;
    if block_remote_images {
        flags |= IMAGE_LOAD_NO_REMOTE;
    }
    if prefer_system32_images {
        flags |= IMAGE_LOAD_PREFER_SYSTEM32_IMAGES;
    }

    policy.Anonymous.Anonymous._bitfield = flags;
    set_policy(
        ProcessImageLoadPolicy,
        &policy as *const _ as *const _,
        std::mem::size_of_val(&policy),
        "image_load",
    )
}

fn apply_payload_mitigation() -> Result<()> {
    let candidate_masks = [
        PAYLOAD_RESTRICTION_MASK,
        PAYLOAD_RESTRICTION_MASK & !PAYLOAD_RESTRICTION_ENABLE_ROP_SIM_EXEC,
        PAYLOAD_RESTRICTION_ENABLE_EXPORT_ADDRESS_FILTER
            | PAYLOAD_RESTRICTION_ENABLE_EXPORT_ADDRESS_FILTER_PLUS
            | PAYLOAD_RESTRICTION_ENABLE_IMPORT_ADDRESS_FILTER
            | PAYLOAD_RESTRICTION_ENABLE_ROP_STACK_PIVOT
            | PAYLOAD_RESTRICTION_ENABLE_ROP_CALLER_CHECK,
        PAYLOAD_RESTRICTION_ENABLE_EXPORT_ADDRESS_FILTER
            | PAYLOAD_RESTRICTION_ENABLE_IMPORT_ADDRESS_FILTER
            | PAYLOAD_RESTRICTION_ENABLE_ROP_STACK_PIVOT,
        PAYLOAD_RESTRICTION_ENABLE_EXPORT_ADDRESS_FILTER,
    ];

    let mut last_error: Option<windows::core::Error> = None;

    for mask in candidate_masks {
        let mut policy = PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY::default();
        policy.Anonymous.Anonymous._bitfield = mask;

        match set_policy_raw(
            ProcessPayloadRestrictionPolicy,
            &policy as *const _ as *const _,
            std::mem::size_of_val(&policy),
        ) {
            Ok(()) => return Ok(()),
            Err(err) => {
                if err.code().0 == ERROR_INVALID_PARAMETER_HRESULT {
                    last_error = Some(err);
                    continue;
                }
                return Err(map_windows_apply_error(err, "payload_restriction"));
            }
        }
    }

    Err(map_windows_apply_error(
        last_error.unwrap_or_else(|| windows::core::Error::from_win32()),
        "payload_restriction",
    ))
}

fn set_policy(
    policy: PROCESS_MITIGATION_POLICY,
    value: *const core::ffi::c_void,
    len: usize,
    policy_name: &'static str,
) -> Result<()> {
    set_policy_raw(policy, value, len).map_err(|e| map_windows_apply_error(e, policy_name))
}

fn set_policy_raw(
    policy: PROCESS_MITIGATION_POLICY,
    value: *const core::ffi::c_void,
    len: usize,
) -> windows::core::Result<()> {
    unsafe { SetProcessMitigationPolicy(policy, value, len) }
}

fn query_from_handle(process_id: ProcessId, handle: HANDLE) -> Result<ProcessMitigationStatus> {
    unsafe {
        let mut signature = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
        get_policy(
            handle,
            ProcessSignaturePolicy,
            &mut signature as *mut _ as *mut _,
            std::mem::size_of_val(&signature),
            "signature",
            process_id,
        )?;

        let mut image_load = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
        get_policy(
            handle,
            ProcessImageLoadPolicy,
            &mut image_load as *mut _ as *mut _,
            std::mem::size_of_val(&image_load),
            "image_load",
            process_id,
        )?;

        let mut dynamic_code = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::default();
        get_policy(
            handle,
            ProcessDynamicCodePolicy,
            &mut dynamic_code as *mut _ as *mut _,
            std::mem::size_of_val(&dynamic_code),
            "dynamic_code",
            process_id,
        )?;

        let mut payload = PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY::default();
        get_policy(
            handle,
            ProcessPayloadRestrictionPolicy,
            &mut payload as *mut _ as *mut _,
            std::mem::size_of_val(&payload),
            "payload_restriction",
            process_id,
        )?;

        let mut child = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default();
        get_policy(
            handle,
            ProcessChildProcessPolicy,
            &mut child as *mut _ as *mut _,
            std::mem::size_of_val(&child),
            "child_process",
            process_id,
        )?;

        let signature_flags = signature.Anonymous.Anonymous._bitfield;
        let image_load_flags = image_load.Anonymous.Anonymous._bitfield;
        let dynamic_flags = dynamic_code.Anonymous.Anonymous._bitfield;
        let payload_flags = payload.Anonymous.Anonymous._bitfield;
        let child_flags = child.Anonymous.Anonymous._bitfield;

        Ok(ProcessMitigationStatus {
            process_id,
            microsoft_signed_only: (signature_flags & BINARY_SIGNED_MICROSOFT_SIGNED_ONLY) != 0,
            block_remote_images: (image_load_flags & IMAGE_LOAD_NO_REMOTE) != 0,
            prefer_system32_images: (image_load_flags & IMAGE_LOAD_PREFER_SYSTEM32_IMAGES) != 0,
            disable_dynamic_code: (dynamic_flags & DYNAMIC_CODE_PROHIBIT) != 0,
            restrict_payload: (payload_flags & PAYLOAD_RESTRICTION_MASK) != 0,
            block_child_process_creation: (child_flags & CHILD_RESTRICTION_NO_PROCESS_CREATION)
                != 0,
        })
    }
}

fn get_policy(
    handle: HANDLE,
    policy: PROCESS_MITIGATION_POLICY,
    out_value: *mut core::ffi::c_void,
    len: usize,
    policy_name: &'static str,
    process_id: ProcessId,
) -> Result<()> {
    unsafe { GetProcessMitigationPolicy(handle, policy, out_value, len) }
        .map_err(|e| map_windows_query_error(e, policy_name, process_id))
}

fn map_windows_apply_error(err: windows::core::Error, policy_name: &'static str) -> Error {
    let code = err.code().0;
    if code == 5 {
        return Error::AccessDenied(AccessDeniedError::with_reason(
            "current process",
            "set mitigation policy",
            Cow::Owned(format!("{}: access denied", policy_name)),
        ));
    }

    Error::Mitigation(MitigationError::ApplyFailed(
        MitigationOperationError::new("apply", policy_name)
            .with_reason(Cow::Owned(err.to_string()))
            .with_code(code),
    ))
}

fn map_windows_query_error(
    err: windows::core::Error,
    policy_name: &'static str,
    process_id: ProcessId,
) -> Error {
    let code = err.code().0;
    if code == 5 {
        return Error::AccessDenied(AccessDeniedError::with_reason(
            Cow::Owned(format!("process {}", process_id.as_u32())),
            "query mitigation policy",
            Cow::Owned(format!("{}: access denied", policy_name)),
        ));
    }

    Error::Mitigation(MitigationError::QueryFailed(
        MitigationOperationError::new("query", policy_name)
            .with_process_id(process_id.as_u32())
            .with_reason(Cow::Owned(err.to_string()))
            .with_code(code),
    ))
}

struct QueryProcessHandle {
    handle: HANDLE,
    close_on_drop: bool,
}

impl QueryProcessHandle {
    fn open(process_id: ProcessId) -> Result<Self> {
        let current = ProcessId::new(unsafe { GetCurrentProcessId() });
        if process_id == current {
            return Ok(Self {
                handle: unsafe { GetCurrentProcess() },
                close_on_drop: false,
            });
        }

        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                process_id.as_u32(),
            )
        }
        .map_err(|e| map_windows_query_error(e, "open_process", process_id))?;

        Ok(Self {
            handle,
            close_on_drop: true,
        })
    }
}

impl Drop for QueryProcessHandle {
    fn drop(&mut self) {
        if self.close_on_drop {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MitigationPlan, ProcessMitigation};

    #[test]
    fn mitigation_plan_enable_deduplicates_values() {
        let plan = MitigationPlan::new()
            .enable(ProcessMitigation::DisableDynamicCode)
            .enable(ProcessMitigation::DisableDynamicCode)
            .enable(ProcessMitigation::MicrosoftSignedOnly);

        let debug = format!("{plan:?}");
        let count = debug.matches("DisableDynamicCode").count();
        assert_eq!(count, 1);
        assert!(debug.contains("MicrosoftSignedOnly"));
    }
}
