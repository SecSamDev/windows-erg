use std::ffi::c_void;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

use crate::error::{Error, PipeCreateError, PipeError};
use crate::utils::to_utf16_nul;

use super::types::PipeSecurityOptions;

pub(crate) struct NativePipeSecurityAttributes {
    attrs: SECURITY_ATTRIBUTES,
    descriptor: Option<PSECURITY_DESCRIPTOR>,
    include_for_call: bool,
}

impl NativePipeSecurityAttributes {
    pub(crate) fn from_options(options: &PipeSecurityOptions, resource: &str) -> crate::Result<Self> {
        let mut descriptor = None;
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: options.inherit_handle.into(),
            lpSecurityDescriptor: std::ptr::null_mut::<c_void>(),
        };

        if let Some(security_descriptor) = &options.security_descriptor {
            let sddl = descriptor_to_sddl(security_descriptor);
            let sddl_wide = to_utf16_nul(&sddl);

            let mut raw_descriptor = PSECURITY_DESCRIPTOR::default();
            let mut descriptor_size = 0u32;
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(sddl_wide.as_ptr()),
                    SDDL_REVISION_1,
                    &mut raw_descriptor as *mut _,
                    Some(&mut descriptor_size),
                )
            }
            .map_err(|e| {
                Error::Pipe(PipeError::Create(PipeCreateError::with_code(
                    resource.to_string(),
                    "security_descriptor",
                    e.code().0,
                )))
            })?;

            attrs.lpSecurityDescriptor = raw_descriptor.0;
            descriptor = Some(raw_descriptor);
        }

        Ok(Self {
            attrs,
            descriptor,
            include_for_call: options.inherit_handle || options.security_descriptor.is_some(),
        })
    }

    pub(crate) fn as_option_ptr(&self) -> Option<*const SECURITY_ATTRIBUTES> {
        if self.include_for_call {
            Some(&self.attrs as *const SECURITY_ATTRIBUTES)
        } else {
            None
        }
    }
}

impl Drop for NativePipeSecurityAttributes {
    fn drop(&mut self) {
        if let Some(descriptor) = self.descriptor {
            unsafe {
                let _ = LocalFree(HLOCAL(descriptor.0));
            }
        }
    }
}

fn descriptor_to_sddl(descriptor: &crate::security::SecurityDescriptor) -> String {
    let mut sddl = String::new();

    if let Some(owner) = descriptor.owner() {
        sddl.push_str("O:");
        sddl.push_str(owner.as_str());
    }

    if let Some(group) = descriptor.group() {
        sddl.push_str("G:");
        sddl.push_str(group.as_str());
    }

    sddl.push_str("D:");
    for ace in descriptor.dacl().entries() {
        let ace_type = match ace.ace_type {
            crate::security::AceType::Allow => "A",
            crate::security::AceType::Deny => "D",
        };

        let mut flags = String::new();
        if ace.inheritance.object_inherit {
            flags.push_str("OI");
        }
        if ace.inheritance.container_inherit {
            flags.push_str("CI");
        }
        if ace.inheritance.inherit_only {
            flags.push_str("IO");
        }
        if ace.inheritance.no_propagate_inherit {
            flags.push_str("NP");
        }
        if ace.inherited {
            flags.push_str("ID");
        }

        sddl.push_str(&format!(
            "({};{};0x{:X};;;{})",
            ace_type,
            flags,
            ace.access_mask.bits(),
            ace.trustee.as_str()
        ));
    }

    sddl
}
