//! Module (DLL) enumeration.

use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, GetModuleBaseNameW, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
};

use super::processes::Process;
use super::types::{ImagePath, ModuleInfo};
use crate::error::{Error, ProcessError, ProcessOpenError, Result};

impl Process {
    /// Enumerate all modules (DLLs) loaded in this process.
    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        let mut out_modules = Vec::with_capacity(32);
        let mut work_buffer = Vec::with_capacity(8192);
        self.modules_with_buffer(&mut out_modules, &mut work_buffer)?;
        Ok(out_modules)
    }

    /// Enumerate modules using reusable output and work buffers.
    ///
    /// # Arguments
    /// - `out_modules`: Output buffer to store ModuleInfo results
    /// - `work_buffer`: Work buffer for module handles and string data (reused across calls)
    pub fn modules_with_buffer(
        &self,
        out_modules: &mut Vec<ModuleInfo>,
        work_buffer: &mut Vec<u8>,
    ) -> Result<usize> {
        self.modules_with_filter_impl(out_modules, work_buffer, |_| true)
    }

    /// Enumerate modules matching a filter using reusable output and work buffers.
    ///
    /// The filter function is called for each module. Only modules where the filter
    /// returns `true` are added to the output buffer. This is more efficient than enumerating all
    /// and filtering afterwards.
    ///
    /// # Arguments
    /// - `out_modules`: Output buffer to store ModuleInfo results
    /// - `work_buffer`: Work buffer for module handles and string data (should be reused)
    /// - `filter`: Predicate function to filter modules
    ///
    /// Returns the number of matching modules found and added to the buffer.
    pub fn modules_with_filter<F>(
        &self,
        out_modules: &mut Vec<ModuleInfo>,
        work_buffer: &mut Vec<u8>,
        filter: F,
    ) -> Result<usize>
    where
        F: Fn(&ModuleInfo) -> bool,
    {
        self.modules_with_filter_impl(out_modules, work_buffer, filter)
    }

    /// Internal: Enumerate modules with pre-allocated work buffer.
    fn modules_with_filter_impl<F>(
        &self,
        out_modules: &mut Vec<ModuleInfo>,
        work_buffer: &mut Vec<u8>,
        filter: F,
    ) -> Result<usize>
    where
        F: Fn(&ModuleInfo) -> bool,
    {
        out_modules.clear();

        // Ensure work buffer is large enough for module handles (8KB)
        if work_buffer.capacity() < 8192 {
            work_buffer.reserve(8192 - work_buffer.capacity());
        }
        unsafe {
            work_buffer.set_len(8192);
        }

        let mut bytes_needed = 0u32;

        // First call to get size
        unsafe {
            EnumProcessModules(
                self.as_raw_handle(),
                work_buffer.as_mut_ptr() as *mut HMODULE,
                work_buffer.len() as u32,
                &mut bytes_needed,
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to enumerate modules (first call)",
                e.code().0,
            )))
        })?;

        // Resize if needed
        if bytes_needed as usize > work_buffer.len() {
            work_buffer.clear();
            if work_buffer.capacity() < bytes_needed as usize {
                work_buffer.reserve(bytes_needed as usize - work_buffer.capacity());
            }
            unsafe {
                work_buffer.set_len(bytes_needed as usize);
            }
        }

        // Second call with correct size
        unsafe {
            EnumProcessModules(
                self.as_raw_handle(),
                work_buffer.as_mut_ptr() as *mut HMODULE,
                work_buffer.len() as u32,
                &mut bytes_needed,
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::OpenFailed(ProcessOpenError::with_code(
                self.id().as_u32(),
                "Failed to enumerate modules (second call)",
                e.code().0,
            )))
        })?;

        let module_count = bytes_needed as usize / std::mem::size_of::<HMODULE>();
        let module_handles = unsafe {
            std::slice::from_raw_parts(work_buffer.as_ptr() as *const HMODULE, module_count)
        };

        // Reuse work buffer for string data starting after module handles
        // Ensure it has enough space for string operations (need room for module name and path)
        let string_buffer_start = bytes_needed as usize;
        if work_buffer.len() < string_buffer_start + 2048 {
            let needed = string_buffer_start + 2048;
            if work_buffer.capacity() < needed {
                work_buffer.reserve(needed - work_buffer.capacity());
            }
            unsafe {
                work_buffer.set_len(needed);
            }
        }

        let string_buffer_ptr =
            unsafe { work_buffer.as_mut_ptr().add(string_buffer_start) as *mut u16 };
        let string_buffer_len = (work_buffer.len() - string_buffer_start) / 2;
        let string_buffer_slice =
            unsafe { std::slice::from_raw_parts_mut(string_buffer_ptr, string_buffer_len) };

        for &hmodule in module_handles {
            // Get module name
            let name_len =
                unsafe { GetModuleBaseNameW(self.as_raw_handle(), hmodule, string_buffer_slice) }
                    as usize;

            let name = if name_len > 0 {
                String::from_utf16_lossy(&string_buffer_slice[..name_len])
            } else {
                continue;
            };

            // Get full path (reuse same buffer)
            let path_len =
                unsafe { GetModuleFileNameExW(self.as_raw_handle(), hmodule, string_buffer_slice) }
                    as usize;

            let path = if path_len > 0 {
                // Use from_utf16 for efficient cache lookup without intermediate String
                ImagePath::from_utf16(&string_buffer_slice[..path_len])
            } else {
                ImagePath::from_str(&name)
            };

            // Get module info (base address and size)
            let mut mod_info = MODULEINFO::default();
            let (base_address, size) = if unsafe {
                GetModuleInformation(
                    self.as_raw_handle(),
                    hmodule,
                    &mut mod_info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                )
            }
            .is_ok()
            {
                (mod_info.lpBaseOfDll as usize, mod_info.SizeOfImage)
            } else {
                (0, 0)
            };

            let module_info = ModuleInfo {
                name,
                path,
                base_address,
                size,
            };

            // Apply filter and add to output buffer if it matches
            if filter(&module_info) {
                out_modules.push(module_info);
            }
        }

        Ok(out_modules.len())
    }
}
