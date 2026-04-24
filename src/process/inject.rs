//! DLL injection into a target process.

use std::ffi::CString;
use std::path::Path;

use windows::Win32::Foundation::{
    CloseHandle, DUPLICATE_CLOSE_SOURCE, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetCurrentProcess, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE,
    PROCESS_VM_OPERATION, PROCESS_VM_WRITE, WaitForSingleObject,
};

use super::processes::Process;
use crate::error::{
    AlreadyInjectedError, Error, InjectionFailedError, InvalidParameterError, ProcessError, Result,
};

/// Injection timeout in milliseconds.
const INJECT_TIMEOUT_MS: u32 = 5000;

impl Process {
    /// Inject a DLL into this process.
    ///
    /// Opens the process with the necessary rights, allocates memory for the DLL path,
    /// and creates a remote thread running `LoadLibraryA` in the target process.
    ///
    /// Returns `Err(ProcessError::AlreadyInjected)` if the DLL filename is already
    /// loaded by the target process.
    ///
    /// # Remarks
    /// - The DLL path must be valid UTF-8 and contain no embedded null characters.
    /// - The calling process must have the privileges required to open the target process
    ///   with `PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION`.
    /// - Injecting a 32-bit DLL into a 64-bit process (or vice versa) will silently fail;
    ///   ensure bitness matches.
    ///
    /// # Example
    /// ```no_run
    /// use std::path::Path;
    /// use windows_erg::process::{Process, ProcessId};
    ///
    /// # fn main() -> windows_erg::Result<()> {
    /// let process = Process::open(ProcessId::new(1234))?;
    /// process.inject_dll(Path::new("C:\\path\\to\\my.dll"))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn inject_dll(&self, dll_path: &Path) -> Result<()> {
        let path_str = dll_path.to_str().ok_or_else(|| {
            Error::InvalidParameter(InvalidParameterError::new(
                "dll_path",
                "DLL path must be valid UTF-8",
            ))
        })?;

        let dll_path_cstr = CString::new(path_str).map_err(|_| {
            Error::InvalidParameter(InvalidParameterError::new(
                "dll_path",
                "DLL path must not contain embedded null characters",
            ))
        })?;

        // Check whether the DLL (by filename) is already loaded.
        let dll_filename = dll_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(path_str)
            .to_ascii_lowercase();

        if self.is_dll_loaded(&dll_filename)? {
            return Err(Error::Process(ProcessError::AlreadyInjected(
                AlreadyInjectedError::new(self.pid().as_u32(), dll_filename),
            )));
        }

        // Open the target process with the rights required for injection.
        let pid = self.pid().as_u32();
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_CREATE_THREAD
                    | PROCESS_VM_WRITE
                    | PROCESS_VM_OPERATION
                    | PROCESS_DUP_HANDLE,
                false,
                pid,
            )
        }
        .map_err(|e| {
            Error::Process(ProcessError::InjectionFailed(
                InjectionFailedError::with_code(
                    pid,
                    "Failed to open process with injection rights",
                    e.code().0,
                ),
            ))
        })?;

        // Perform injection; ensure we always close the handle.
        let result = inject_impl(process_handle, pid, &dll_path_cstr);
        unsafe {
            let _ = CloseHandle(process_handle);
        }
        result
    }

    /// Check whether a DLL with the given name (case-insensitive, filename only) is
    /// currently loaded in this process.
    ///
    /// # Example
    /// ```no_run
    /// use windows_erg::process::{Process, ProcessId};
    ///
    /// # fn main() -> windows_erg::Result<()> {
    /// let process = Process::open(ProcessId::new(1234))?;
    /// if process.is_dll_loaded("kernel32.dll")? {
    ///     println!("kernel32 is loaded");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_dll_loaded(&self, dll_name: &str) -> Result<bool> {
        let pid = self.pid().as_u32();
        let dll_name_lower = dll_name.to_ascii_lowercase();

        // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32 captures both 32- and 64-bit modules.
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
                .map_err(|e| {
                    Error::Process(ProcessError::InjectionFailed(
                        InjectionFailedError::with_code(
                            pid,
                            "Failed to snapshot process modules",
                            e.code().0,
                        ),
                    ))
                })?;

        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        let found = unsafe {
            if Module32FirstW(snapshot, &mut entry).is_err() {
                let _ = CloseHandle(snapshot);
                return Ok(false);
            }
            let mut result = false;
            loop {
                // szModule is the module filename (no path), null-terminated u16 slice.
                let name_end = entry
                    .szModule
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szModule.len());
                let module_name =
                    String::from_utf16_lossy(&entry.szModule[..name_end]).to_ascii_lowercase();
                if module_name == dll_name_lower {
                    result = true;
                    break;
                }
                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
            result
        };

        unsafe {
            let _ = CloseHandle(snapshot);
        }
        Ok(found)
    }

    /// Convenience accessor used within this module.
    fn pid(&self) -> super::types::ProcessId {
        self.id()
    }
}

/// Core injection logic. `process_handle` must already be open with the required rights.
/// The caller is responsible for closing `process_handle`.
fn inject_impl(process_handle: HANDLE, pid: u32, dll_path: &CString) -> Result<()> {
    let path_bytes = dll_path.as_bytes_with_nul();

    // Allocate memory in the target process for the DLL path.
    let remote_mem = unsafe {
        VirtualAllocEx(
            process_handle,
            None,
            path_bytes.len(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    if remote_mem.is_null() {
        return Err(Error::Process(ProcessError::InjectionFailed(
            InjectionFailedError::new(pid, "Failed to allocate memory in target process"),
        )));
    }

    // Write the DLL path into the target process.
    let write_result = unsafe {
        WriteProcessMemory(
            process_handle,
            remote_mem,
            path_bytes.as_ptr() as *const _,
            path_bytes.len(),
            None,
        )
    };
    if let Err(e) = write_result {
        unsafe {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        }
        return Err(Error::Process(ProcessError::InjectionFailed(
            InjectionFailedError::with_code(
                pid,
                "Failed to write DLL path into target process",
                e.code().0,
            ),
        )));
    }

    // Resolve LoadLibraryA in kernel32.
    let load_library_addr = unsafe {
        let k32 = GetModuleHandleA(windows::core::s!("kernel32.dll")).map_err(
            |e: windows::core::Error| {
                let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                Error::Process(ProcessError::InjectionFailed(
                    InjectionFailedError::with_code(
                        pid,
                        "Failed to get kernel32.dll handle",
                        e.code().0,
                    ),
                ))
            },
        )?;
        GetProcAddress(k32, windows::core::s!("LoadLibraryA")).ok_or_else(|| {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
            Error::Process(ProcessError::InjectionFailed(InjectionFailedError::new(
                pid,
                "Failed to resolve LoadLibraryA",
            )))
        })?
    };

    // Create a remote thread executing LoadLibraryA(dll_path).
    let start_routine: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
        unsafe { std::mem::transmute(load_library_addr) };

    let remote_thread = unsafe {
        CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(start_routine),
            Some(remote_mem),
            0,
            None,
        )
    }
    .map_err(|e| {
        unsafe {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        }
        Error::Process(ProcessError::InjectionFailed(
            InjectionFailedError::with_code(
                pid,
                "Failed to create remote thread in target process",
                e.code().0,
            ),
        ))
    })?;

    if remote_thread == INVALID_HANDLE_VALUE {
        unsafe {
            let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
        }
        return Err(Error::Process(ProcessError::InjectionFailed(
            InjectionFailedError::new(pid, "CreateRemoteThread returned invalid handle"),
        )));
    }

    // Wait for the remote thread to complete.
    let wait_result = unsafe { WaitForSingleObject(remote_thread, INJECT_TIMEOUT_MS) };

    if wait_result == WAIT_OBJECT_0 {
        // Retrieve the exit code (which is the HMODULE returned by LoadLibraryA).
        let mut exit_code: u32 = 0;
        if unsafe {
            windows::Win32::System::Threading::GetExitCodeThread(remote_thread, &mut exit_code)
                .is_ok()
        } {
            let module_handle = exit_code as isize;
            if module_handle == 0 {
                // LoadLibraryA returned NULL — injection failed inside the target process.
                unsafe {
                    let _ = CloseHandle(remote_thread);
                    let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
                }
                return Err(Error::Process(ProcessError::InjectionFailed(
                    InjectionFailedError::new(
                        pid,
                        "LoadLibraryA returned NULL in target process (wrong bitness or DLL not found?)",
                    ),
                )));
            }

            // Close the remote HMODULE handle to avoid leaking it in the target process.
            if module_handle != INVALID_HANDLE_VALUE.0 as isize {
                let mut dup_handle = HANDLE::default();
                let _ = unsafe {
                    DuplicateHandle(
                        process_handle,
                        HANDLE(module_handle as *mut _),
                        GetCurrentProcess(),
                        &mut dup_handle,
                        0,
                        false,
                        DUPLICATE_CLOSE_SOURCE,
                    )
                };
                if !dup_handle.is_invalid() {
                    unsafe {
                        let _ = CloseHandle(dup_handle);
                    }
                }
            }
        }
    }
    // If wait timed out the thread may still be running; we leave it running
    // (the DLL will load asynchronously) but do not return an error.

    unsafe {
        let _ = CloseHandle(remote_thread);
        let _ = VirtualFreeEx(process_handle, remote_mem, 0, MEM_RELEASE);
    }
    Ok(())
}
