//! Process spawning with optional parent reparenting and token-based launch.

use std::borrow::Cow;
use std::ffi::c_void;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, WIN32_ERROR,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrimary,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::Threading::{
    CREATE_DEFAULT_ERROR_MODE, CREATE_NEW_CONSOLE, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, PROCESS_CREATE_PROCESS, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, STARTUPINFOEXW, UpdateProcThreadAttribute,
};
use windows::core::PCWSTR;

use super::processes::Process;
use super::types::{ProcessAccess, ProcessId, ThreadId};
use crate::error::{Error, InvalidParameterError, ProcessError, ProcessSpawnError, Result};
use crate::utils::{OwnedHandle, to_utf16_nul};

const DEFAULT_DESKTOP: &str = "winsta0\\default";

fn format_command_line(exe_path: &str, args: &[String]) -> String {
    if args.is_empty() {
        format!("\"{exe_path}\"")
    } else {
        format!("\"{exe_path}\" {}", args.join(" "))
    }
}

fn map_spawn_windows_error(
    command: &str,
    reason: impl Into<Cow<'static, str>>,
    error: &windows::core::Error,
) -> Error {
    Error::Process(ProcessError::SpawnFailed(ProcessSpawnError::with_code(
        Cow::Owned(command.to_string()),
        reason,
        error.code().0,
    )))
}

fn spawn_error(command: &str, reason: impl Into<Cow<'static, str>>, error_code: i32) -> Error {
    Error::Process(ProcessError::SpawnFailed(ProcessSpawnError::with_code(
        Cow::Owned(command.to_string()),
        reason,
        error_code,
    )))
}

fn close_handle_if_valid(handle: HANDLE) {
    if !handle.0.is_null() {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}

struct EnvBlock(*mut c_void);

impl EnvBlock {
    fn as_ptr(&self) -> *mut c_void {
        self.0
    }

    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl Drop for EnvBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = DestroyEnvironmentBlock(self.0);
            }
        }
    }
}

struct AttributeList {
    buffer: Vec<u8>,
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
    initialized: bool,
}

impl AttributeList {
    fn with_parent(parent_handle: &HANDLE) -> Result<Self> {
        let mut size = 0;
        unsafe {
            let _ = InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                1,
                0,
                &mut size,
            );
        }

        let mut buffer = vec![0u8; size];
        let ptr = LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr() as *mut _);

        unsafe { InitializeProcThreadAttributeList(ptr, 1, 0, &mut size) }.map_err(|e| {
            Error::Process(ProcessError::SpawnFailed(ProcessSpawnError::with_code(
                "<attribute_list>",
                "Failed to initialize process attribute list",
                e.code().0,
            )))
        })?;

        let parent_ptr = std::ptr::addr_of!(parent_handle.0);

        if let Err(e) = unsafe {
            UpdateProcThreadAttribute(
                ptr,
                0,
                PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
                Some(parent_ptr as *const _ as *mut _),
                std::mem::size_of::<HANDLE>(),
                None,
                None,
            )
        } {
            unsafe {
                DeleteProcThreadAttributeList(ptr);
            }
            return Err(Error::Process(ProcessError::SpawnFailed(
                ProcessSpawnError::with_code(
                    "<attribute_list>",
                    "Failed to set parent process attribute",
                    e.code().0,
                ),
            )));
        }

        Ok(Self {
            buffer,
            ptr,
            initialized: true,
        })
    }

    fn ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.ptr
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.ptr);
            }
        }
        self.buffer.clear();
    }
}

fn get_user_token_from_pid(pid: ProcessId, command: &str) -> Result<OwnedHandle> {
    let process_handle =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid.as_u32()) }.map_err(
            |e| map_spawn_windows_error(command, "Failed to open token source process", &e),
        )?;

    let process_handle = OwnedHandle::new(process_handle);

    let mut token = HANDLE(std::ptr::null_mut());
    unsafe {
        OpenProcessToken(
            process_handle.raw(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS,
            &mut token,
        )
    }
    .map_err(|e| map_spawn_windows_error(command, "Failed to open process token", &e))?;

    let token = OwnedHandle::new(token);

    let mut duplicated = HANDLE(std::ptr::null_mut());
    unsafe {
        DuplicateTokenEx(
            token.raw(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS | TOKEN_QUERY | TOKEN_DUPLICATE,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicated,
        )
    }
    .map_err(|e| map_spawn_windows_error(command, "Failed to duplicate process token", &e))?;

    Ok(OwnedHandle::new(duplicated))
}

fn enable_privilege(privilege_name: &str, command: &str) -> Result<()> {
    let mut token = HANDLE(std::ptr::null_mut());
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .map_err(|e| map_spawn_windows_error(command, "Failed to open current process token", &e))?;

    let token = OwnedHandle::new(token);
    let mut token_privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: Default::default(),
    };

    let privilege_wide = to_utf16_nul(privilege_name);
    unsafe {
        LookupPrivilegeValueW(
            None,
            PCWSTR(privilege_wide.as_ptr()),
            &mut token_privileges.Privileges[0].Luid,
        )
    }
    .map_err(|e| map_spawn_windows_error(command, "Failed to lookup privilege LUID", &e))?;

    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    unsafe { AdjustTokenPrivileges(token.raw(), false, Some(&token_privileges), 0, None, None) }
        .map_err(|e| map_spawn_windows_error(command, "Failed to adjust token privileges", &e))?;

    let last_error: WIN32_ERROR = unsafe { GetLastError() };
    if last_error == ERROR_NOT_ALL_ASSIGNED {
        return Err(spawn_error(
            command,
            Cow::Owned(format!(
                "Privilege '{privilege_name}' was not assigned to current token"
            )),
            last_error.0 as i32,
        ));
    }

    Ok(())
}

fn create_env_block(token: HANDLE, command: &str) -> Result<EnvBlock> {
    let mut env_block: *mut c_void = std::ptr::null_mut();
    unsafe { CreateEnvironmentBlock(&mut env_block, token, false) }
        .map_err(|e| map_spawn_windows_error(command, "Failed to create environment block", &e))?;
    Ok(EnvBlock(env_block))
}

fn get_userprofile_from_env_block(env_block: *mut c_void) -> Option<Vec<u16>> {
    if env_block.is_null() {
        return None;
    }

    unsafe {
        let mut ptr = env_block as *const u16;
        while *ptr != 0 {
            let mut len = 0usize;
            while *ptr.add(len) != 0 {
                len += 1;
            }

            let env_var = std::slice::from_raw_parts(ptr, len);
            let env_var_string = String::from_utf16_lossy(env_var);

            if let Some(eq_pos) = env_var_string.find('=')
                && env_var_string.starts_with("USERPROFILE=")
            {
                let value_len = env_var_string[eq_pos + 1..].encode_utf16().count();
                let mut out = std::slice::from_raw_parts(ptr.add(eq_pos + 1), value_len).to_vec();
                out.push(0);
                return Some(out);
            }

            ptr = ptr.add(len + 1);
        }
    }

    None
}

/// A spawned process with owned process/thread handles.
pub struct SpawnedProcess {
    pid: ProcessId,
    thread_id: ThreadId,
    process: HANDLE,
    thread: HANDLE,
}

impl SpawnedProcess {
    /// Process ID for the newly spawned process.
    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    /// Primary thread ID for the newly spawned process.
    pub fn thread_id(&self) -> ThreadId {
        self.thread_id
    }

    /// Resume the primary thread. Useful when spawned in suspended state.
    pub fn resume(&self) -> Result<()> {
        let result = unsafe { ResumeThread(self.thread) };
        if result == u32::MAX {
            let err = windows::core::Error::from_win32();
            return Err(Error::Process(ProcessError::SpawnFailed(
                ProcessSpawnError::with_code(
                    "<resume-thread>",
                    "Failed to resume spawned process thread",
                    err.code().0,
                ),
            )));
        }
        Ok(())
    }

    /// Open a managed `Process` handle for the spawned process.
    pub fn open_process(&self, access: ProcessAccess) -> Result<Process> {
        Process::open_with_access(self.pid, access)
    }
}

impl Drop for SpawnedProcess {
    fn drop(&mut self) {
        close_handle_if_valid(self.process);
        close_handle_if_valid(self.thread);
    }
}

unsafe impl Send for SpawnedProcess {}

/// Builder for spawning processes with optional parent reparenting and token source.
#[derive(Debug, Clone)]
pub struct ProcessSpawner {
    exe_path: String,
    args: Vec<String>,
    parent_pid: Option<ProcessId>,
    token_source_pid: Option<ProcessId>,
    suspended: bool,
    desktop: Option<String>,
}

impl ProcessSpawner {
    /// Create a new process spawner for an executable path.
    pub fn new(exe_path: &str) -> Self {
        Self {
            exe_path: exe_path.to_string(),
            args: Vec::new(),
            parent_pid: None,
            token_source_pid: None,
            suspended: false,
            desktop: None,
        }
    }

    /// Set command-line arguments for the spawned process.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_string())
            .collect();
        self
    }

    /// Set the parent process for reparenting via process attributes.
    pub fn parent(mut self, pid: ProcessId) -> Self {
        self.parent_pid = Some(pid);
        self
    }

    /// Launch under a duplicated primary token from another process ID.
    pub fn as_user_of(mut self, pid: ProcessId) -> Self {
        self.token_source_pid = Some(pid);
        self
    }

    /// Spawn the process in suspended state.
    pub fn suspended(mut self) -> Self {
        self.suspended = true;
        self
    }

    /// Set an explicit desktop for process creation (e.g. "winsta0\\default").
    pub fn desktop(mut self, desktop: &str) -> Self {
        self.desktop = Some(desktop.to_string());
        self
    }

    /// Spawn the process using the configured options.
    pub fn spawn(self) -> Result<SpawnedProcess> {
        if self.exe_path.trim().is_empty() {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "exe_path",
                "Executable path cannot be empty",
            )));
        }

        let command = format_command_line(&self.exe_path, &self.args);
        let mut command_wide = to_utf16_nul(&command);

        let mut creation_flags =
            EXTENDED_STARTUPINFO_PRESENT | CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_CONSOLE;

        if self.suspended {
            creation_flags |= CREATE_SUSPENDED;
        }

        let mut process_info = PROCESS_INFORMATION::default();
        let mut startup_info = STARTUPINFOEXW::default();
        startup_info.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

        let mut desktop_wide = self.desktop.as_deref().map(to_utf16_nul).or_else(|| {
            if self.token_source_pid.is_some() {
                Some(to_utf16_nul(DEFAULT_DESKTOP))
            } else {
                None
            }
        });

        if let Some(desktop) = desktop_wide.as_mut() {
            startup_info.StartupInfo.lpDesktop = windows::core::PWSTR(desktop.as_mut_ptr());
        }

        let parent_handle = if let Some(parent_pid) = self.parent_pid {
            let handle = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_PROCESS,
                    false,
                    parent_pid.as_u32(),
                )
            }
            .map_err(|e| map_spawn_windows_error(&command, "Failed to open parent process", &e))?;
            Some(OwnedHandle::new(handle))
        } else {
            None
        };

        let attribute_list = if let Some(parent) = parent_handle.as_ref() {
            let attrs = AttributeList::with_parent(&parent.raw())?;
            startup_info.lpAttributeList = attrs.ptr();
            Some(attrs)
        } else {
            None
        };

        let mut env_block: Option<EnvBlock> = None;
        let mut current_directory_wide: Option<Vec<u16>> = None;

        let process_token = if let Some(token_source_pid) = self.token_source_pid {
            enable_privilege("SeAssignPrimaryTokenPrivilege", &command)?;
            enable_privilege("SeIncreaseQuotaPrivilege", &command)?;

            let token = get_user_token_from_pid(token_source_pid, &command)?;
            let block = create_env_block(token.raw(), &command)?;
            if !block.is_null() {
                current_directory_wide = get_userprofile_from_env_block(block.as_ptr());
            }
            env_block = Some(block);
            creation_flags |= CREATE_UNICODE_ENVIRONMENT;
            Some(token)
        } else {
            None
        };

        let command_ptr = windows::core::PWSTR(command_wide.as_mut_ptr());
        let current_dir = current_directory_wide
            .as_ref()
            .map(|v| PCWSTR(v.as_ptr()))
            .unwrap_or(PCWSTR::null());

        let result = if let Some(token) = process_token.as_ref() {
            unsafe {
                CreateProcessAsUserW(
                    token.raw(),
                    PCWSTR::null(),
                    command_ptr,
                    None,
                    None,
                    false,
                    creation_flags,
                    env_block.as_ref().map(|b| b.as_ptr() as *const c_void),
                    current_dir,
                    &startup_info.StartupInfo as *const _ as *const _,
                    &mut process_info,
                )
            }
        } else {
            unsafe {
                CreateProcessW(
                    PCWSTR::null(),
                    command_ptr,
                    None,
                    None,
                    false,
                    creation_flags,
                    None,
                    current_dir,
                    &startup_info.StartupInfo,
                    &mut process_info,
                )
            }
        };

        let _keep_attr_alive = attribute_list;

        result.map_err(|e| map_spawn_windows_error(&command, "Failed to spawn process", &e))?;

        Ok(SpawnedProcess {
            pid: ProcessId::new(process_info.dwProcessId),
            thread_id: ThreadId::new(process_info.dwThreadId),
            process: process_info.hProcess,
            thread: process_info.hThread,
        })
    }
}
