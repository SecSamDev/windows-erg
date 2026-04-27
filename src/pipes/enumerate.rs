use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_DIRECTORY_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_PIPE_LOCAL_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    FileDirectoryInformation, FilePipeLocalInformation, NtCreateFile, NtQueryDirectoryFile,
    NtQueryInformationFile,
};
use windows::Win32::Foundation::{HANDLE, RtlNtStatusToDosError, UNICODE_STRING};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAGS_AND_ATTRIBUTES, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows::core::PWSTR;

use crate::error::{Error, PipeError, PipeIoError, Result};
use crate::utils::to_utf16_nul;

use super::types::{
    NamedPipeChange, NamedPipeInfo, NamedPipeLocalInfo, PipeName, filetime_to_system_time,
};
use crate::types::ProcessId;

const NAMED_PIPE_DIRECTORY_PATH: &str = r"\Device\NamedPipe\";
const NAMED_PIPE_DIRECTORY_RESOURCE: &str = r"\Device\NamedPipe";
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const STATUS_SUCCESS: i32 = 0;
const STATUS_NO_MORE_FILES: i32 = 0x8000_0006_u32 as i32;
const DIRECTORY_BUFFER_CAPACITY: usize = 64 * 1024;

/// Stateful helper that diffs successive named-pipe snapshots.
#[derive(Debug, Default)]
pub struct NamedPipePoller {
    known_pipes: HashMap<PipeName, NamedPipeInfo>,
}

impl NamedPipePoller {
    /// Create a poller with an empty baseline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the current baseline with the latest snapshot and return detected changes.
    pub fn poll(&mut self) -> Result<Vec<NamedPipeChange>> {
        let current_pipes = list()?;
        let mut current_map = HashMap::with_capacity(current_pipes.len());

        for pipe in current_pipes {
            current_map.insert(pipe.pipe_name.clone(), pipe);
        }

        let mut changes = Vec::new();

        for (pipe_name, pipe_info) in &current_map {
            if !self.known_pipes.contains_key(pipe_name) {
                changes.push(NamedPipeChange::Appeared(pipe_info.clone()));
            }
        }

        for (pipe_name, pipe_info) in &self.known_pipes {
            if !current_map.contains_key(pipe_name) {
                changes.push(NamedPipeChange::Removed(pipe_info.clone()));
            }
        }

        changes.sort_by(|left, right| change_name(left).cmp(change_name(right)));
        self.known_pipes = current_map;

        Ok(changes)
    }

    /// Seed the baseline from the current snapshot without reporting any changes.
    pub fn seed(&mut self) -> Result<usize> {
        let current_pipes = list()?;
        self.known_pipes = current_pipes
            .into_iter()
            .map(|pipe| (pipe.pipe_name.clone(), pipe))
            .collect();
        Ok(self.known_pipes.len())
    }

    /// Poll for a fixed number of rounds with a sleep interval between rounds.
    pub fn poll_interval(
        &mut self,
        rounds: usize,
        interval: Duration,
    ) -> Result<Vec<Vec<NamedPipeChange>>> {
        let mut snapshots = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            thread::sleep(interval);
            snapshots.push(self.poll()?);
        }
        Ok(snapshots)
    }

    /// Poll for a fixed number of rounds and invoke a callback for each round.
    ///
    /// Returns the total number of changes observed across all rounds.
    pub fn poll_interval_with_callback<F>(
        &mut self,
        rounds: usize,
        interval: Duration,
        mut callback: F,
    ) -> Result<usize>
    where
        F: FnMut(usize, &[NamedPipeChange]),
    {
        let mut total_changes = 0usize;
        for round in 1..=rounds {
            thread::sleep(interval);
            let changes = self.poll()?;
            total_changes += changes.len();
            callback(round, &changes);
        }
        Ok(total_changes)
    }
}

pub fn poll_interval(rounds: usize, interval: Duration) -> Result<Vec<Vec<NamedPipeChange>>> {
    let mut poller = NamedPipePoller::new();
    poller.seed()?;
    poller.poll_interval(rounds, interval)
}

pub fn poll_interval_with_callback<F>(
    rounds: usize,
    interval: Duration,
    callback: F,
) -> Result<usize>
where
    F: FnMut(usize, &[NamedPipeChange]),
{
    let mut poller = NamedPipePoller::new();
    poller.seed()?;
    poller.poll_interval_with_callback(rounds, interval, callback)
}

pub fn list() -> Result<Vec<NamedPipeInfo>> {
    let mut out_pipes = Vec::with_capacity(64);
    list_with_buffer(&mut out_pipes)?;
    Ok(out_pipes)
}

pub fn list_with_buffer(out_pipes: &mut Vec<NamedPipeInfo>) -> Result<usize> {
    list_with_filter(out_pipes, |_| true)
}

pub fn list_with_filter<F>(out_pipes: &mut Vec<NamedPipeInfo>, filter: F) -> Result<usize>
where
    F: Fn(&NamedPipeInfo) -> bool,
{
    out_pipes.clear();

    let directory_handle = open_named_pipe_directory()?;
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut work_buffer = vec![0u8; DIRECTORY_BUFFER_CAPACITY];
    let mut restart_scan = true;

    loop {
        let status = unsafe {
            NtQueryDirectoryFile(
                directory_handle.raw(),
                HANDLE(std::ptr::null_mut()),
                None,
                None,
                &mut io_status,
                work_buffer.as_mut_ptr() as *mut _,
                work_buffer.len() as u32,
                FileDirectoryInformation,
                false,
                None,
                restart_scan,
            )
        };

        let status_code = status.0;
        if status_code == STATUS_NO_MORE_FILES {
            break;
        }

        if status_code != STATUS_SUCCESS {
            return Err(pipe_directory_status_error(
                "query named pipe directory",
                status_code,
            ));
        }

        let bytes_returned = io_status.Information;
        if bytes_returned == 0 {
            break;
        }

        parse_directory_entries(&work_buffer[..bytes_returned], out_pipes, &filter)?;
        restart_scan = false;
    }

    out_pipes.sort_by(|left, right| left.pipe_name.as_str().cmp(right.pipe_name.as_str()));
    Ok(out_pipes.len())
}

pub fn query_local_info(pipe_name: &PipeName) -> Result<NamedPipeLocalInfo> {
    let relative_name = pipe_name
        .as_str()
        .strip_prefix(PipeName::PREFIX)
        .ok_or_else(|| {
            Error::Pipe(PipeError::Io(PipeIoError::new(
                NAMED_PIPE_DIRECTORY_RESOURCE,
                "derive relative pipe name",
            )))
        })?;

    let relative_utf16: Vec<u16> = relative_name.encode_utf16().collect();
    query_pipe_local_info(&relative_utf16)
}

fn parse_directory_entries<F>(
    buffer: &[u8],
    out_pipes: &mut Vec<NamedPipeInfo>,
    filter: &F,
) -> Result<()>
where
    F: Fn(&NamedPipeInfo) -> bool,
{
    let mut offset = 0usize;

    while offset < buffer.len() {
        let entry = unsafe { &*(buffer.as_ptr().add(offset) as *const FILE_DIRECTORY_INFORMATION) };

        let name_len = (entry.FileNameLength / 2) as usize;
        let name_slice = unsafe { std::slice::from_raw_parts(entry.FileName.as_ptr(), name_len) };
        let relative_name = String::from_utf16_lossy(name_slice);

        if !relative_name.is_empty() {
            let pipe_name = PipeName::from_relative_name(&relative_name).map_err(|_| {
                Error::Pipe(PipeError::Io(PipeIoError::new(
                    NAMED_PIPE_DIRECTORY_RESOURCE,
                    "parse named pipe directory entry",
                )))
            })?;

            let pipe_info = NamedPipeInfo {
                pipe_name,
                relative_name,
                creation_time: filetime_to_system_time(entry.CreationTime),
                last_access_time: filetime_to_system_time(entry.LastAccessTime),
                last_write_time: filetime_to_system_time(entry.LastWriteTime),
                change_time: filetime_to_system_time(entry.ChangeTime),
                end_of_file: entry.EndOfFile,
                allocation_size: entry.AllocationSize,
                file_attributes: entry.FileAttributes,
                file_index: entry.FileIndex,
                local_info: None,
            };

            if filter(&pipe_info) {
                out_pipes.push(pipe_info);
            }
        }

        if entry.NextEntryOffset == 0 {
            break;
        }

        offset += entry.NextEntryOffset as usize;
    }

    Ok(())
}

fn query_pipe_local_info(relative_name_utf16: &[u16]) -> Result<NamedPipeLocalInfo> {
    let pipe_handle = open_named_pipe_file(relative_name_utf16)?;
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut local_info = FILE_PIPE_LOCAL_INFORMATION::default();

    let status = unsafe {
        NtQueryInformationFile(
            pipe_handle.raw(),
            &mut io_status,
            &mut local_info as *mut _ as *mut _,
            std::mem::size_of::<FILE_PIPE_LOCAL_INFORMATION>() as u32,
            FilePipeLocalInformation,
        )
    };

    if status.0 != STATUS_SUCCESS {
        return Err(pipe_directory_status_error(
            "query named pipe local information",
            status.0,
        ));
    }

    let server_process_id = unsafe {
        let mut pid: u32 = 0;
        if GetNamedPipeServerProcessId(pipe_handle.raw(), &mut pid).is_ok() {
            Some(ProcessId(pid))
        } else {
            None
        }
    };

    Ok(NamedPipeLocalInfo {
        named_pipe_type: local_info.NamedPipeType,
        named_pipe_configuration: local_info.NamedPipeConfiguration,
        maximum_instances: local_info.MaximumInstances,
        current_instances: local_info.CurrentInstances,
        inbound_quota: local_info.InboundQuota,
        read_data_available: local_info.ReadDataAvailable,
        outbound_quota: local_info.OutboundQuota,
        write_quota_available: local_info.WriteQuotaAvailable,
        named_pipe_state: local_info.NamedPipeState,
        named_pipe_end: local_info.NamedPipeEnd,
        server_process_id,
    })
}

fn open_named_pipe_directory() -> Result<crate::utils::OwnedHandle> {
    let mut nt_path_wide = to_utf16_nul(NAMED_PIPE_DIRECTORY_PATH);
    let mut unicode_name = UNICODE_STRING {
        Length: ((nt_path_wide.len() - 1) * 2) as u16,
        MaximumLength: (nt_path_wide.len() * 2) as u16,
        Buffer: PWSTR(nt_path_wide.as_mut_ptr()),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: HANDLE(std::ptr::null_mut()),
        ObjectName: &mut unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut directory_handle = HANDLE(std::ptr::null_mut());

    let status = unsafe {
        NtCreateFile(
            &mut directory_handle,
            windows::Win32::Storage::FileSystem::FILE_ACCESS_RIGHTS(
                FILE_LIST_DIRECTORY.0 | SYNCHRONIZE_ACCESS,
            ),
            &object_attributes,
            &mut io_status,
            None,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT,
            None,
            0,
        )
    };

    if status.0 != STATUS_SUCCESS {
        return Err(pipe_directory_status_error(
            "open named pipe directory",
            status.0,
        ));
    }

    Ok(crate::utils::OwnedHandle::new(directory_handle))
}

fn open_named_pipe_file(relative_name_utf16: &[u16]) -> Result<crate::utils::OwnedHandle> {
    let mut nt_path_wide = Vec::with_capacity(
        NAMED_PIPE_DIRECTORY_PATH.encode_utf16().count() + relative_name_utf16.len() + 1,
    );
    nt_path_wide.extend(NAMED_PIPE_DIRECTORY_PATH.encode_utf16());
    nt_path_wide.extend_from_slice(relative_name_utf16);
    nt_path_wide.push(0);

    let mut unicode_name = UNICODE_STRING {
        Length: ((nt_path_wide.len() - 1) * 2) as u16,
        MaximumLength: (nt_path_wide.len() * 2) as u16,
        Buffer: PWSTR(nt_path_wide.as_mut_ptr()),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: HANDLE(std::ptr::null_mut()),
        ObjectName: &mut unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut pipe_handle = HANDLE(std::ptr::null_mut());

    let status = unsafe {
        NtCreateFile(
            &mut pipe_handle,
            windows::Win32::Storage::FileSystem::FILE_ACCESS_RIGHTS(
                FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE_ACCESS,
            ),
            &object_attributes,
            &mut io_status,
            None,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            None,
            0,
        )
    };

    if status.0 != STATUS_SUCCESS {
        return Err(pipe_directory_status_error(
            "open named pipe for local info",
            status.0,
        ));
    }

    Ok(crate::utils::OwnedHandle::new(pipe_handle))
}

fn change_name(change: &NamedPipeChange) -> &str {
    match change {
        NamedPipeChange::Appeared(info) | NamedPipeChange::Removed(info) => info.pipe_name.as_str(),
    }
}

fn pipe_directory_status_error(operation: &'static str, status: i32) -> Error {
    let error_code = unsafe { RtlNtStatusToDosError(windows::Win32::Foundation::NTSTATUS(status)) };
    let mapped_code = if error_code == 0 {
        status
    } else {
        error_code as i32
    };

    Error::Pipe(PipeError::Io(PipeIoError::with_code(
        NAMED_PIPE_DIRECTORY_RESOURCE,
        operation,
        mapped_code,
    )))
}
