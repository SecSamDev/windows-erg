use std::path::Path;

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_BEGIN, FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GetDiskFreeSpaceW, GetFileSize, OPEN_EXISTING, ReadFile,
    SetFilePointerEx,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{FSCTL_GET_RETRIEVAL_POINTERS, STARTING_VCN_INPUT_BUFFER};
use windows::core::{Error as WinError, PCWSTR};

use crate::Result;
use crate::error::{Error, FileOperationError, InvalidParameterError};
use crate::utils::to_utf16_nul_in;

pub(crate) fn encode_pcwstr(text: &str, out_buffer: &mut Vec<u16>) {
    to_utf16_nul_in(text, out_buffer);
}

pub(crate) fn get_drive_and_disk(path: &Path) -> Result<(String, String)> {
    let path_string = path.to_string_lossy();
    let mut chars = path_string.chars();

    let drive = chars.next().ok_or_else(|| {
        Error::InvalidParameter(InvalidParameterError::new("path", "Path cannot be empty"))
    })?;

    let separator = chars.next().ok_or_else(|| {
        Error::InvalidParameter(InvalidParameterError::new(
            "path",
            "Path must include a drive separator",
        ))
    })?;

    if separator != ':' || !drive.is_ascii_alphabetic() {
        return Err(Error::InvalidParameter(InvalidParameterError::new(
            "path",
            "Path must start with a drive letter (for example C:\\...)",
        )));
    }

    let drive_letter = drive.to_ascii_uppercase();
    Ok((
        format!(r"\\.\{}:", drive_letter),
        format!("{}:\\", drive_letter),
    ))
}

pub(crate) fn get_drive_metadata(
    path: &Path,
    work_buffer: &mut Buffer,
) -> Result<(HANDLE, u32, u32)> {
    let (drive_path, disk_letter) = get_drive_and_disk(path)?;

    let disk_name = work_buffer.u16_vec();
    encode_pcwstr(&drive_path, disk_name);

    let disk_handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(disk_name.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| {
        Error::FileOperation(FileOperationError::with_code(
            path.to_string_lossy().to_string(),
            "open source volume",
            e.code().0,
        ))
    })?;

    let mut sectors_in_cluster = 0u32;
    let mut bytes_per_sector = 0u32;
    let mut free_clusters = 0u32;
    let mut total_clusters = 0u32;

    encode_pcwstr(&disk_letter, disk_name);
    unsafe {
        GetDiskFreeSpaceW(
            PCWSTR::from_raw(disk_name.as_ptr()),
            Some(&mut sectors_in_cluster),
            Some(&mut bytes_per_sector),
            Some(&mut free_clusters),
            Some(&mut total_clusters),
        )
    }
    .map_err(|e| {
        Error::FileOperation(FileOperationError::with_code(
            path.to_string_lossy().to_string(),
            "query source volume metadata",
            e.code().0,
        ))
    })?;

    Ok((disk_handle, sectors_in_cluster, bytes_per_sector))
}

pub(crate) fn get_file_pointer_and_size(
    path: &Path,
    work_buffer: &mut Buffer,
) -> Result<(HANDLE, u64)> {
    let file_name = format!(r"\\.\{}", path.to_string_lossy());
    let file_name_wide = work_buffer.u16_vec();
    encode_pcwstr(&file_name, file_name_wide);

    let file_handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(file_name_wide.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0),
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map_err(|e| {
        Error::FileOperation(FileOperationError::with_code(
            path.to_string_lossy().to_string(),
            "open source file metadata handle",
            e.code().0,
        ))
    })?;

    let mut file_size_high = 0u32;
    let file_size_low = unsafe { GetFileSize(file_handle, Some(&mut file_size_high)) };
    let file_size = ((file_size_high as u64) << 32) | file_size_low as u64;

    Ok((file_handle, file_size))
}

pub(crate) fn get_retrieval_pointers(
    file_handle: HANDLE,
    work_buffer: &mut Buffer,
) -> Result<RetrievalPointersBuffer> {
    let mut in_buffer = STARTING_VCN_INPUT_BUFFER::default();
    let mut bytes_returned = 0u32;

    let out_buffer = work_buffer.u8();
    let out_buffer_size = out_buffer.len() as u32;

    unsafe {
        DeviceIoControl(
            file_handle,
            FSCTL_GET_RETRIEVAL_POINTERS,
            Some(std::ptr::addr_of_mut!(in_buffer) as _),
            std::mem::size_of::<STARTING_VCN_INPUT_BUFFER>() as u32,
            Some(out_buffer.as_mut_ptr() as _),
            out_buffer_size,
            Some(&mut bytes_returned),
            None,
        )
    }
    .map_err(|e: WinError| {
        Error::FileOperation(FileOperationError::with_code(
            "source file".to_string(),
            "query file retrieval pointers",
            e.code().0,
        ))
    })?;

    buffer_to_retrieval_pointers(&out_buffer[..bytes_returned as usize])
}

pub(crate) fn move_disk_position(disk_handle: HANDLE, offset: i64) -> std::io::Result<()> {
    unsafe { SetFilePointerEx(disk_handle, offset, None, FILE_BEGIN) }
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
    Ok(())
}

pub(crate) fn read_file_from_disk_pointer(
    disk_handle: HANDLE,
    out_buffer: &mut [u8],
    bytes_to_read: u32,
) -> std::io::Result<u32> {
    if out_buffer.len() < bytes_to_read as usize {
        return Err(std::io::Error::from_raw_os_error(
            ERROR_INSUFFICIENT_BUFFER.0 as i32,
        ));
    }

    let io_buffer = &mut out_buffer[..bytes_to_read as usize];
    let mut read_bytes = 0u32;

    unsafe { ReadFile(disk_handle, Some(io_buffer), Some(&mut read_bytes), None) }
        .map_err(|e: WinError| std::io::Error::from_raw_os_error(e.code().0))?;

    Ok(read_bytes)
}

pub(crate) fn buffer_to_retrieval_pointers(buffer: &[u8]) -> Result<RetrievalPointersBuffer> {
    if buffer.len() < 16 {
        return Err(Error::FileOperation(FileOperationError::new(
            "source file",
            "parse retrieval pointers",
        )));
    }

    let extent_count = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let starting_vcn = i64::from_le_bytes(buffer[8..16].try_into().map_err(|_| {
        Error::FileOperation(FileOperationError::new(
            "source file",
            "parse retrieval pointer starting VCN",
        ))
    })?);

    let mut extents = Vec::with_capacity(extent_count as usize);
    let mut offset = 16usize;

    for _ in 0..extent_count {
        if buffer.len() < offset + 16 {
            return Err(Error::FileOperation(FileOperationError::new(
                "source file",
                "parse retrieval pointer extents",
            )));
        }

        let next_vcn = i64::from_le_bytes(buffer[offset..offset + 8].try_into().map_err(|_| {
            Error::FileOperation(FileOperationError::new(
                "source file",
                "parse retrieval pointer next VCN",
            ))
        })?);

        let lcn = i64::from_le_bytes(buffer[offset + 8..offset + 16].try_into().map_err(|_| {
            Error::FileOperation(FileOperationError::new(
                "source file",
                "parse retrieval pointer LCN",
            ))
        })?);

        offset += 16;
        extents.push(PointerExtent { next_vcn, lcn });
    }

    Ok(RetrievalPointersBuffer {
        extent_count,
        starting_vcn,
        extents,
    })
}

#[derive(Debug, Clone)]
#[repr(C)]
pub(crate) struct RetrievalPointersBuffer {
    pub extent_count: u32,
    pub starting_vcn: i64,
    pub extents: Vec<PointerExtent>,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub(crate) struct PointerExtent {
    pub next_vcn: i64,
    pub lcn: i64,
}

/// Work buffer for raw Windows API operations.
pub(crate) struct Buffer {
    u8_buffer: Vec<u8>,
    u16_buffer: Vec<u16>,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            u8_buffer: vec![0u8; 1024],
            u16_buffer: vec![0u16; 1024],
        }
    }

    pub fn with_capacity(size: usize) -> Self {
        Self {
            u8_buffer: vec![0u8; size],
            u16_buffer: vec![0u16; size],
        }
    }

    pub fn u8(&mut self) -> &mut [u8] {
        &mut self.u8_buffer
    }

    pub fn u16_vec(&mut self) -> &mut Vec<u16> {
        &mut self.u16_buffer
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{buffer_to_retrieval_pointers, get_drive_and_disk};
    use std::path::Path;

    #[test]
    fn parses_drive_and_disk_prefix() {
        let (drive, disk) = get_drive_and_disk(Path::new(r"C:\\Windows\\notepad.exe")).unwrap();
        assert_eq!(drive, r"\\.\C:");
        assert_eq!(disk, r"C:\");
    }

    #[test]
    fn parses_retrieval_pointer_buffer() {
        // extent_count=1, reserved=0, starting_vcn=0, next_vcn=4, lcn=1024
        let mut raw = Vec::new();
        raw.extend(1u32.to_le_bytes());
        raw.extend(0u32.to_le_bytes());
        raw.extend(0i64.to_le_bytes());
        raw.extend(4i64.to_le_bytes());
        raw.extend(1024i64.to_le_bytes());

        let parsed = buffer_to_retrieval_pointers(&raw).unwrap();
        assert_eq!(parsed.extent_count, 1);
        assert_eq!(parsed.starting_vcn, 0);
        assert_eq!(parsed.extents.len(), 1);
        assert_eq!(parsed.extents[0].next_vcn, 4);
        assert_eq!(parsed.extents[0].lcn, 1024);
    }
}
