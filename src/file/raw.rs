use std::borrow::Cow;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};

use crate::Result;
use crate::error::{Error, FileOperationError, InvalidParameterError};

use super::builder::RawFileBuilder;
use super::win::{
    Buffer, PointerExtent, RetrievalPointersBuffer, get_drive_metadata, get_file_pointer_and_size,
    get_retrieval_pointers, move_disk_position, read_file_from_disk_pointer,
};

struct OwnedHandle {
    handle: HANDLE,
    close_on_drop: bool,
}

impl OwnedHandle {
    fn new(handle: HANDLE, close_on_drop: bool) -> Self {
        Self {
            handle,
            close_on_drop,
        }
    }

    fn raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.close_on_drop {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

/// Low-level reader for file content through raw disk cluster reads.
///
/// This type is Windows-only and intended for privileged scenarios where
/// reading file extents directly from disk is required.
pub struct RawFile {
    source_path: PathBuf,
    disk_handle: OwnedHandle,
    file_size: u64,
    retrieval_pointers: RetrievalPointersBuffer,
    bytes_per_cluster: usize,
    clusters_per_read: usize,
    extent_index: usize,
    bytes_read: usize,
    cluster_index: usize,
}

impl RawFile {
    /// Open a raw file reader with default tuning values.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - `path` is empty or not a drive-qualified path,
    /// - source file metadata cannot be opened,
    /// - raw volume metadata cannot be queried,
    /// - retrieval pointer data is unavailable for the file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_tuning(path, 16, 32_000)
    }

    /// Create a builder for opening a raw file reader.
    ///
    /// This is the preferred entry point when custom read tuning is needed.
    pub fn builder() -> RawFileBuilder {
        RawFileBuilder::new()
    }

    /// Open a raw file reader with custom tuning values.
    pub(crate) fn open_with_tuning<P: AsRef<Path>>(
        path: P,
        clusters_per_read: usize,
        metadata_buffer_capacity: usize,
    ) -> Result<Self> {
        let source_path = path.as_ref().to_path_buf();
        if source_path.as_os_str().is_empty() {
            return Err(Error::InvalidParameter(InvalidParameterError::new(
                "path",
                "Raw file path cannot be empty",
            )));
        }

        let mut work_buffer = Buffer::with_capacity(metadata_buffer_capacity.max(4096));

        let (disk_handle, sectors_in_cluster, bytes_per_sector) =
            get_drive_metadata(&source_path, &mut work_buffer)?;

        let (file_metadata_handle, file_size) =
            get_file_pointer_and_size(&source_path, &mut work_buffer)?;

        let metadata_handle = OwnedHandle::new(file_metadata_handle, true);
        let retrieval_pointers = get_retrieval_pointers(metadata_handle.raw(), &mut work_buffer)?;

        Ok(Self {
            source_path,
            disk_handle: OwnedHandle::new(disk_handle, true),
            file_size,
            retrieval_pointers,
            bytes_per_cluster: (bytes_per_sector * sectors_in_cluster) as usize,
            clusters_per_read: clusters_per_read.max(1),
            extent_index: 0,
            bytes_read: 0,
            cluster_index: 0,
        })
    }

    /// Copy this source file into the given destination path.
    ///
    /// The destination is created or truncated.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - the destination cannot be created,
    /// - source data cannot be read from raw extents,
    /// - destination writes or flush fail,
    /// - the current process does not have required privileges.
    pub fn copy_to<P: AsRef<Path>>(&self, destination: P) -> Result<()> {
        let destination_path = destination.as_ref();

        let mut source = RawFile::builder()
            .path(&self.source_path)
            .clusters_per_read(self.clusters_per_read)
            .open()?;

        let mut read_buffer = vec![0u8; source.bytes_per_cluster * source.clusters_per_read];

        let file = std::fs::File::create(destination_path).map_err(|e| {
            file_op_error_with_io_code(destination_path, "create destination file", e)
        })?;

        let mut writer = std::io::BufWriter::new(file);

        loop {
            let read = source.read(&mut read_buffer).map_err(|e| {
                file_op_error_with_io_code(&self.source_path, "read source file", e)
            })?;

            if read == 0 {
                break;
            }

            writer.write_all(&read_buffer[..read]).map_err(|e| {
                file_op_error_with_io_code(destination_path, "write destination file", e)
            })?;
        }

        writer.flush().map_err(|e| {
            file_op_error_with_io_code(destination_path, "flush destination file", e)
        })?;

        Ok(())
    }

    fn current_extent(&self) -> Option<&PointerExtent> {
        self.retrieval_pointers.extents.get(self.extent_index)
    }
}

impl Read for RawFile {
    fn read(&mut self, out_buffer: &mut [u8]) -> std::io::Result<usize> {
        if out_buffer.len() < self.bytes_per_cluster {
            return Err(std::io::Error::from_raw_os_error(
                ERROR_INSUFFICIENT_BUFFER.0 as i32,
            ));
        }

        if self.bytes_read >= self.file_size as usize {
            return Ok(0);
        }

        while let Some(extent) = self.current_extent() {
            let previous_vcn = if self.extent_index > 0 {
                self.retrieval_pointers.extents[self.extent_index - 1].next_vcn
            } else {
                self.retrieval_pointers.starting_vcn
            };

            if extent.next_vcn < previous_vcn {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Retrieval pointers are not monotonic",
                ));
            }

            let extent_cluster_count = (extent.next_vcn - previous_vcn) as usize;
            if self.cluster_index >= extent_cluster_count {
                self.extent_index += 1;
                self.cluster_index = 0;
                continue;
            }

            let clusters_available = extent_cluster_count - self.cluster_index;
            let cluster_capacity = out_buffer.len() / self.bytes_per_cluster;
            let clusters_to_read = clusters_available.min(cluster_capacity);

            if clusters_to_read == 0 {
                return Ok(0);
            }

            let disk_offset =
                (extent.lcn + self.cluster_index as i64) * self.bytes_per_cluster as i64;
            move_disk_position(self.disk_handle.raw(), disk_offset)?;

            let bytes_to_read = (clusters_to_read * self.bytes_per_cluster) as u32;
            let mut read_bytes =
                read_file_from_disk_pointer(self.disk_handle.raw(), out_buffer, bytes_to_read)?;

            if self.bytes_read + read_bytes as usize > self.file_size as usize {
                read_bytes = (self.file_size - self.bytes_read as u64) as u32;
            }

            self.bytes_read += read_bytes as usize;

            if clusters_to_read == clusters_available {
                self.extent_index += 1;
                self.cluster_index = 0;
            } else {
                self.cluster_index += clusters_to_read;
            }

            return Ok(read_bytes as usize);
        }

        Ok(0)
    }
}

fn file_op_error_with_io_code(
    path: &Path,
    operation: &'static str,
    error: std::io::Error,
) -> Error {
    let path_text = Cow::Owned(path.to_string_lossy().to_string());
    if let Some(code) = error.raw_os_error() {
        Error::FileOperation(FileOperationError::with_code(path_text, operation, code))
    } else {
        Error::FileOperation(FileOperationError::new(path_text, operation))
    }
}
