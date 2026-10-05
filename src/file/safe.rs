//! File creation and deletion that never follow a reparse point.
//!
//! A privileged process (a SYSTEM service) writing into a directory an
//! unprivileged user controls must not let a junction or symbolic link
//! planted on the path redirect the write somewhere else — the classic
//! "privileged file operation" redirection. These helpers walk the path one
//! component at a time from the volume root, opening each directory
//! *relative to the previous handle* with `FILE_OPEN_REPARSE_POINT` and
//! refusing any that is a reparse point, then create or delete the file
//! relative to the last verified handle. Each directory is held open without
//! `FILE_SHARE_DELETE`, so it cannot be renamed or replaced mid-walk.

use std::ffi::c_void;
use std::path::{Component, Path, Prefix};

use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
    FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    NTCREATEFILE_CREATE_DISPOSITION, NTCREATEFILE_CREATE_OPTIONS, NtCreateFile,
};
use windows::Win32::Foundation::{GENERIC_WRITE, HANDLE, RtlNtStatusToDosError, UNICODE_STRING};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FileDispositionInfo,
    GetFileInformationByHandle, SYNCHRONIZE, SetFileInformationByHandle, WriteFile,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;
use windows::core::PWSTR;

use crate::Result;
use crate::error::{Error, FileOperationError, InvalidParameterError};
use crate::utils::OwnedHandle;

/// Create `dir\name` with `content`, failing if it already exists, if any
/// directory on the way (including `dir`) is a reparse point, or if `name`
/// is not a plain file name. `hidden` sets `FILE_ATTRIBUTE_HIDDEN`.
///
/// `dir` must be an absolute drive path (`C:\...`).
pub fn create_new_no_follow(dir: &Path, name: &str, content: &[u8], hidden: bool) -> Result<()> {
    validate_file_name(name)?;
    let parent = open_directory_chain(dir)?;
    let attributes = if hidden {
        FILE_ATTRIBUTE_HIDDEN
    } else {
        FILE_ATTRIBUTE_NORMAL
    };
    let file = nt_open(
        Some(&parent),
        name,
        FILE_ACCESS_RIGHTS(GENERIC_WRITE.0 | SYNCHRONIZE.0 | FILE_READ_ATTRIBUTES.0),
        attributes,
        FILE_SHARE_MODE(0),
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(|code| file_error(dir, "create file", code))?;

    let mut remaining = content;
    while !remaining.is_empty() {
        let mut written = 0u32;
        // SAFETY: `file` is a valid, synchronous handle opened for writing
        // above and alive for this call; `remaining` is a live slice and
        // `written` a live out-parameter.
        unsafe { WriteFile(file.raw(), Some(remaining), Some(&mut written), None) }
            .map_err(|e| file_error(dir, "write file", e.code().0))?;
        if written == 0 {
            return Err(file_error(dir, "write file", 0));
        }
        remaining = &remaining[written as usize..];
    }
    Ok(())
}

/// Delete the file at `path`, failing if it or any directory on the way is
/// a reparse point. `path` must be an absolute drive path.
pub fn delete_no_follow(path: &Path) -> Result<()> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Err(invalid("path", "path must name a file inside a directory"));
    };
    validate_file_name(name)?;
    let parent = open_directory_chain(dir)?;
    let file = nt_open(
        Some(&parent),
        name,
        FILE_ACCESS_RIGHTS(DELETE.0 | SYNCHRONIZE.0 | FILE_READ_ATTRIBUTES.0),
        FILE_FLAGS_AND_ATTRIBUTES(0),
        FILE_SHARE_MODE(0),
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(|code| file_error(path, "open file for delete", code))?;
    refuse_reparse_point(&file, path)?;

    let info = FILE_DISPOSITION_INFO {
        DeleteFile: true.into(),
    };
    // SAFETY: `file` was opened with DELETE access and is alive for this
    // call; `info` is a correctly sized FILE_DISPOSITION_INFO on the stack.
    unsafe {
        SetFileInformationByHandle(
            file.raw(),
            FileDispositionInfo,
            std::ptr::from_ref(&info).cast::<c_void>(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|e| file_error(path, "delete file", e.code().0))
}

/// Open every directory from the volume root down to `dir`, each relative to
/// its parent's handle, refusing any reparse point. Returns `dir`'s handle.
fn open_directory_chain(dir: &Path) -> Result<OwnedHandle> {
    let mut components = dir.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) => letter as char,
            _ => return Err(invalid("dir", "only drive-letter paths are supported")),
        },
        _ => return Err(invalid("dir", "path must be absolute (C:\\...)")),
    };
    if components.next() != Some(Component::RootDir) {
        return Err(invalid("dir", "path must be absolute (C:\\...)"));
    }

    let directory_access =
        FILE_ACCESS_RIGHTS(FILE_LIST_DIRECTORY.0 | FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0)
            | SYNCHRONIZE;
    let directory_options = FILE_DIRECTORY_FILE
        | FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_FOR_BACKUP_INTENT
        | FILE_OPEN_REPARSE_POINT;
    // Readers and writers may share; nobody may delete or rename a
    // directory while it is part of the verified chain.
    let share = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);

    let root_name = format!(r"\??\{drive}:\");
    let mut current = nt_open(
        None,
        &root_name,
        directory_access,
        FILE_FLAGS_AND_ATTRIBUTES(0),
        share,
        FILE_OPEN,
        directory_options,
    )
    .map_err(|code| file_error(dir, "open volume root", code))?;

    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid("dir", "`.` and `..` are not allowed"));
        };
        let name = name
            .to_str()
            .ok_or_else(|| invalid("dir", "path is not valid Unicode"))?;
        let next = nt_open(
            Some(&current),
            name,
            directory_access,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            share,
            FILE_OPEN,
            directory_options,
        )
        .map_err(|code| file_error(dir, "open directory", code))?;
        refuse_reparse_point(&next, dir)?;
        current = next;
    }
    Ok(current)
}

fn refuse_reparse_point(handle: &OwnedHandle, path: &Path) -> Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is a valid open handle with FILE_READ_ATTRIBUTES;
    // `info` is a live out-parameter of the right type.
    unsafe { GetFileInformationByHandle(handle.raw(), &mut info) }
        .map_err(|e| file_error(path, "query attributes", e.code().0))?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        return Err(Error::FileOperation(FileOperationError::new(
            path.display().to_string(),
            "refuse reparse point (junction or symbolic link) on the path",
        )));
    }
    Ok(())
}

/// `NtCreateFile` relative to `root` (or an absolute NT path without one).
/// Returns the Win32 error code on failure.
fn nt_open(
    root: Option<&OwnedHandle>,
    name: &str,
    access: FILE_ACCESS_RIGHTS,
    attributes: FILE_FLAGS_AND_ATTRIBUTES,
    share: FILE_SHARE_MODE,
    disposition: NTCREATEFILE_CREATE_DISPOSITION,
    options: NTCREATEFILE_CREATE_OPTIONS,
) -> std::result::Result<OwnedHandle, i32> {
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    let byte_len = u16::try_from(wide.len() * 2).map_err(|_| 206)?; // ERROR_FILENAME_EXCED_RANGE
    let mut unicode_name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: PWSTR(wide.as_mut_ptr()),
    };
    let object_attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root.map_or(HANDLE(std::ptr::null_mut()), OwnedHandle::raw),
        ObjectName: &mut unicode_name,
        // Case-insensitive like Win32. No OBJ_OPENLINK: that only affects
        // object-manager symbolic links; file system reparse points are
        // handled by FILE_OPEN_REPARSE_POINT in `options`.
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut handle = HANDLE(std::ptr::null_mut());
    // SAFETY: every pointer refers to a live local: `unicode_name` borrows
    // `wide`, which outlives the call, and `root` (when given) is a valid
    // directory handle owned by the caller for the duration of the call.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &object_attributes,
            &mut io_status,
            None,
            attributes,
            share,
            disposition,
            options,
            None,
            0,
        )
    };
    if status.is_err() {
        // SAFETY: a pure status-code translation with no pointers.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(if code == 0 { status.0 } else { code as i32 });
    }
    Ok(OwnedHandle::new(handle))
}

/// A single path component: no separators, no stream syntax, not `.`/`..`.
fn validate_file_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['\\', '/', ':'])
        || name.contains('\0')
    {
        return Err(invalid("name", "must be a plain file name"));
    }
    Ok(())
}

fn invalid(parameter: &'static str, message: &'static str) -> Error {
    Error::InvalidParameter(InvalidParameterError::new(parameter, message))
}

fn file_error(path: &Path, operation: &'static str, code: i32) -> Error {
    Error::FileOperation(FileOperationError::with_code(
        path.display().to_string(),
        operation,
        code,
    ))
}

#[cfg(test)]
mod tests {
    use std::os::windows::fs::MetadataExt;
    use std::path::PathBuf;
    use std::process::Command;

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("werg-safe-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn junction(link: &Path, target: &Path) {
        let status = Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap()
            .status;
        assert!(status.success(), "mklink /J failed");
    }

    #[test]
    fn creates_a_new_file_with_content_and_the_hidden_attribute() {
        let dir = TempDir::new("create");
        create_new_no_follow(&dir.0, "decoy.xlsx", b"bait", true).unwrap();
        let path = dir.0.join("decoy.xlsx");
        assert_eq!(std::fs::read(&path).unwrap(), b"bait");
        let attributes = std::fs::metadata(&path).unwrap().file_attributes();
        assert_ne!(attributes & FILE_ATTRIBUTE_HIDDEN.0, 0);
    }

    #[test]
    fn never_overwrites_an_existing_file() {
        let dir = TempDir::new("exists");
        std::fs::write(dir.0.join("a.txt"), b"original").unwrap();
        assert!(create_new_no_follow(&dir.0, "a.txt", b"new", false).is_err());
        assert_eq!(std::fs::read(dir.0.join("a.txt")).unwrap(), b"original");
    }

    #[test]
    fn rejects_names_that_are_not_a_single_component() {
        let dir = TempDir::new("names");
        for name in ["", ".", "..", r"sub\a.txt", "a.txt:stream", "../a.txt"] {
            assert!(
                create_new_no_follow(&dir.0, name, b"x", false).is_err(),
                "{name:?}"
            );
        }
        assert!(create_new_no_follow(Path::new(r"relative\dir"), "a", b"x", false).is_err());
    }

    #[test]
    fn refuses_a_junction_anywhere_on_the_path() {
        let dir = TempDir::new("junction");
        let target = dir.0.join("target");
        std::fs::create_dir_all(target.join("sub")).unwrap();
        let link = dir.0.join("link");
        junction(&link, &target);

        assert!(create_new_no_follow(&link, "a.txt", b"x", false).is_err());
        assert!(create_new_no_follow(&link.join("sub"), "a.txt", b"x", false).is_err());
        assert!(!target.join("a.txt").exists());
        assert!(!target.join("sub").join("a.txt").exists());
    }

    #[test]
    fn deletes_a_file_but_not_through_a_junction() {
        let dir = TempDir::new("delete");
        let target = dir.0.join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("a.txt"), b"x").unwrap();
        let link = dir.0.join("link");
        junction(&link, &target);

        assert!(delete_no_follow(&link.join("a.txt")).is_err());
        assert!(target.join("a.txt").exists());

        delete_no_follow(&target.join("a.txt")).unwrap();
        assert!(!target.join("a.txt").exists());
    }
}
