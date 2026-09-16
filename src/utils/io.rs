use std::io;

use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_PIPE_NOT_CONNECTED};

/// `HRESULT_FROM_WIN32` facility bits (`0x8007xxxx`).
const WIN32_HRESULT_MASK: u32 = 0xFFFF_0000;
const WIN32_HRESULT_PREFIX: u32 = 0x8007_0000;

/// Convert a `windows` error into an [`io::Error`].
///
/// Win32 failures arrive wrapped as `HRESULT_FROM_WIN32(code)`. Passing the
/// HRESULT straight to [`io::Error::from_raw_os_error`] yields an unknown OS
/// error, so [`io::ErrorKind`] (`BrokenPipe`, `TimedOut`, ...) is lost; this
/// unwraps the Win32 code first.
pub fn win_to_io_error(err: windows::core::Error) -> io::Error {
    match win32_code(&err) {
        Some(code) => io::Error::from_raw_os_error(code as i32),
        None => io::Error::other(err),
    }
}

/// Win32 error code carried by `err`, if it wraps one.
pub fn win32_code(err: &windows::core::Error) -> Option<u32> {
    let hresult = err.code().0 as u32;
    (hresult & WIN32_HRESULT_MASK == WIN32_HRESULT_PREFIX).then_some(hresult & 0xFFFF)
}

/// Outcome of a pipe read that failed at the Win32 level.
pub(crate) enum PipeReadError {
    /// The peer closed its end: report end of stream.
    EndOfStream,
    /// Message-mode read filled the buffer; the rest of the message follows.
    MoreData,
    /// Any other failure.
    Failed(io::Error),
}

/// Classify a failed `ReadFile` on a pipe the way `std` does for its own pipes.
pub(crate) fn classify_pipe_read_error(err: windows::core::Error) -> PipeReadError {
    match win32_code(&err) {
        Some(code) if code == ERROR_BROKEN_PIPE.0 || code == ERROR_PIPE_NOT_CONNECTED.0 => {
            PipeReadError::EndOfStream
        }
        Some(code) if code == ERROR_MORE_DATA.0 => PipeReadError::MoreData,
        _ => PipeReadError::Failed(win_to_io_error(err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{E_POINTER, ERROR_ACCESS_DENIED};

    #[test]
    fn win32_hresult_maps_to_io_kind() {
        let err = windows::core::Error::from(ERROR_BROKEN_PIPE.to_hresult());
        assert_eq!(win_to_io_error(err).kind(), io::ErrorKind::BrokenPipe);

        let err = windows::core::Error::from(ERROR_ACCESS_DENIED.to_hresult());
        let io_err = win_to_io_error(err);
        assert_eq!(io_err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(io_err.raw_os_error(), Some(ERROR_ACCESS_DENIED.0 as i32));
    }

    #[test]
    fn non_win32_hresult_is_preserved() {
        let err = windows::core::Error::from(E_POINTER);
        let io_err = win_to_io_error(err);
        assert_eq!(io_err.raw_os_error(), None);
        assert_eq!(win32_code(&windows::core::Error::from(E_POINTER)), None);
    }

    #[test]
    fn pipe_read_errors_are_classified() {
        let classify = |code: windows::Win32::Foundation::WIN32_ERROR| {
            classify_pipe_read_error(windows::core::Error::from(code.to_hresult()))
        };
        assert!(matches!(
            classify(ERROR_BROKEN_PIPE),
            PipeReadError::EndOfStream
        ));
        assert!(matches!(
            classify(ERROR_PIPE_NOT_CONNECTED),
            PipeReadError::EndOfStream
        ));
        assert!(matches!(classify(ERROR_MORE_DATA), PipeReadError::MoreData));
        assert!(matches!(
            classify(ERROR_ACCESS_DENIED),
            PipeReadError::Failed(_)
        ));
    }
}
