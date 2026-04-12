use crate::error::{
    Error, PipeConnectError, PipeCreateError, PipeError, PipeIoError, PipeTimeoutError,
};

use super::types::{PipeName, to_cow_pipe_name};

const ERROR_BROKEN_PIPE_CODE: i32 = 109;
const ERROR_PIPE_CONNECTED_CODE: i32 = 535;
const ERROR_PIPE_BUSY_CODE: i32 = 231;
const ERROR_SEM_TIMEOUT_CODE: i32 = 121;

pub(crate) fn map_pipe_windows_error(
    operation: &'static str,
    pipe_name: Option<&PipeName>,
    error_code: i32,
) -> Error {
    match error_code {
        ERROR_SEM_TIMEOUT_CODE => Error::Pipe(PipeError::Timeout(PipeTimeoutError::new(
            to_cow_pipe_name(pipe_name),
            operation,
        ))),
        ERROR_PIPE_BUSY_CODE => Error::Pipe(PipeError::Connect(
            PipeConnectError::new(to_cow_pipe_name(pipe_name))
                .with_context("pipe is busy")
                .with_code(error_code),
        )),
        ERROR_PIPE_CONNECTED_CODE => Error::Pipe(PipeError::Connect(
            PipeConnectError::new(to_cow_pipe_name(pipe_name))
                .with_context("pipe is already connected")
                .with_code(error_code),
        )),
        ERROR_BROKEN_PIPE_CODE => Error::Pipe(PipeError::Io(PipeIoError::with_code(
            to_cow_pipe_name(pipe_name),
            operation,
            error_code,
        ))),
        _ => {
            if operation == "create" {
                Error::Pipe(PipeError::Create(PipeCreateError::with_code(
                    to_cow_pipe_name(pipe_name),
                    operation,
                    error_code,
                )))
            } else if operation == "connect" {
                Error::Pipe(PipeError::Connect(
                    PipeConnectError::new(to_cow_pipe_name(pipe_name)).with_code(error_code),
                ))
            } else {
                Error::Pipe(PipeError::Io(PipeIoError::with_code(
                    to_cow_pipe_name(pipe_name),
                    operation,
                    error_code,
                )))
            }
        }
    }
}
