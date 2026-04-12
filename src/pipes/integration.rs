use super::types::PipeClientEndpoint;

/// Standard I/O redirection endpoints for child process wiring.
#[derive(Debug, Default)]
pub struct ChildPipeEndpoints {
    /// Child process stdin endpoint.
    pub stdin: Option<PipeClientEndpoint>,
    /// Child process stdout endpoint.
    pub stdout: Option<PipeClientEndpoint>,
    /// Child process stderr endpoint.
    pub stderr: Option<PipeClientEndpoint>,
}

/// Pipe-backed stdio endpoint selection.
#[derive(Debug)]
pub enum PipeStdio {
    /// Inherit current process stdio endpoint.
    Inherit,
    /// Disable this stdio endpoint.
    Null,
    /// Use an explicit client endpoint.
    Endpoint(PipeClientEndpoint),
}
