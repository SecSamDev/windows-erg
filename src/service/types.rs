use windows::Win32::System::Services::{
    SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE,
    SERVICE_ALL_ACCESS, SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_STOP, SERVICE_PAUSED, SERVICE_PAUSE_CONTINUE,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED,
};

/// Service state as reported by the Windows Service Control Manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is stopped.
    Stopped,
    /// Service is starting.
    StartPending,
    /// Service is stopping.
    StopPending,
    /// Service is running.
    Running,
    /// Service is paused.
    Paused,
    /// Unknown/unsupported state value.
    Unknown(u32),
}

impl ServiceState {
    pub(crate) fn from_windows(state: SERVICE_STATUS_CURRENT_STATE) -> Self {
        match state.0 {
            x if x == SERVICE_STOPPED.0 => ServiceState::Stopped,
            x if x == SERVICE_START_PENDING.0 => ServiceState::StartPending,
            x if x == SERVICE_STOP_PENDING.0 => ServiceState::StopPending,
            x if x == SERVICE_RUNNING.0 => ServiceState::Running,
            x if x == SERVICE_PAUSED.0 => ServiceState::Paused,
            other => ServiceState::Unknown(other),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ServiceState::Stopped => "stopped",
            ServiceState::StartPending => "start_pending",
            ServiceState::StopPending => "stop_pending",
            ServiceState::Running => "running",
            ServiceState::Paused => "paused",
            ServiceState::Unknown(_) => "unknown",
        }
    }
}

/// Access rights for opening a Service Control Manager handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceManagerAccess {
    /// Connect to the SCM database.
    Connect,
    /// Enumerate installed services.
    EnumerateService,
    /// Full manager access rights.
    AllAccess,
    /// Custom SCM rights.
    Custom(u32),
}

impl ServiceManagerAccess {
    pub(crate) fn to_windows(self) -> u32 {
        match self {
            ServiceManagerAccess::Connect => SC_MANAGER_CONNECT,
            ServiceManagerAccess::EnumerateService => SC_MANAGER_ENUMERATE_SERVICE,
            ServiceManagerAccess::AllAccess => SC_MANAGER_ALL_ACCESS,
            ServiceManagerAccess::Custom(rights) => rights,
        }
    }
}

/// Access rights for opening an individual Windows service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAccess {
    /// Query runtime status.
    QueryStatus,
    /// Start the service.
    Start,
    /// Stop the service.
    Stop,
    /// Pause/continue the service.
    PauseContinue,
    /// Full service access rights.
    AllAccess,
    /// Custom service access rights.
    Custom(u32),
}

impl ServiceAccess {
    pub(crate) fn to_windows(self) -> u32 {
        match self {
            ServiceAccess::QueryStatus => SERVICE_QUERY_STATUS,
            ServiceAccess::Start => SERVICE_START,
            ServiceAccess::Stop => SERVICE_STOP,
            ServiceAccess::PauseContinue => SERVICE_PAUSE_CONTINUE,
            ServiceAccess::AllAccess => SERVICE_ALL_ACCESS,
            ServiceAccess::Custom(rights) => rights,
        }
    }
}

/// Service control codes that can be sent to a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceControl {
    /// Request service stop.
    Stop,
    /// Request service pause.
    Pause,
    /// Request service continue.
    Continue,
    /// Request service status refresh.
    Interrogate,
}

impl ServiceControl {
    pub(crate) fn to_windows(self) -> u32 {
        match self {
            ServiceControl::Stop => SERVICE_CONTROL_STOP,
            ServiceControl::Pause => SERVICE_CONTROL_PAUSE,
            ServiceControl::Continue => SERVICE_CONTROL_CONTINUE,
            ServiceControl::Interrogate => SERVICE_CONTROL_INTERROGATE,
        }
    }

    pub(crate) fn operation_name(self) -> &'static str {
        match self {
            ServiceControl::Stop => "stop",
            ServiceControl::Pause => "pause",
            ServiceControl::Continue => "continue",
            ServiceControl::Interrogate => "interrogate",
        }
    }
}
