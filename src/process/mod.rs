//! Process operations and management.
//!
//! This module provides ergonomic access to Windows process APIs including:
//! - Opening and querying processes
//! - Reading PEB (Process Environment Block) data
//! - Enumerating threads and modules
//! - Process tree operations
//! - Memory information
//!
//! # Examples
//!
//! ## Opening and querying a process
//!
//! ```no_run
//! use windows_erg::process::{Process, ProcessId};
//!
//! # fn main() -> windows_erg::Result<()> {
//! let process = Process::open(ProcessId::new(1234))?;
//! println!("Process name: {}", process.name()?);
//! println!("Process path: {}", process.path()?.display());
//! # Ok(())
//! # }
//! ```
//!
//! ## Reading PEB data
//!
//! ```no_run
//! use windows_erg::process::Process;
//!
//! # fn main() -> windows_erg::Result<()> {
//! let process = Process::current();
//! println!("Command line: {}", process.command_line()?);
//!
//! let env = process.environment()?;
//! for (key, value) in env {
//!     println!("{} = {}", key, value);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Listing all processes
//!
//! ```no_run
//! use windows_erg::process::Process;
//!
//! # fn main() -> windows_erg::Result<()> {
//! let processes = Process::list()?;
//! for proc in processes {
//!     println!("{}: {}", proc.pid, proc.name);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Using buffer reuse for performance
//!
//! ```no_run
//! use windows_erg::process::Process;
//!
//! # fn main() -> windows_erg::Result<()> {
//! let processes = Process::list()?;
//! let mut buffer = Vec::with_capacity(8192);
//!
//! for proc_info in processes {
//!     if let Ok(process) = Process::open(proc_info.pid) {
//!         if let Ok(cmd) = process.command_line_with_buffer(&mut buffer) {
//!             println!("{}: {}", proc_info.name, cmd);
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Process tree operations
//!
//! ```no_run
//! use windows_erg::process::{Process, ProcessId};
//!
//! # fn main() -> windows_erg::Result<()> {
//! // Kill a process and all its children
//! let process = Process::open(ProcessId::new(1234))?;
//! process.kill_tree()?;
//!
//! // Or kill entire tree from root ancestor
//! Process::kill_tree_from_root(ProcessId::new(1234))?;
//! # Ok(())
//! # }
//! ```

mod list;
mod memory;
mod modules;
mod peb;
mod processes;
mod threads;
mod tree;
mod types;

// Re-export public types
pub use processes::Process;
pub use types::{
    MemoryInfo, ModuleInfo, ProcessAccess, ProcessId, ProcessInfo, ProcessParameters, ThreadId,
    ThreadInfo,
};
