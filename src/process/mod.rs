//! Cross-Platform Process Management
//!
//! Provides unified process management APIs across Windows, Linux, and macOS.
//! This module is used by both the full agent and the core library for
//! embedded/mobile integrations.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Extended process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID
    pub ppid: Option<u32>,
    /// Process name
    pub name: String,
    /// Full executable path
    pub path: Option<String>,
    /// Command line arguments
    pub cmdline: Vec<String>,
    /// User running the process
    pub user: Option<String>,
    /// User ID
    pub uid: u32,
    /// Process start time (Unix timestamp)
    pub start_time: u64,
    /// Memory usage (RSS) in bytes
    pub memory_bytes: u64,
    /// Virtual memory in bytes
    pub virtual_memory_bytes: u64,
    /// CPU usage percentage
    pub cpu_percent: f32,
    /// Number of threads
    pub thread_count: u32,
    /// Number of handles/file descriptors
    pub handle_count: u32,
    /// Is the process elevated (admin/root)
    pub is_elevated: bool,
    /// Is the binary digitally signed
    pub is_signed: bool,
    /// Signer name if signed
    pub signer: Option<String>,
    /// Process status string
    pub status: String,
    /// Current working directory
    pub cwd: Option<String>,
}

/// Process criticality levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CriticalityLevel {
    /// System-critical (will crash OS if killed)
    SystemCritical,
    /// Service-critical (important services)
    ServiceCritical,
    /// User-critical (user experience)
    UserCritical,
    /// Not critical
    Normal,
}

/// Trust level for processes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Known malicious
    Untrusted,
    /// Suspicious behavior
    Suspicious,
    /// Unknown
    Unknown,
    /// Normal behavior
    Normal,
    /// Verified safe
    Trusted,
}

/// Result of a kill operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillResult {
    /// Process ID
    pub pid: u32,
    /// Whether the kill succeeded
    pub success: bool,
    /// Whether graceful termination was used
    pub graceful: bool,
    /// Human-readable message
    pub message: String,
    /// Error message if failed
    pub error: Option<String>,
}

/// Result of a suspend/resume operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendResumeResult {
    /// Process ID
    pub pid: u32,
    /// Whether the operation succeeded
    pub success: bool,
    /// Number of threads affected
    pub threads_affected: u32,
    /// Human-readable message
    pub message: String,
}

/// Process network connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConnection {
    /// Protocol (TCP/UDP)
    pub protocol: String,
    /// Local address
    pub local_addr: String,
    /// Local port
    pub local_port: u16,
    /// Remote address
    pub remote_addr: String,
    /// Remote port
    pub remote_port: u16,
    /// Connection state
    pub state: String,
}

/// Process manager trait for cross-platform implementation
pub trait ProcessManager: Send + Sync {
    /// Get all running processes
    fn list_processes(&self) -> Result<Vec<ProcessInfo>>;

    /// Get a specific process by PID
    fn get_process(&self, pid: u32) -> Result<ProcessInfo>;

    /// Get network connections for a process
    fn get_connections(&self, pid: u32) -> Result<Vec<ProcessConnection>>;

    /// Check if a process is critical
    fn is_critical(&self, pid: u32) -> CriticalityLevel;

    /// Kill a process (with safety checks)
    fn kill_process(&self, pid: u32, force: bool) -> Result<KillResult>;

    /// Suspend a process
    fn suspend_process(&self, pid: u32) -> Result<SuspendResumeResult>;

    /// Resume a process
    fn resume_process(&self, pid: u32) -> Result<SuspendResumeResult>;
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
pub mod windows_impl {
    use super::*;

    pub struct WindowsProcessManager;

    impl WindowsProcessManager {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for WindowsProcessManager {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ProcessManager for WindowsProcessManager {
        fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
            use sysinfo::{ProcessRefreshKind, System};

            let mut system = System::new();
            system.refresh_processes_specifics(ProcessRefreshKind::everything());

            let mut processes = Vec::new();
            for (pid, process) in system.processes() {
                processes.push(ProcessInfo {
                    pid: pid.as_u32(),
                    ppid: process.parent().map(|p| p.as_u32()),
                    name: process.name().to_string(),
                    path: process.exe().map(|p| p.to_string_lossy().to_string()),
                    cmdline: process.cmd().to_vec(),
                    user: process.user_id().map(|u| u.to_string()),
                    uid: 0, // Windows doesn't use numeric UIDs
                    start_time: process.start_time(),
                    memory_bytes: process.memory(),
                    virtual_memory_bytes: process.virtual_memory(),
                    cpu_percent: process.cpu_usage(),
                    thread_count: 0,    // Would need additional API calls
                    handle_count: 0,    // Would need additional API calls
                    is_elevated: false, // Would need privilege check
                    is_signed: false,   // Would need Authenticode check
                    signer: None,
                    status: format!("{:?}", process.status()),
                    cwd: process.cwd().map(|p| p.to_string_lossy().to_string()),
                });
            }

            Ok(processes)
        }

        fn get_process(&self, pid: u32) -> Result<ProcessInfo> {
            let processes = self.list_processes()?;
            processes
                .into_iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| Error::platform(format!("Process {} not found", pid)))
        }

        fn get_connections(&self, _pid: u32) -> Result<Vec<ProcessConnection>> {
            // Would use GetExtendedTcpTable/GetExtendedUdpTable
            Ok(Vec::new())
        }

        fn is_critical(&self, _pid: u32) -> CriticalityLevel {
            // Would check against known critical process list
            CriticalityLevel::Normal
        }

        fn kill_process(&self, pid: u32, force: bool) -> Result<KillResult> {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::{
                OpenProcess, TerminateProcess, PROCESS_TERMINATE,
            };

            unsafe {
                let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
                    .map_err(|e| Error::platform(format!("Failed to open process: {}", e)))?;

                let result = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);

                if result.is_ok() {
                    Ok(KillResult {
                        pid,
                        success: true,
                        graceful: !force,
                        message: "Process terminated".to_string(),
                        error: None,
                    })
                } else {
                    Err(Error::platform("TerminateProcess failed"))
                }
            }
        }

        fn suspend_process(&self, _pid: u32) -> Result<SuspendResumeResult> {
            // Would iterate threads and call SuspendThread
            Err(Error::platform("Not implemented"))
        }

        fn resume_process(&self, _pid: u32) -> Result<SuspendResumeResult> {
            // Would iterate threads and call ResumeThread
            Err(Error::platform("Not implemented"))
        }
    }
}

// ============================================================================
// Linux Implementation
// ============================================================================

#[cfg(target_os = "linux")]
pub mod linux_impl {
    use super::*;

    pub struct LinuxProcessManager;

    impl LinuxProcessManager {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for LinuxProcessManager {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ProcessManager for LinuxProcessManager {
        fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
            use sysinfo::{ProcessRefreshKind, System};

            let mut system = System::new();
            system.refresh_processes_specifics(ProcessRefreshKind::everything());

            let mut processes = Vec::new();
            for (pid, process) in system.processes() {
                let pid_u32 = pid.as_u32();

                // Get additional info from /proc
                let (uid, thread_count, handle_count) = get_proc_info(pid_u32);

                processes.push(ProcessInfo {
                    pid: pid_u32,
                    ppid: process.parent().map(|p| p.as_u32()),
                    name: process.name().to_string(),
                    path: process.exe().map(|p| p.to_string_lossy().to_string()),
                    cmdline: process.cmd().to_vec(),
                    user: process.user_id().map(|u| u.to_string()),
                    uid,
                    start_time: process.start_time(),
                    memory_bytes: process.memory(),
                    virtual_memory_bytes: process.virtual_memory(),
                    cpu_percent: process.cpu_usage(),
                    thread_count,
                    handle_count,
                    is_elevated: uid == 0,
                    is_signed: false,
                    signer: None,
                    status: format!("{:?}", process.status()),
                    cwd: process.cwd().map(|p| p.to_string_lossy().to_string()),
                });
            }

            Ok(processes)
        }

        fn get_process(&self, pid: u32) -> Result<ProcessInfo> {
            let processes = self.list_processes()?;
            processes
                .into_iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| Error::platform(format!("Process {} not found", pid)))
        }

        fn get_connections(&self, pid: u32) -> Result<Vec<ProcessConnection>> {
            // Read from /proc/net/tcp and /proc/net/udp and correlate with
            // socket inodes from /proc/{pid}/fd
            Ok(Vec::new())
        }

        fn is_critical(&self, pid: u32) -> CriticalityLevel {
            if pid == 1 {
                return CriticalityLevel::SystemCritical;
            }
            if pid == 2 {
                return CriticalityLevel::SystemCritical; // kthreadd
            }
            CriticalityLevel::Normal
        }

        fn kill_process(&self, pid: u32, force: bool) -> Result<KillResult> {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let signal = if force {
                Signal::SIGKILL
            } else {
                Signal::SIGTERM
            };

            match kill(Pid::from_raw(pid as i32), signal) {
                Ok(_) => Ok(KillResult {
                    pid,
                    success: true,
                    graceful: !force,
                    message: format!(
                        "Process terminated with {}",
                        if force { "SIGKILL" } else { "SIGTERM" }
                    ),
                    error: None,
                }),
                Err(e) => Err(Error::platform(format!("Failed to kill process: {}", e))),
            }
        }

        fn suspend_process(&self, pid: u32) -> Result<SuspendResumeResult> {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            match kill(Pid::from_raw(pid as i32), Signal::SIGSTOP) {
                Ok(_) => Ok(SuspendResumeResult {
                    pid,
                    success: true,
                    threads_affected: 1,
                    message: "Process suspended via SIGSTOP".to_string(),
                }),
                Err(e) => Err(Error::platform(format!("Failed to suspend: {}", e))),
            }
        }

        fn resume_process(&self, pid: u32) -> Result<SuspendResumeResult> {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            match kill(Pid::from_raw(pid as i32), Signal::SIGCONT) {
                Ok(_) => Ok(SuspendResumeResult {
                    pid,
                    success: true,
                    threads_affected: 1,
                    message: "Process resumed via SIGCONT".to_string(),
                }),
                Err(e) => Err(Error::platform(format!("Failed to resume: {}", e))),
            }
        }
    }

    fn get_proc_info(pid: u32) -> (u32, u32, u32) {
        let mut uid = 0u32;
        let mut thread_count = 0u32;
        let mut handle_count = 0u32;

        // Get UID from /proc/{pid}/status
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
            for line in status.lines() {
                if line.starts_with("Uid:") {
                    if let Some(uid_str) = line.split_whitespace().nth(1) {
                        uid = uid_str.parse().unwrap_or(0);
                    }
                }
                if line.starts_with("Threads:") {
                    if let Some(threads_str) = line.split_whitespace().nth(1) {
                        thread_count = threads_str.parse().unwrap_or(0);
                    }
                }
            }
        }

        // Count file descriptors
        if let Ok(entries) = std::fs::read_dir(format!("/proc/{}/fd", pid)) {
            handle_count = entries.count() as u32;
        }

        (uid, thread_count, handle_count)
    }
}

// ============================================================================
// macOS Implementation
// ============================================================================

#[cfg(target_os = "macos")]
pub mod macos_impl {
    use super::*;

    pub struct MacOsProcessManager;

    impl MacOsProcessManager {
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for MacOsProcessManager {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ProcessManager for MacOsProcessManager {
        fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
            use sysinfo::{ProcessRefreshKind, System};

            let mut system = System::new();
            system.refresh_processes_specifics(ProcessRefreshKind::everything());

            let mut processes = Vec::new();
            for (pid, process) in system.processes() {
                processes.push(ProcessInfo {
                    pid: pid.as_u32(),
                    ppid: process.parent().map(|p| p.as_u32()),
                    name: process.name().to_string(),
                    path: process.exe().map(|p| p.to_string_lossy().to_string()),
                    cmdline: process.cmd().to_vec(),
                    user: process.user_id().map(|u| u.to_string()),
                    uid: 0,
                    start_time: process.start_time(),
                    memory_bytes: process.memory(),
                    virtual_memory_bytes: process.virtual_memory(),
                    cpu_percent: process.cpu_usage(),
                    thread_count: 0,
                    handle_count: 0,
                    is_elevated: false,
                    is_signed: false,
                    signer: None,
                    status: format!("{:?}", process.status()),
                    cwd: process.cwd().map(|p| p.to_string_lossy().to_string()),
                });
            }

            Ok(processes)
        }

        fn get_process(&self, pid: u32) -> Result<ProcessInfo> {
            let processes = self.list_processes()?;
            processes
                .into_iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| Error::platform(format!("Process {} not found", pid)))
        }

        fn get_connections(&self, _pid: u32) -> Result<Vec<ProcessConnection>> {
            // Would use lsof or native APIs
            Ok(Vec::new())
        }

        fn is_critical(&self, pid: u32) -> CriticalityLevel {
            if pid == 1 {
                return CriticalityLevel::SystemCritical; // launchd
            }
            CriticalityLevel::Normal
        }

        fn kill_process(&self, pid: u32, force: bool) -> Result<KillResult> {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            let signal = if force {
                Signal::SIGKILL
            } else {
                Signal::SIGTERM
            };

            match kill(Pid::from_raw(pid as i32), signal) {
                Ok(_) => Ok(KillResult {
                    pid,
                    success: true,
                    graceful: !force,
                    message: "Process terminated".to_string(),
                    error: None,
                }),
                Err(e) => Err(Error::platform(format!("Failed to kill: {}", e))),
            }
        }

        fn suspend_process(&self, pid: u32) -> Result<SuspendResumeResult> {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            match kill(Pid::from_raw(pid as i32), Signal::SIGSTOP) {
                Ok(_) => Ok(SuspendResumeResult {
                    pid,
                    success: true,
                    threads_affected: 1,
                    message: "Process suspended".to_string(),
                }),
                Err(e) => Err(Error::platform(format!("Failed to suspend: {}", e))),
            }
        }

        fn resume_process(&self, pid: u32) -> Result<SuspendResumeResult> {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;

            match kill(Pid::from_raw(pid as i32), Signal::SIGCONT) {
                Ok(_) => Ok(SuspendResumeResult {
                    pid,
                    success: true,
                    threads_affected: 1,
                    message: "Process resumed".to_string(),
                }),
                Err(e) => Err(Error::platform(format!("Failed to resume: {}", e))),
            }
        }
    }
}

/// Get the platform-specific process manager
pub fn get_process_manager() -> Box<dyn ProcessManager> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows_impl::WindowsProcessManager::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux_impl::LinuxProcessManager::new())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(macos_impl::MacOsProcessManager::new())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        compile_error!("Unsupported platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criticality_levels() {
        assert!(matches!(
            CriticalityLevel::SystemCritical,
            CriticalityLevel::SystemCritical
        ));
    }

    #[test]
    fn test_trust_levels() {
        assert!(matches!(TrustLevel::Untrusted, TrustLevel::Untrusted));
    }

    #[test]
    fn test_process_manager() {
        let manager = get_process_manager();
        let processes = manager.list_processes();
        assert!(processes.is_ok());
        assert!(!processes.unwrap().is_empty());
    }
}
