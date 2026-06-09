//! Linux platform implementation

use super::{FileInfo, NetworkConnection, PlatformApi, ProcessInfo};
use crate::error::{Error, Result};

/// Linux platform API
pub struct LinuxApi;

impl LinuxApi {
    /// Create a new Linux API instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxApi {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformApi for LinuxApi {
    fn get_processes(&self) -> Result<Vec<ProcessInfo>> {
        // In production, this would read /proc
        Ok(Vec::new())
    }

    fn get_process(&self, pid: u32) -> Result<ProcessInfo> {
        // Read /proc/<pid>/status, cmdline, etc.
        Err(Error::platform(format!("Process {} not found", pid)))
    }

    fn get_network_connections(&self) -> Result<Vec<NetworkConnection>> {
        // Read /proc/net/tcp, /proc/net/udp
        Ok(Vec::new())
    }

    fn get_file_info(&self, path: &str) -> Result<FileInfo> {
        let metadata = std::fs::metadata(path)?;

        Ok(FileInfo {
            path: path.to_string(),
            size: metadata.len(),
            created: 0, // Not available on Linux
            modified: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            accessed: metadata
                .accessed()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
            is_signed: false,
            signer: None,
            sha256: None,
        })
    }

    fn kill_process(&self, pid: u32) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                if libc::kill(pid as i32, libc::SIGKILL) == 0 {
                    Ok(())
                } else {
                    Err(Error::platform(format!("Failed to kill process {}", pid)))
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::platform("Not on Linux"))
        }
    }

    fn suspend_process(&self, pid: u32) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                if libc::kill(pid as i32, libc::SIGSTOP) == 0 {
                    Ok(())
                } else {
                    Err(Error::platform(format!(
                        "Failed to suspend process {}",
                        pid
                    )))
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::platform("Not on Linux"))
        }
    }

    fn resume_process(&self, pid: u32) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                if libc::kill(pid as i32, libc::SIGCONT) == 0 {
                    Ok(())
                } else {
                    Err(Error::platform(format!("Failed to resume process {}", pid)))
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::platform("Not on Linux"))
        }
    }

    fn isolate_network(&self) -> Result<()> {
        Err(Error::platform("Network isolation not implemented"))
    }

    fn restore_network(&self) -> Result<()> {
        Err(Error::platform("Network restore not implemented"))
    }

    fn is_elevated(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn get_uid(&self) -> u32 {
        #[cfg(target_os = "linux")]
        {
            unsafe { libc::getuid() }
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }

    fn get_uptime(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
                if let Some(uptime) = uptime_str.split_whitespace().next() {
                    return uptime.parse::<f64>().unwrap_or(0.0) as u64;
                }
            }
        }
        0
    }
}

/// Get resource usage (CPU, memory) for current process
#[cfg(target_os = "linux")]
pub fn get_resource_usage() -> (f32, u64) {
    let pid = std::process::id();

    // Read memory from /proc/self/status
    let memory = if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(kb) = line.split_whitespace().nth(1) {
                    if let Ok(kb_val) = kb.parse::<u64>() {
                        return (0.0, kb_val * 1024); // Convert KB to bytes
                    }
                }
            }
        }
        0
    } else {
        0
    };

    // CPU usage would require tracking over time
    (0.0, memory)
}

#[cfg(not(target_os = "linux"))]
pub fn get_resource_usage() -> (f32, u64) {
    (0.0, 0)
}
