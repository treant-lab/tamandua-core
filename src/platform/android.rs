//! Android platform implementation

use super::{FileInfo, NetworkConnection, PlatformApi, ProcessInfo};
use crate::error::{Error, Result};

/// Android platform API
pub struct AndroidApi;

impl AndroidApi {
    /// Create a new Android API instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for AndroidApi {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformApi for AndroidApi {
    fn get_processes(&self) -> Result<Vec<ProcessInfo>> {
        // Android process access is limited
        Ok(Vec::new())
    }

    fn get_process(&self, _pid: u32) -> Result<ProcessInfo> {
        Err(Error::platform("Process access limited on Android"))
    }

    fn get_network_connections(&self) -> Result<Vec<NetworkConnection>> {
        Ok(Vec::new())
    }

    fn get_file_info(&self, _path: &str) -> Result<FileInfo> {
        Err(Error::platform("Limited file access on Android"))
    }

    fn kill_process(&self, _pid: u32) -> Result<()> {
        Err(Error::platform("Cannot kill processes on Android"))
    }

    fn suspend_process(&self, _pid: u32) -> Result<()> {
        Err(Error::platform("Cannot suspend processes on Android"))
    }

    fn resume_process(&self, _pid: u32) -> Result<()> {
        Err(Error::platform("Cannot resume processes on Android"))
    }

    fn isolate_network(&self) -> Result<()> {
        Err(Error::platform(
            "Network isolation not available on Android",
        ))
    }

    fn restore_network(&self) -> Result<()> {
        Err(Error::platform("Network restore not available on Android"))
    }

    fn is_elevated(&self) -> bool {
        false // Android apps run sandboxed
    }

    fn get_uid(&self) -> u32 {
        0
    }

    fn get_uptime(&self) -> u64 {
        0
    }
}
