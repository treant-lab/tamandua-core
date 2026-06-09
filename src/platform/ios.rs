//! iOS platform implementation

use super::{FileInfo, NetworkConnection, PlatformApi, ProcessInfo};
use crate::error::{Error, Result};

/// iOS platform API
pub struct IosApi;

impl IosApi {
    /// Create a new iOS API instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosApi {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformApi for IosApi {
    fn get_processes(&self) -> Result<Vec<ProcessInfo>> {
        // iOS is sandboxed - limited process access
        Ok(Vec::new())
    }

    fn get_process(&self, _pid: u32) -> Result<ProcessInfo> {
        Err(Error::platform("Process access not available on iOS"))
    }

    fn get_network_connections(&self) -> Result<Vec<NetworkConnection>> {
        Ok(Vec::new())
    }

    fn get_file_info(&self, _path: &str) -> Result<FileInfo> {
        Err(Error::platform("Limited file access on iOS"))
    }

    fn kill_process(&self, _pid: u32) -> Result<()> {
        Err(Error::platform("Cannot kill processes on iOS"))
    }

    fn suspend_process(&self, _pid: u32) -> Result<()> {
        Err(Error::platform("Cannot suspend processes on iOS"))
    }

    fn resume_process(&self, _pid: u32) -> Result<()> {
        Err(Error::platform("Cannot resume processes on iOS"))
    }

    fn isolate_network(&self) -> Result<()> {
        Err(Error::platform("Network isolation not available on iOS"))
    }

    fn restore_network(&self) -> Result<()> {
        Err(Error::platform("Network restore not available on iOS"))
    }

    fn is_elevated(&self) -> bool {
        false // iOS apps always run sandboxed
    }

    fn get_uid(&self) -> u32 {
        0
    }

    fn get_uptime(&self) -> u64 {
        0
    }
}
