//! Platform-specific abstractions
//!
//! This module provides a unified API across all supported platforms
//! (Windows, Linux, macOS, iOS, Android).

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(target_os = "android")]
pub mod android;

/// Process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,

    /// Parent process ID
    pub ppid: u32,

    /// Process name
    pub name: String,

    /// Command line
    pub cmdline: String,

    /// Executable path
    pub exe_path: String,

    /// Current working directory
    pub cwd: Option<String>,

    /// User ID
    pub uid: u32,

    /// Is process elevated/running as admin
    pub is_elevated: bool,

    /// Start time (Unix timestamp)
    pub start_time: u64,

    /// CPU usage percentage
    pub cpu_usage: f32,

    /// Memory usage in bytes
    pub memory_usage: u64,

    /// Number of threads
    pub num_threads: u32,
}

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
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

    /// Connection state (ESTABLISHED, LISTEN, etc.)
    pub state: String,

    /// Process ID owning this connection
    pub pid: u32,
}

/// File information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    /// File path
    pub path: String,

    /// File size in bytes
    pub size: u64,

    /// Creation time (Unix timestamp)
    pub created: u64,

    /// Modification time (Unix timestamp)
    pub modified: u64,

    /// Access time (Unix timestamp)
    pub accessed: u64,

    /// Is file signed
    pub is_signed: bool,

    /// Signer name (if signed)
    pub signer: Option<String>,

    /// File hash (SHA256)
    pub sha256: Option<String>,
}

/// Platform-specific API trait
///
/// Each platform implements this trait to provide
/// access to OS-specific functionality.
pub trait PlatformApi: Send + Sync {
    /// Get all running processes
    fn get_processes(&self) -> Result<Vec<ProcessInfo>>;

    /// Get information about a specific process
    fn get_process(&self, pid: u32) -> Result<ProcessInfo>;

    /// Get all network connections
    fn get_network_connections(&self) -> Result<Vec<NetworkConnection>>;

    /// Get information about a file
    fn get_file_info(&self, path: &str) -> Result<FileInfo>;

    /// Kill a process
    fn kill_process(&self, pid: u32) -> Result<()>;

    /// Suspend a process
    fn suspend_process(&self, pid: u32) -> Result<()>;

    /// Resume a process
    fn resume_process(&self, pid: u32) -> Result<()>;

    /// Isolate network (block all network traffic)
    fn isolate_network(&self) -> Result<()>;

    /// Restore network connectivity
    fn restore_network(&self) -> Result<()>;

    /// Check if running with elevated privileges
    fn is_elevated(&self) -> bool;

    /// Get current user ID
    fn get_uid(&self) -> u32;

    /// Get system uptime in seconds
    fn get_uptime(&self) -> u64;
}

/// Get the platform-specific API implementation
pub fn get_platform_api() -> Box<dyn PlatformApi> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsApi::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxApi::new())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsApi::new())
    }

    #[cfg(target_os = "ios")]
    {
        Box::new(ios::IosApi::new())
    }

    #[cfg(target_os = "android")]
    {
        Box::new(android::AndroidApi::new())
    }

    #[cfg(not(any(
        target_os = "windows",
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    )))]
    {
        compile_error!("Unsupported platform")
    }
}

/// Get current resource usage (CPU, memory)
pub fn get_resource_usage() -> (f32, u64) {
    #[cfg(target_os = "windows")]
    {
        windows::get_resource_usage()
    }

    #[cfg(target_os = "linux")]
    {
        linux::get_resource_usage()
    }

    #[cfg(target_os = "macos")]
    {
        macos::get_resource_usage()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        (0.0, 0)
    }
}

/// Calculate file entropy (0.0-8.0)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculate SHA256 hash of data
pub fn calculate_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Calculate BLAKE3 hash of data
pub fn calculate_blake3(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hash.to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_entropy() {
        // Low entropy (all same byte)
        let data = vec![0u8; 1024];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.1);

        // High entropy (random-ish)
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.0);
    }

    #[test]
    fn test_calculate_sha256() {
        let data = b"hello world";
        let hash = calculate_sha256(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
