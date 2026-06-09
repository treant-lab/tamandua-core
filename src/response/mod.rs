//! Response execution
//!
//! Handles response actions like process termination,
//! file quarantine, and network isolation.

use crate::config::AgentConfig;
use crate::error::{Error, Result};
use crate::platform;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

mod quarantine;

pub use quarantine::QuarantineManager;

/// Response action type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseAction {
    /// Kill a process
    KillProcess { pid: u32 },

    /// Suspend a process
    SuspendProcess { pid: u32 },

    /// Resume a process
    ResumeProcess { pid: u32 },

    /// Quarantine a file
    QuarantineFile { path: String },

    /// Restore a quarantined file
    RestoreFile { quarantine_id: String },

    /// Block a network connection
    BlockNetwork {
        protocol: String,
        address: String,
        port: u16,
    },

    /// Isolate endpoint (block all network)
    IsolateEndpoint,

    /// Restore network connectivity
    RestoreNetwork,

    /// Custom command
    Custom { command: String, args: Vec<String> },
}

/// Response result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseResult {
    /// Action ID
    pub id: String,

    /// Action that was executed
    pub action: ResponseAction,

    /// Success status
    pub success: bool,

    /// Error message (if failed)
    pub error: Option<String>,

    /// Timestamp
    pub timestamp: u64,

    /// Additional metadata
    pub metadata: serde_json::Value,
}

/// Response metrics
#[derive(Debug, Clone)]
pub struct ResponseMetrics {
    /// Total responses executed
    pub responses_executed: u64,

    /// Successful responses
    pub responses_succeeded: u64,

    /// Failed responses
    pub responses_failed: u64,

    /// Processes killed
    pub processes_killed: u64,

    /// Files quarantined
    pub files_quarantined: u64,
}

/// Response executor
pub struct ResponseExecutor {
    /// Configuration
    config: AgentConfig,

    /// Quarantine manager
    quarantine: QuarantineManager,

    /// Platform API
    platform: Box<dyn platform::PlatformApi>,

    /// Metrics
    metrics: Arc<ResponseMetricsInner>,

    /// Running state
    running: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Debug)]
struct ResponseMetricsInner {
    responses_executed: AtomicU64,
    responses_succeeded: AtomicU64,
    responses_failed: AtomicU64,
    processes_killed: AtomicU64,
    files_quarantined: AtomicU64,
}

impl ResponseExecutor {
    /// Create a new response executor
    pub fn new(config: &AgentConfig) -> Result<Self> {
        debug!("Initializing response executor");

        let quarantine = QuarantineManager::new(&config.response.quarantine_dir)?;
        let platform = platform::get_platform_api();

        let metrics = Arc::new(ResponseMetricsInner {
            responses_executed: AtomicU64::new(0),
            responses_succeeded: AtomicU64::new(0),
            responses_failed: AtomicU64::new(0),
            processes_killed: AtomicU64::new(0),
            files_quarantined: AtomicU64::new(0),
        });

        Ok(Self {
            config: config.clone(),
            quarantine,
            platform,
            metrics,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Start response executor
    pub async fn start(&mut self) -> Result<()> {
        if !self.config.response.enabled {
            debug!("Response executor disabled");
            return Ok(());
        }

        info!("Starting response executor");
        self.running.store(true, Ordering::Relaxed);
        info!("Response executor started");
        Ok(())
    }

    /// Stop response executor
    pub async fn stop(&mut self) -> Result<()> {
        debug!("Stopping response executor");
        self.running.store(false, Ordering::Relaxed);
        debug!("Response executor stopped");
        Ok(())
    }

    /// Execute a response action
    pub fn execute(&self, action: ResponseAction) -> ResponseResult {
        self.metrics
            .responses_executed
            .fetch_add(1, Ordering::Relaxed);

        let result = match &action {
            ResponseAction::KillProcess { pid } => self.kill_process(*pid),
            ResponseAction::SuspendProcess { pid } => self.suspend_process(*pid),
            ResponseAction::ResumeProcess { pid } => self.resume_process(*pid),
            ResponseAction::QuarantineFile { path } => self.quarantine_file(path),
            ResponseAction::RestoreFile { quarantine_id } => self.restore_file(quarantine_id),
            ResponseAction::BlockNetwork {
                protocol,
                address,
                port,
            } => self.block_network(protocol, address, *port),
            ResponseAction::IsolateEndpoint => self.isolate_endpoint(),
            ResponseAction::RestoreNetwork => self.restore_network(),
            ResponseAction::Custom { command, args } => self.execute_custom(command, args),
        };

        let (success, error) = match result {
            Ok(_) => {
                self.metrics
                    .responses_succeeded
                    .fetch_add(1, Ordering::Relaxed);
                (true, None)
            }
            Err(e) => {
                self.metrics
                    .responses_failed
                    .fetch_add(1, Ordering::Relaxed);
                warn!("Response action failed: {}", e);
                (false, Some(e.to_string()))
            }
        };

        ResponseResult {
            id: uuid::Uuid::new_v4().to_string(),
            action,
            success,
            error,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            metadata: serde_json::json!({}),
        }
    }

    /// Kill a process
    fn kill_process(&self, pid: u32) -> Result<()> {
        if !self.config.response.allow_kill {
            return Err(Error::response("Process killing is disabled"));
        }

        info!("Killing process {}", pid);
        self.platform.kill_process(pid)?;
        self.metrics
            .processes_killed
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Suspend a process
    fn suspend_process(&self, pid: u32) -> Result<()> {
        info!("Suspending process {}", pid);
        self.platform.suspend_process(pid)
    }

    /// Resume a process
    fn resume_process(&self, pid: u32) -> Result<()> {
        info!("Resuming process {}", pid);
        self.platform.resume_process(pid)
    }

    /// Quarantine a file
    fn quarantine_file(&self, path: &str) -> Result<()> {
        if !self.config.response.allow_quarantine {
            return Err(Error::response("File quarantine is disabled"));
        }

        info!("Quarantining file: {}", path);
        self.quarantine.quarantine_file(Path::new(path))?;
        self.metrics
            .files_quarantined
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Restore a quarantined file
    fn restore_file(&self, quarantine_id: &str) -> Result<()> {
        info!("Restoring file: {}", quarantine_id);
        self.quarantine.restore_file(quarantine_id)
    }

    /// Block a network connection
    fn block_network(&self, protocol: &str, address: &str, port: u16) -> Result<()> {
        info!("Blocking network: {}://{}:{}", protocol, address, port);
        // Platform-specific firewall rules would go here
        Ok(())
    }

    /// Isolate endpoint
    fn isolate_endpoint(&self) -> Result<()> {
        if !self.config.response.allow_isolate {
            return Err(Error::response("Network isolation is disabled"));
        }

        warn!("Isolating endpoint - blocking all network traffic");
        self.platform.isolate_network()
    }

    /// Restore network connectivity
    fn restore_network(&self) -> Result<()> {
        info!("Restoring network connectivity");
        self.platform.restore_network()
    }

    /// Execute custom command
    fn execute_custom(&self, command: &str, args: &[String]) -> Result<()> {
        info!("Executing custom command: {} {:?}", command, args);
        // Custom command execution would go here
        Ok(())
    }

    /// Get response metrics
    pub fn metrics(&self) -> ResponseMetrics {
        ResponseMetrics {
            responses_executed: self.metrics.responses_executed.load(Ordering::Relaxed),
            responses_succeeded: self.metrics.responses_succeeded.load(Ordering::Relaxed),
            responses_failed: self.metrics.responses_failed.load(Ordering::Relaxed),
            processes_killed: self.metrics.processes_killed.load(Ordering::Relaxed),
            files_quarantined: self.metrics.files_quarantined.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_executor_creation() {
        let config = AgentConfig::default();
        let executor = ResponseExecutor::new(&config).unwrap();
        assert_eq!(executor.metrics().responses_executed, 0);
    }
}
