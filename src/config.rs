//! Agent configuration
//!
//! This module handles all configuration for the Tamandua Core agent.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Unique agent identifier
    pub agent_id: String,

    /// Backend server URL (WebSocket)
    pub server_url: String,

    /// Authentication token (JWT)
    pub auth_token: Option<String>,

    /// Telemetry configuration
    pub telemetry: TelemetryConfig,

    /// Detection configuration
    pub detection: DetectionConfig,

    /// Response configuration
    pub response: ResponseConfig,

    /// Transport configuration
    pub transport: TransportConfig,

    /// Data directory for storing state
    pub data_dir: PathBuf,

    /// Log level
    pub log_level: String,
}

/// Telemetry collection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Enable telemetry collection
    pub enabled: bool,

    /// Event batch size before sending
    pub batch_size: usize,

    /// Batch timeout in seconds
    pub batch_timeout_secs: u64,

    /// Enable compression
    pub compression: bool,

    /// Collection interval in milliseconds
    pub collection_interval_ms: u64,

    /// Maximum queue size before dropping events
    pub max_queue_size: usize,

    /// Collectors to enable
    pub collectors: CollectorsConfig,
}

/// Individual collector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorsConfig {
    /// Process events
    pub process: bool,

    /// File events
    pub file: bool,

    /// Network events
    pub network: bool,

    /// DNS queries
    pub dns: bool,

    /// Registry changes (Windows only)
    pub registry: bool,

    /// Authentication events
    pub auth: bool,
}

/// Detection engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Enable detection engine
    pub enabled: bool,

    /// YARA rules directory
    pub yara_rules_dir: Option<PathBuf>,

    /// Enable entropy analysis
    pub entropy_analysis: bool,

    /// Entropy threshold (0.0-8.0)
    pub entropy_threshold: f64,

    /// Enable ML detection
    pub ml_enabled: bool,

    /// ML model path (ONNX)
    pub ml_model_path: Option<PathBuf>,

    /// ML confidence threshold (0.0-1.0)
    pub ml_threshold: f64,

    /// Enable heuristic detection
    pub heuristics_enabled: bool,
}

/// Response execution configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    /// Enable response actions
    pub enabled: bool,

    /// Allow process termination
    pub allow_kill: bool,

    /// Allow file quarantine
    pub allow_quarantine: bool,

    /// Quarantine directory
    pub quarantine_dir: PathBuf,

    /// Allow network isolation
    pub allow_isolate: bool,

    /// Require confirmation before response
    pub require_confirmation: bool,
}

/// Transport/connectivity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Enable transport
    pub enabled: bool,

    /// Reconnect attempts
    pub max_reconnect_attempts: u32,

    /// Reconnect backoff in seconds
    pub reconnect_backoff_secs: u64,

    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,

    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,

    /// Enable TLS
    pub tls_enabled: bool,

    /// TLS certificate path (for mTLS)
    pub tls_cert_path: Option<PathBuf>,

    /// TLS key path (for mTLS)
    pub tls_key_path: Option<PathBuf>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: Uuid::new_v4().to_string(),
            server_url: "wss://localhost:4000/socket/agent".to_string(),
            auth_token: None,
            telemetry: TelemetryConfig::default(),
            detection: DetectionConfig::default(),
            response: ResponseConfig::default(),
            transport: TransportConfig::default(),
            data_dir: get_default_data_dir(),
            log_level: "info".to_string(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            batch_size: 100,
            batch_timeout_secs: 30,
            compression: true,
            collection_interval_ms: 1000,
            max_queue_size: 10000,
            collectors: CollectorsConfig::default(),
        }
    }
}

impl Default for CollectorsConfig {
    fn default() -> Self {
        Self {
            process: true,
            file: true,
            network: true,
            dns: true,
            registry: cfg!(target_os = "windows"),
            auth: true,
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            yara_rules_dir: None,
            entropy_analysis: true,
            entropy_threshold: 7.2,
            ml_enabled: false,
            ml_model_path: None,
            ml_threshold: 0.8,
            heuristics_enabled: true,
        }
    }
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_kill: true,
            allow_quarantine: true,
            quarantine_dir: get_default_quarantine_dir(),
            allow_isolate: false, // Dangerous, opt-in only
            require_confirmation: false,
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_reconnect_attempts: 10,
            reconnect_backoff_secs: 5,
            heartbeat_interval_secs: 30,
            connection_timeout_secs: 10,
            tls_enabled: true,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl AgentConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)
            .map_err(|e| Error::config(format!("Failed to parse config: {}", e)))?;
        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.validate()?;
        let contents = toml::to_string_pretty(self)
            .map_err(|e| Error::config(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        if let Ok(agent_id) = std::env::var("TAMANDUA_AGENT_ID") {
            config.agent_id = agent_id;
        }

        if let Ok(server_url) = std::env::var("TAMANDUA_SERVER_URL") {
            config.server_url = server_url;
        }

        if let Ok(auth_token) = std::env::var("TAMANDUA_AUTH_TOKEN") {
            config.auth_token = Some(auth_token);
        }

        if let Ok(data_dir) = std::env::var("TAMANDUA_DATA_DIR") {
            config.data_dir = PathBuf::from(data_dir);
        }

        if let Ok(log_level) = std::env::var("TAMANDUA_LOG_LEVEL") {
            config.log_level = log_level;
        }

        config.validate()?;
        Ok(config)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate agent_id
        if self.agent_id.is_empty() {
            return Err(Error::config("agent_id cannot be empty"));
        }

        // Validate server_url
        if !self.server_url.starts_with("ws://") && !self.server_url.starts_with("wss://") {
            return Err(Error::config("server_url must start with ws:// or wss://"));
        }

        // Validate telemetry config
        if self.telemetry.batch_size == 0 {
            return Err(Error::config("telemetry.batch_size must be > 0"));
        }

        if self.telemetry.max_queue_size < self.telemetry.batch_size {
            return Err(Error::config(
                "telemetry.max_queue_size must be >= batch_size",
            ));
        }

        // Validate detection config
        if self.detection.entropy_threshold < 0.0 || self.detection.entropy_threshold > 8.0 {
            return Err(Error::config("detection.entropy_threshold must be 0.0-8.0"));
        }

        if self.detection.ml_threshold < 0.0 || self.detection.ml_threshold > 1.0 {
            return Err(Error::config("detection.ml_threshold must be 0.0-1.0"));
        }

        // Validate transport config
        if self.transport.max_reconnect_attempts == 0 {
            return Err(Error::config(
                "transport.max_reconnect_attempts must be > 0",
            ));
        }

        Ok(())
    }
}

/// Get default data directory based on platform
fn get_default_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"C:\ProgramData\Tamandua")
    }

    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/lib/tamandua")
    }

    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/Tamandua")
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("./tamandua_data")
    }
}

/// Get default quarantine directory based on platform
fn get_default_quarantine_dir() -> PathBuf {
    let mut dir = get_default_data_dir();
    dir.push("quarantine");
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_valid() {
        let config = AgentConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_entropy_threshold() {
        let mut config = AgentConfig::default();
        config.detection.entropy_threshold = 10.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_server_url() {
        let mut config = AgentConfig::default();
        config.server_url = "http://localhost".to_string();
        assert!(config.validate().is_err());
    }
}
