//! Tamandua Core Library
//!
//! Cross-platform connectivity and detection library shared between
//! all Tamandua agents (desktop, mobile, embedded).
//!
//! # Architecture
//!
//! This library follows the design pattern established by Firezone's connlib,
//! providing a clean separation between platform-agnostic core logic and
//! platform-specific implementations.
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │         Application Layer               │
//! │  (Desktop/Mobile/Embedded Agents)       │
//! └─────────────────────────────────────────┘
//!                    │
//!                    ▼
//! ┌─────────────────────────────────────────┐
//! │         Tamandua Core Library           │
//! │  - Telemetry Collection                 │
//! │  - Detection Engine                     │
//! │  - Response Executor                    │
//! │  - Transport Manager                    │
//! └─────────────────────────────────────────┘
//!                    │
//!                    ▼
//! ┌─────────────────────────────────────────┐
//! │       Platform Abstraction Layer        │
//! │  (Windows/Linux/macOS/iOS/Android)      │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - `full`: Enable all features (default)
//! - `telemetry`: Event collection and batching
//! - `detection`: YARA, heuristics, ML integration
//! - `response`: Process termination, quarantine, isolation
//! - `transport`: WebSocket connectivity to backend
//! - `mobile`: iOS/Android optimizations
//! - `embedded`: Embedded device support
//!
//! # Example
//!
//! ```rust,no_run
//! use tamandua_core::{TamanduaCore, AgentConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = AgentConfig::from_file("config.toml")?;
//!     let mut agent = TamanduaCore::new(config).await?;
//!
//!     agent.start().await?;
//!
//!     // Agent runs until stopped
//!     tokio::signal::ctrl_c().await?;
//!     agent.stop().await?;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::too_many_arguments)]

pub mod config;
pub mod error;
pub mod platform;
pub mod process;
pub mod types;

#[cfg(feature = "telemetry")]
pub mod telemetry;

#[cfg(feature = "detection")]
pub mod detection;

#[cfg(feature = "response")]
pub mod response;

#[cfg(feature = "transport")]
pub mod transport;

// P2P NAT traversal for direct analyst-to-agent connections
#[cfg(feature = "p2p")]
pub mod p2p;

#[cfg(any(feature = "mobile", target_os = "ios", target_os = "android"))]
pub mod ffi;

// Re-exports for convenience
pub use config::AgentConfig;
pub use error::{Error, Result};
pub use types::{
    Alert, AlertFilter, AlertSeverity, AlertStatus, EventNotification, ScanResult, ScanStatus,
    ScanType, SystemMetrics, TamanduaError, ThreatInfo,
};

use std::sync::Arc;
use tracing::{debug, error, info, warn};

#[cfg(feature = "transport")]
use tokio::sync::RwLock;

/// Core agent status
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AgentStatus {
    /// Agent is initializing
    Initializing,
    /// Agent is running normally
    Running,
    /// Agent is connected to backend
    Connected,
    /// Agent is disconnected from backend
    Disconnected,
    /// Agent is stopping
    Stopping,
    /// Agent has stopped
    Stopped,
    /// Agent encountered an error
    Error,
}

/// Core agent health metrics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentHealth {
    /// Current status
    pub status: AgentStatus,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Number of events collected
    pub events_collected: u64,
    /// Number of detections triggered
    pub detections_triggered: u64,
    /// Number of responses executed
    pub responses_executed: u64,
    /// CPU usage percentage
    pub cpu_usage: f32,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Last heartbeat timestamp
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
}

/// Core agent that can be embedded in any application
///
/// This is the main entry point for integrating Tamandua EDR
/// functionality into desktop, mobile, or embedded applications.
///
/// # Thread Safety
///
/// `TamanduaCore` is designed to be used from a single async runtime.
/// All methods are async and internally synchronized.
pub struct TamanduaCore {
    /// Agent configuration
    config: AgentConfig,

    /// Current agent status
    #[cfg(feature = "transport")]
    status: Arc<RwLock<AgentStatus>>,

    /// Start time for uptime calculation
    start_time: std::time::Instant,

    #[cfg(feature = "telemetry")]
    telemetry: telemetry::TelemetryManager,

    #[cfg(feature = "detection")]
    detection: detection::DetectionEngine,

    #[cfg(feature = "response")]
    response: response::ResponseExecutor,

    #[cfg(feature = "transport")]
    transport: transport::TransportManager,
}

impl TamanduaCore {
    /// Create a new Tamandua core agent
    ///
    /// # Arguments
    ///
    /// * `config` - Agent configuration
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails for any component.
    #[cfg(all(feature = "full"))]
    pub async fn new(config: AgentConfig) -> Result<Self> {
        info!("Initializing Tamandua Core v{}", env!("CARGO_PKG_VERSION"));
        debug!("Configuration: {:?}", config);

        let start_time = std::time::Instant::now();

        #[cfg(feature = "transport")]
        let status = Arc::new(RwLock::new(AgentStatus::Initializing));

        // Initialize telemetry manager
        #[cfg(feature = "telemetry")]
        let telemetry = telemetry::TelemetryManager::new(&config)?;

        // Initialize detection engine
        #[cfg(feature = "detection")]
        let detection = detection::DetectionEngine::new(&config)?;

        // Initialize response executor
        #[cfg(feature = "response")]
        let response = response::ResponseExecutor::new(&config)?;

        // Initialize transport manager
        #[cfg(feature = "transport")]
        let transport = transport::TransportManager::new(&config, status.clone()).await?;

        info!("Tamandua Core initialized successfully");

        Ok(Self {
            config,
            #[cfg(feature = "transport")]
            status,
            start_time,
            #[cfg(feature = "telemetry")]
            telemetry,
            #[cfg(feature = "detection")]
            detection,
            #[cfg(feature = "response")]
            response,
            #[cfg(feature = "transport")]
            transport,
        })
    }

    /// Simplified constructor for embedded/minimal builds
    #[cfg(not(feature = "full"))]
    pub async fn new(config: AgentConfig) -> Result<Self> {
        info!(
            "Initializing Tamandua Core (minimal) v{}",
            env!("CARGO_PKG_VERSION")
        );

        #[cfg(feature = "telemetry")]
        let telemetry = telemetry::TelemetryManager::new(&config)?;

        #[cfg(feature = "detection")]
        let detection = detection::DetectionEngine::new(&config)?;

        #[cfg(feature = "response")]
        let response = response::ResponseExecutor::new(&config)?;

        #[cfg(feature = "transport")]
        let status = Arc::new(RwLock::new(AgentStatus::Initializing));

        #[cfg(feature = "transport")]
        let transport = transport::TransportManager::new(&config, status.clone()).await?;

        Ok(Self {
            config,
            start_time: std::time::Instant::now(),
            #[cfg(feature = "transport")]
            status,
            #[cfg(feature = "telemetry")]
            telemetry,
            #[cfg(feature = "detection")]
            detection,
            #[cfg(feature = "response")]
            response,
            #[cfg(feature = "transport")]
            transport,
        })
    }

    /// Start the agent
    ///
    /// This will:
    /// 1. Connect to the backend (if transport enabled)
    /// 2. Start telemetry collection (if telemetry enabled)
    /// 3. Start detection engine (if detection enabled)
    /// 4. Begin processing events
    #[cfg(feature = "transport")]
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Tamandua Core agent");

        // Update status
        {
            let mut status = self.status.write().await;
            *status = AgentStatus::Running;
        }

        // Start transport (connect to backend)
        #[cfg(feature = "transport")]
        {
            self.transport.connect().await?;
            info!("Connected to backend");
        }

        // Start telemetry collection
        #[cfg(feature = "telemetry")]
        {
            self.telemetry.start().await?;
            info!("Telemetry collection started");
        }

        // Start detection engine
        #[cfg(feature = "detection")]
        {
            self.detection.start().await?;
            info!("Detection engine started");
        }

        // Start response executor
        #[cfg(feature = "response")]
        {
            self.response.start().await?;
            info!("Response executor started");
        }

        info!("Tamandua Core agent started successfully");
        Ok(())
    }

    /// Simplified start for minimal builds
    #[cfg(not(feature = "transport"))]
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Tamandua Core agent (minimal)");
        Ok(())
    }

    /// Stop the agent gracefully
    ///
    /// This will:
    /// 1. Stop event collection
    /// 2. Flush pending events
    /// 3. Disconnect from backend
    #[cfg(feature = "transport")]
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping Tamandua Core agent");

        // Update status
        {
            let mut status = self.status.write().await;
            *status = AgentStatus::Stopping;
        }

        // Stop response executor first
        #[cfg(feature = "response")]
        {
            self.response.stop().await?;
            debug!("Response executor stopped");
        }

        // Stop detection engine
        #[cfg(feature = "detection")]
        {
            self.detection.stop().await?;
            debug!("Detection engine stopped");
        }

        // Stop telemetry collection
        #[cfg(feature = "telemetry")]
        {
            self.telemetry.stop().await?;
            debug!("Telemetry collection stopped");
        }

        // Disconnect transport
        #[cfg(feature = "transport")]
        {
            self.transport.disconnect().await?;
            debug!("Disconnected from backend");
        }

        // Update final status
        {
            let mut status = self.status.write().await;
            *status = AgentStatus::Stopped;
        }

        info!("Tamandua Core agent stopped");
        Ok(())
    }

    /// Simplified stop for minimal builds
    #[cfg(not(feature = "transport"))]
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping Tamandua Core agent (minimal)");
        Ok(())
    }

    /// Get current agent status
    #[cfg(feature = "transport")]
    pub async fn status(&self) -> AgentStatus {
        *self.status.read().await
    }

    /// Get agent health metrics
    #[cfg(feature = "transport")]
    pub async fn health(&self) -> AgentHealth {
        let status = *self.status.read().await;
        let uptime = self.start_time.elapsed().as_secs();

        #[cfg(feature = "telemetry")]
        let events_collected = self.telemetry.metrics().events_collected;
        #[cfg(not(feature = "telemetry"))]
        let events_collected = 0;

        #[cfg(feature = "detection")]
        let detections_triggered = self.detection.metrics().detections_triggered;
        #[cfg(not(feature = "detection"))]
        let detections_triggered = 0;

        #[cfg(feature = "response")]
        let responses_executed = self.response.metrics().responses_executed;
        #[cfg(not(feature = "response"))]
        let responses_executed = 0;

        // Get system metrics
        let (cpu_usage, memory_usage) = platform::get_resource_usage();

        AgentHealth {
            status,
            uptime_seconds: uptime,
            events_collected,
            detections_triggered,
            responses_executed,
            cpu_usage,
            memory_usage,
            last_heartbeat: chrono::Utc::now(),
        }
    }

    /// Get agent configuration (immutable reference)
    pub fn config(&self) -> &AgentConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Requires a live Tamandua server: `agent.start()` opens a real transport
    // connection to the configured URL. Ignored by default so offline/CI runs
    // stay green; run explicitly with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "requires a live Tamandua server (network transport connection)"]
    async fn test_agent_lifecycle_minimal() {
        let config = AgentConfig::default();
        let mut agent = TamanduaCore::new(config).await.unwrap();

        agent.start().await.unwrap();
        agent.stop().await.unwrap();
    }
}
