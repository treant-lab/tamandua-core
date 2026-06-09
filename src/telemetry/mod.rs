//! Telemetry collection and batching
//!
//! This module provides event collection, batching, compression,
//! and forwarding to the backend.

use crate::config::AgentConfig;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

#[cfg(feature = "transport")]
use tokio::sync::mpsc;

mod batch;
mod collector;

pub use batch::EventBatch;
pub use collector::EventCollector;

/// Telemetry event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventType {
    /// Process creation/termination
    Process,
    /// File system operations
    File,
    /// Network connections
    Network,
    /// DNS queries
    Dns,
    /// Registry changes (Windows)
    Registry,
    /// Authentication events
    Auth,
    /// Generic system event
    System,
}

/// Telemetry event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Event ID (UUID)
    pub id: String,

    /// Event type
    pub event_type: EventType,

    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,

    /// Agent ID
    pub agent_id: String,

    /// Event payload (JSON)
    pub payload: serde_json::Value,

    /// Event metadata
    pub metadata: EventMetadata,
}

/// Event metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    /// Hostname
    pub hostname: String,

    /// Operating system
    pub os: String,

    /// OS version
    pub os_version: String,

    /// Agent version
    pub agent_version: String,
}

/// Telemetry metrics
#[derive(Debug, Clone)]
pub struct TelemetryMetrics {
    /// Total events collected
    pub events_collected: u64,

    /// Events dropped due to queue full
    pub events_dropped: u64,

    /// Batches sent
    pub batches_sent: u64,

    /// Send errors
    pub send_errors: u64,
}

/// Telemetry manager
///
/// Coordinates event collection from multiple collectors,
/// batching, compression, and forwarding to the backend.
pub struct TelemetryManager {
    /// Configuration
    config: AgentConfig,

    /// Event collectors
    #[cfg(feature = "transport")]
    collectors: Vec<Box<dyn EventCollector>>,

    /// Event channel sender
    #[cfg(feature = "transport")]
    tx: mpsc::Sender<TelemetryEvent>,

    /// Event channel receiver
    #[cfg(feature = "transport")]
    rx: Option<mpsc::Receiver<TelemetryEvent>>,

    /// Metrics
    metrics: Arc<TelemetryMetricsInner>,

    /// Shutdown signal
    #[cfg(feature = "transport")]
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

#[derive(Debug)]
struct TelemetryMetricsInner {
    events_collected: AtomicU64,
    events_dropped: AtomicU64,
    batches_sent: AtomicU64,
    send_errors: AtomicU64,
}

impl TelemetryManager {
    /// Create a new telemetry manager
    pub fn new(config: &AgentConfig) -> Result<Self> {
        debug!("Initializing telemetry manager");

        #[cfg(feature = "transport")]
        let (tx, rx) = mpsc::channel(config.telemetry.max_queue_size);

        let metrics = Arc::new(TelemetryMetricsInner {
            events_collected: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            batches_sent: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
        });

        Ok(Self {
            config: config.clone(),
            #[cfg(feature = "transport")]
            collectors: Vec::new(),
            #[cfg(feature = "transport")]
            tx,
            #[cfg(feature = "transport")]
            rx: Some(rx),
            metrics,
            #[cfg(feature = "transport")]
            shutdown_tx: None,
        })
    }

    /// Start telemetry collection
    #[cfg(feature = "transport")]
    pub async fn start(&mut self) -> Result<()> {
        if !self.config.telemetry.enabled {
            debug!("Telemetry collection disabled");
            return Ok(());
        }

        debug!("Starting telemetry collection");

        // Initialize collectors based on config
        self.initialize_collectors()?;

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        // Start collector tasks
        for collector in &self.collectors {
            let tx = self.tx.clone();
            let mut shutdown = shutdown_rx.clone();
            let interval =
                std::time::Duration::from_millis(self.config.telemetry.collection_interval_ms);

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => {
                            // Collect events
                            // Note: actual collection happens in collector
                        }
                        _ = shutdown.changed() => {
                            debug!("Collector shutting down");
                            break;
                        }
                    }
                }
            });
        }

        // Start batch processor
        let rx = self
            .rx
            .take()
            .ok_or_else(|| Error::telemetry("Receiver already taken"))?;

        let config = self.config.clone();
        let metrics = self.metrics.clone();
        let mut shutdown = shutdown_rx.clone();

        tokio::spawn(async move {
            Self::batch_processor(rx, config, metrics, shutdown).await;
        });

        debug!("Telemetry collection started");
        Ok(())
    }

    /// Simplified start for non-transport builds
    #[cfg(not(feature = "transport"))]
    pub async fn start(&mut self) -> Result<()> {
        debug!("Telemetry collection (minimal mode)");
        Ok(())
    }

    /// Stop telemetry collection
    #[cfg(feature = "transport")]
    pub async fn stop(&mut self) -> Result<()> {
        debug!("Stopping telemetry collection");

        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }

        // Give tasks time to shutdown gracefully
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        debug!("Telemetry collection stopped");
        Ok(())
    }

    /// Simplified stop for non-transport builds
    #[cfg(not(feature = "transport"))]
    pub async fn stop(&mut self) -> Result<()> {
        debug!("Telemetry collection stopped (minimal mode)");
        Ok(())
    }

    /// Get telemetry metrics
    pub fn metrics(&self) -> TelemetryMetrics {
        TelemetryMetrics {
            events_collected: self.metrics.events_collected.load(Ordering::Relaxed),
            events_dropped: self.metrics.events_dropped.load(Ordering::Relaxed),
            batches_sent: self.metrics.batches_sent.load(Ordering::Relaxed),
            send_errors: self.metrics.send_errors.load(Ordering::Relaxed),
        }
    }

    /// Initialize collectors based on configuration
    #[cfg(feature = "transport")]
    fn initialize_collectors(&mut self) -> Result<()> {
        debug!("Initializing collectors");

        let collectors_config = &self.config.telemetry.collectors;

        if collectors_config.process {
            debug!("Process collector enabled");
            // Collector initialization happens here
        }

        if collectors_config.file {
            debug!("File collector enabled");
        }

        if collectors_config.network {
            debug!("Network collector enabled");
        }

        if collectors_config.dns {
            debug!("DNS collector enabled");
        }

        #[cfg(target_os = "windows")]
        if collectors_config.registry {
            debug!("Registry collector enabled");
        }

        if collectors_config.auth {
            debug!("Auth collector enabled");
        }

        Ok(())
    }

    /// Batch processor task
    #[cfg(feature = "transport")]
    async fn batch_processor(
        mut rx: mpsc::Receiver<TelemetryEvent>,
        config: AgentConfig,
        metrics: Arc<TelemetryMetricsInner>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut batch = Vec::with_capacity(config.telemetry.batch_size);
        let timeout = tokio::time::Duration::from_secs(config.telemetry.batch_timeout_secs);

        loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Some(event) => {
                            batch.push(event);
                            metrics.events_collected.fetch_add(1, Ordering::Relaxed);

                            if batch.len() >= config.telemetry.batch_size {
                                Self::send_batch(&mut batch, &config, &metrics).await;
                            }
                        }
                        None => {
                            debug!("Event channel closed");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(timeout) => {
                    if !batch.is_empty() {
                        Self::send_batch(&mut batch, &config, &metrics).await;
                    }
                }
                _ = shutdown.changed() => {
                    debug!("Batch processor shutting down");
                    if !batch.is_empty() {
                        Self::send_batch(&mut batch, &config, &metrics).await;
                    }
                    break;
                }
            }
        }
    }

    /// Send batch to backend
    #[cfg(feature = "transport")]
    async fn send_batch(
        batch: &mut Vec<TelemetryEvent>,
        config: &AgentConfig,
        metrics: &Arc<TelemetryMetricsInner>,
    ) {
        debug!("Sending batch of {} events", batch.len());

        // Compress if enabled
        let payload = if config.telemetry.compression {
            match Self::compress_batch(batch) {
                Ok(compressed) => compressed,
                Err(e) => {
                    warn!("Failed to compress batch: {}", e);
                    metrics.send_errors.fetch_add(1, Ordering::Relaxed);
                    batch.clear();
                    return;
                }
            }
        } else {
            match serde_json::to_vec(batch) {
                Ok(json) => json,
                Err(e) => {
                    warn!("Failed to serialize batch: {}", e);
                    metrics.send_errors.fetch_add(1, Ordering::Relaxed);
                    batch.clear();
                    return;
                }
            }
        };

        // TODO: Send to transport layer
        debug!("Batch sent: {} bytes", payload.len());
        metrics.batches_sent.fetch_add(1, Ordering::Relaxed);

        batch.clear();
    }

    /// Compress batch using gzip
    #[cfg(feature = "transport")]
    fn compress_batch(batch: &[TelemetryEvent]) -> Result<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let json = serde_json::to_vec(batch)?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&json)?;
        Ok(encoder.finish()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization() {
        let event = TelemetryEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: EventType::Process,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            agent_id: "test-agent".to_string(),
            payload: serde_json::json!({"pid": 1234}),
            metadata: EventMetadata {
                hostname: "test-host".to_string(),
                os: "linux".to_string(),
                os_version: "5.15".to_string(),
                agent_version: "0.1.0".to_string(),
            },
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: TelemetryEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event.id, deserialized.id);
        assert_eq!(event.event_type, deserialized.event_type);
    }
}
