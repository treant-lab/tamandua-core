//! Event batching utilities

use super::TelemetryEvent;
use serde::{Deserialize, Serialize};

/// Batch of telemetry events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    /// Batch ID
    pub id: String,

    /// Agent ID
    pub agent_id: String,

    /// Batch timestamp
    pub timestamp: u64,

    /// Events in this batch
    pub events: Vec<TelemetryEvent>,

    /// Compression type (none, gzip)
    pub compression: String,
}

impl EventBatch {
    /// Create a new event batch
    pub fn new(agent_id: String, events: Vec<TelemetryEvent>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            events,
            compression: "none".to_string(),
        }
    }
}
