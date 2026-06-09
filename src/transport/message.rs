//! WebSocket message types

use serde::{Deserialize, Serialize};

/// Message type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MessageType {
    /// Heartbeat/ping
    Heartbeat,

    /// Authentication
    Auth { token: String },

    /// Telemetry batch
    Telemetry { batch: Vec<u8> },

    /// Detection result
    Detection { detection: serde_json::Value },

    /// Response command
    Command { action: serde_json::Value },

    /// Response result
    Response { result: serde_json::Value },

    /// Configuration update
    ConfigUpdate { config: serde_json::Value },

    /// Error message
    Error { message: String },
}

/// WebSocket message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message ID
    pub id: String,

    /// Agent ID
    pub agent_id: String,

    /// Timestamp
    pub timestamp: u64,

    /// Message type and payload
    #[serde(flatten)]
    pub message_type: MessageType,
}

impl Message {
    /// Create a new message
    pub fn new(agent_id: String, message_type: MessageType) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            message_type,
        }
    }

    /// Create a heartbeat message
    pub fn heartbeat(agent_id: String) -> Self {
        Self::new(agent_id, MessageType::Heartbeat)
    }

    /// Create an auth message
    pub fn auth(agent_id: String, token: String) -> Self {
        Self::new(agent_id, MessageType::Auth { token })
    }
}
