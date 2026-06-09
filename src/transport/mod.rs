//! WebSocket transport layer
//!
//! Handles connectivity to the backend server,
//! message serialization, and reconnection logic.

#[cfg(feature = "transport")]
use crate::config::AgentConfig;
#[cfg(feature = "transport")]
use crate::error::{Error, Result};
#[cfg(feature = "transport")]
use crate::AgentStatus;

#[cfg(feature = "transport")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "transport")]
use std::sync::Arc;
#[cfg(feature = "transport")]
use tokio::sync::RwLock;
#[cfg(feature = "transport")]
use tracing::{debug, error, info, warn};

#[cfg(feature = "transport")]
mod client;
#[cfg(feature = "transport")]
mod message;

#[cfg(feature = "transport")]
pub use client::WebSocketClient;
#[cfg(feature = "transport")]
pub use message::{Message, MessageType};

/// Transport manager
#[cfg(feature = "transport")]
pub struct TransportManager {
    /// Configuration
    config: AgentConfig,

    /// WebSocket client
    client: Option<WebSocketClient>,

    /// Agent status reference
    status: Arc<RwLock<AgentStatus>>,

    /// Shutdown signal
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

#[cfg(feature = "transport")]
impl TransportManager {
    /// Create a new transport manager
    pub async fn new(config: &AgentConfig, status: Arc<RwLock<AgentStatus>>) -> Result<Self> {
        debug!("Initializing transport manager");

        Ok(Self {
            config: config.clone(),
            client: None,
            status,
            shutdown_tx: None,
        })
    }

    /// Connect to backend
    pub async fn connect(&mut self) -> Result<()> {
        if !self.config.transport.enabled {
            debug!("Transport disabled");
            return Ok(());
        }

        info!("Connecting to backend: {}", self.config.server_url);

        let mut client = WebSocketClient::new(&self.config)?;
        client.connect().await?;

        self.client = Some(client);

        // Update status
        {
            let mut status = self.status.write().await;
            *status = AgentStatus::Connected;
        }

        info!("Connected to backend");
        Ok(())
    }

    /// Disconnect from backend
    pub async fn disconnect(&mut self) -> Result<()> {
        debug!("Disconnecting from backend");

        if let Some(mut client) = self.client.take() {
            client.disconnect().await?;
        }

        // Update status
        {
            let mut status = self.status.write().await;
            *status = AgentStatus::Disconnected;
        }

        debug!("Disconnected from backend");
        Ok(())
    }

    /// Send a message to backend
    pub async fn send(&mut self, message: Message) -> Result<()> {
        if let Some(ref mut client) = self.client {
            client.send(message).await
        } else {
            Err(Error::transport("Not connected"))
        }
    }

    /// Receive a message from backend
    pub async fn receive(&mut self) -> Result<Option<Message>> {
        if let Some(ref mut client) = self.client {
            client.receive().await
        } else {
            Err(Error::transport("Not connected"))
        }
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }
}

#[cfg(not(feature = "transport"))]
pub struct TransportManager;

#[cfg(not(feature = "transport"))]
impl TransportManager {
    pub async fn new(_config: &crate::config::AgentConfig) -> crate::error::Result<Self> {
        Ok(Self)
    }
}
