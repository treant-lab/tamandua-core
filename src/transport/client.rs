//! WebSocket client implementation

use super::{Message, MessageType};
use crate::config::AgentConfig;
use crate::error::{Error, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, info, warn};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// WebSocket client
pub struct WebSocketClient {
    /// Configuration
    config: AgentConfig,

    /// WebSocket stream
    stream: Option<WsStream>,
}

impl WebSocketClient {
    /// Create a new WebSocket client
    pub fn new(config: &AgentConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            stream: None,
        })
    }

    /// Connect to the backend
    pub async fn connect(&mut self) -> Result<()> {
        let url = &self.config.server_url;
        debug!("Connecting to WebSocket: {}", url);

        let (ws_stream, _) = connect_async(url)
            .await
            .map_err(|e| Error::transport(format!("Connection failed: {}", e)))?;

        info!("WebSocket connected");

        // Send authentication
        let auth_msg = Message::auth(
            self.config.agent_id.clone(),
            self.config.auth_token.clone().unwrap_or_default(),
        );

        self.stream = Some(ws_stream);
        self.send(auth_msg).await?;

        info!("Authentication sent");
        Ok(())
    }

    /// Disconnect from the backend
    pub async fn disconnect(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream
                .close(None)
                .await
                .map_err(|e| Error::transport(format!("Disconnect failed: {}", e)))?;
        }
        Ok(())
    }

    /// Send a message
    pub async fn send(&mut self, message: Message) -> Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| Error::transport("Not connected"))?;

        let json = serde_json::to_string(&message)?;
        let ws_msg = WsMessage::Text(json);

        stream
            .send(ws_msg)
            .await
            .map_err(|e| Error::transport(format!("Send failed: {}", e)))?;

        debug!("Sent message: {}", message.id);
        Ok(())
    }

    /// Receive a message
    pub async fn receive(&mut self) -> Result<Option<Message>> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| Error::transport("Not connected"))?;

        match stream.next().await {
            Some(Ok(WsMessage::Text(text))) => {
                let message: Message = serde_json::from_str(&text)?;
                debug!("Received message: {}", message.id);
                Ok(Some(message))
            }
            Some(Ok(WsMessage::Close(_))) => {
                info!("WebSocket closed by server");
                Ok(None)
            }
            Some(Ok(_)) => {
                // Ignore other message types (binary, ping, pong)
                Ok(None)
            }
            Some(Err(e)) => Err(Error::transport(format!("Receive error: {}", e))),
            None => {
                warn!("WebSocket stream ended");
                Ok(None)
            }
        }
    }
}
