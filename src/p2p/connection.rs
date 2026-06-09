//! High-level connection helpers
//!
//! Provides async wrappers and utilities for P2P connections.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::net::UdpSocket;
use tokio::time::{interval, timeout, Instant};
use tracing::{debug, error, info, warn};

use super::{ConnectionAnswer, ConnectionOffer, P2PConfig, P2PConnection, PeerId, RelayServer};

/// Async P2P connection manager
pub struct AsyncP2PConnection {
    /// Underlying P2P connection
    connection: P2PConnection,

    /// UDP socket for I/O
    socket: UdpSocket,

    /// Receive buffer
    recv_buffer: Vec<u8>,
}

impl AsyncP2PConnection {
    /// Create new async connection (initiator)
    pub async fn initiate(
        remote_id: PeerId,
        relays: &[RelayServer],
        config: P2PConfig,
        bind_addr: SocketAddr,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let connection = P2PConnection::initiate(remote_id, relays, config);

        info!(
            "Async P2P connection initiated, bound to {}",
            socket.local_addr()?
        );

        Ok(Self {
            connection,
            socket,
            recv_buffer: vec![0u8; 65536],
        })
    }

    /// Create async connection from offer (responder)
    pub async fn accept(
        offer: ConnectionOffer,
        relays: &[RelayServer],
        config: P2PConfig,
        bind_addr: SocketAddr,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let connection = P2PConnection::accept(offer, relays, config);

        info!(
            "Async P2P connection accepting, bound to {}",
            socket.local_addr()?
        );

        Ok(Self {
            connection,
            socket,
            recv_buffer: vec![0u8; 65536],
        })
    }

    /// Run connection event loop
    pub async fn run(&mut self) -> Result<()> {
        let mut ticker = interval(Duration::from_millis(100));

        loop {
            tokio::select! {
                // Handle timer events
                _ = ticker.tick() => {
                    self.handle_timer().await?;
                }

                // Handle incoming packets
                result = self.socket.recv_from(&mut self.recv_buffer) => {
                    match result {
                        Ok((len, source)) => {
                            self.handle_input(&self.recv_buffer[..len], source).await?;
                        }
                        Err(e) => {
                            error!("Socket recv error: {}", e);
                            return Err(e.into());
                        }
                    }
                }
            }

            // Check if connection failed
            if matches!(self.connection.state(), super::ConnectionState::Failed) {
                return Err(anyhow!("Connection failed"));
            }

            // Check if connection closed
            if matches!(self.connection.state(), super::ConnectionState::Closed) {
                info!("Connection closed");
                break;
            }
        }

        Ok(())
    }

    /// Wait for connection to establish
    pub async fn wait_connected(&mut self, timeout_duration: Duration) -> Result<()> {
        let result = timeout(timeout_duration, async {
            let mut ticker = interval(Duration::from_millis(100));

            loop {
                ticker.tick().await;
                self.handle_timer().await?;

                // Poll for incoming packets with timeout
                if let Ok(Ok((len, source))) = tokio::time::timeout(
                    Duration::from_millis(50),
                    self.socket.recv_from(&mut self.recv_buffer),
                )
                .await
                {
                    self.handle_input(&self.recv_buffer[..len], source).await?;
                }

                if self.connection.is_connected() {
                    return Ok(());
                }

                if matches!(self.connection.state(), super::ConnectionState::Failed) {
                    return Err(anyhow!("Connection failed"));
                }
            }
        })
        .await;

        match result {
            Ok(inner_result) => inner_result,
            Err(_) => Err(anyhow!("Connection timeout")),
        }
    }

    /// Send data
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.connection.send(data)?;

        // Drain transmit queue
        while let Some(transmit) = self.connection.poll_transmit() {
            self.socket
                .send_to(&transmit.payload, transmit.destination)
                .await?;
            debug!(
                "Sent {} bytes to {}",
                transmit.payload.len(),
                transmit.destination
            );
        }

        Ok(())
    }

    /// Receive data
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.connection.recv()
    }

    /// Get connection offer
    pub fn create_offer(&mut self) -> ConnectionOffer {
        self.connection.create_offer()
    }

    /// Apply connection answer
    pub fn apply_answer(&mut self, answer: ConnectionAnswer) {
        self.connection.apply_answer(answer);
    }

    /// Create connection answer
    pub fn create_answer(&mut self) -> ConnectionAnswer {
        self.connection.create_answer()
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connection.is_connected()
    }

    /// Get connection statistics
    pub fn stats(&self) -> super::ConnectionStats {
        self.connection.stats()
    }

    /// Close connection
    pub fn close(&mut self) {
        self.connection.close();
    }

    // Private methods

    async fn handle_timer(&mut self) -> Result<()> {
        // Drain transmit queue
        while let Some(transmit) = self.connection.poll_transmit() {
            self.socket
                .send_to(&transmit.payload, transmit.destination)
                .await?;
            debug!(
                "Sent {} bytes to {}",
                transmit.payload.len(),
                transmit.destination
            );
        }

        Ok(())
    }

    async fn handle_input(&mut self, data: &[u8], source: SocketAddr) -> Result<()> {
        debug!("Received {} bytes from {}", data.len(), source);

        self.connection.handle_input(data, source, Instant::now());

        // Drain transmit queue (responses)
        while let Some(transmit) = self.connection.poll_transmit() {
            self.socket
                .send_to(&transmit.payload, transmit.destination)
                .await?;
            debug!(
                "Sent {} bytes to {}",
                transmit.payload.len(),
                transmit.destination
            );
        }

        Ok(())
    }
}

/// P2P connection pool for managing multiple connections
pub struct ConnectionPool {
    /// Active connections
    connections: Vec<(PeerId, AsyncP2PConnection)>,

    /// Maximum connections
    max_connections: usize,
}

impl ConnectionPool {
    /// Create new connection pool
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: Vec::new(),
            max_connections,
        }
    }

    /// Add connection
    pub fn add(&mut self, peer_id: PeerId, connection: AsyncP2PConnection) -> Result<()> {
        if self.connections.len() >= self.max_connections {
            return Err(anyhow!("Connection pool full"));
        }

        self.connections.push((peer_id, connection));
        Ok(())
    }

    /// Get connection by peer ID
    pub fn get(&mut self, peer_id: &PeerId) -> Option<&mut AsyncP2PConnection> {
        self.connections
            .iter_mut()
            .find(|(id, _)| id == peer_id)
            .map(|(_, conn)| conn)
    }

    /// Remove connection
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<AsyncP2PConnection> {
        if let Some(pos) = self.connections.iter().position(|(id, _)| id == peer_id) {
            Some(self.connections.remove(pos).1)
        } else {
            None
        }
    }

    /// Get all peer IDs
    pub fn peers(&self) -> Vec<PeerId> {
        self.connections.iter().map(|(id, _)| *id).collect()
    }

    /// Connection count
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_connection_creation() {
        let config = P2PConfig::default();
        let relays = vec![];
        let remote_id = PeerId::new();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let result = AsyncP2PConnection::initiate(remote_id, &relays, config, bind_addr).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_connection_pool() {
        let mut pool = ConnectionPool::new(10);

        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());

        let peers = pool.peers();
        assert_eq!(peers.len(), 0);
    }

    #[tokio::test]
    async fn test_connection_offer_answer() {
        let config = P2PConfig::default();
        let relays = vec![];
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Create initiator
        let remote_id = PeerId::new();
        let mut initiator =
            AsyncP2PConnection::initiate(remote_id, &relays, config.clone(), bind_addr)
                .await
                .unwrap();

        // Create offer
        let offer = initiator.create_offer();
        assert_eq!(offer.peer_id, initiator.connection.local_id());

        // Create responder
        let bind_addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut responder = AsyncP2PConnection::accept(offer, &relays, config, bind_addr2)
            .await
            .unwrap();

        // Create answer
        let answer = responder.create_answer();

        // Apply answer
        initiator.apply_answer(answer);
    }
}
