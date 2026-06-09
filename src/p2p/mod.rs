//! Peer-to-Peer Connection Module
//!
//! Implements ICE (RFC 8445) + WireGuard for direct connections
//! between analysts and agents, bypassing the server for data transfer.
//!
//! # Architecture
//!
//! ```text
//! [Analyst] <-- Signaling (WebSocket) --> [Server] <-- Signaling --> [Agent]
//!     |                                                                  |
//!     +---- ICE Candidate Exchange + WireGuard Handshake ---------------+
//!     |                                                                  |
//!     +------------------ Direct Encrypted Tunnel ----------------------+
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use tamandua_core::p2p::{P2PConnection, P2PConfig, RelayServer};
//!
//! // Initiator (analyst)
//! let config = P2PConfig::default();
//! let relays = vec![RelayServer::new("turn:turn.example.com:3478")];
//! let mut conn = P2PConnection::initiate(remote_peer_id, &relays, config);
//!
//! // Send offer via signaling server
//! let offer = conn.create_offer();
//! // ... send offer ...
//!
//! // Receive answer
//! conn.apply_answer(answer);
//!
//! // Wait for connection
//! while !conn.is_connected() {
//!     conn.poll_events();
//! }
//!
//! // Send data
//! conn.send(b"Hello, agent!").unwrap();
//! ```

pub mod connection;
pub mod ice;
pub mod stun;
pub mod turn;
pub mod wireguard;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

pub use ice::{Candidate, CandidateType, IceAgent};
pub use wireguard::WireGuardTunnel;

/// Unique identifier for a peer (analyst or agent)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub uuid::Uuid);

impl PeerId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn from_string(s: &str) -> Result<Self> {
        Ok(Self(uuid::Uuid::parse_str(s)?))
    }
}

impl Default for PeerId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Configuration for P2P connections
#[derive(Debug, Clone)]
pub struct P2PConfig {
    /// Maximum time to wait for connection establishment
    pub connection_timeout: Duration,

    /// Interval for sending keepalive packets
    pub keepalive_interval: Duration,

    /// STUN server addresses for NAT discovery
    pub stun_servers: Vec<SocketAddr>,

    /// Enable aggressive ICE nomination (faster but more bandwidth)
    pub aggressive_nomination: bool,

    /// MTU for the tunnel
    pub mtu: usize,
}

impl Default for P2PConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(25),
            stun_servers: vec![
                "64.233.177.127:19302".parse().unwrap(), // Google STUN
                "74.125.250.129:19302".parse().unwrap(), // Google STUN
            ],
            aggressive_nomination: false,
            mtu: 1420, // Standard WireGuard MTU
        }
    }
}

/// TURN relay server configuration
#[derive(Debug, Clone)]
pub struct RelayServer {
    pub address: SocketAddr,
    pub username: String,
    pub password: String,
    pub realm: String,
}

impl RelayServer {
    pub fn new(addr: SocketAddr, username: String, password: String) -> Self {
        Self {
            address: addr,
            username,
            password,
            realm: "tamandua".to_string(),
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state, gathering local candidates
    Gathering,

    /// Waiting for remote candidates
    WaitingForRemote,

    /// Performing ICE connectivity checks
    Connecting,

    /// ICE connected, performing WireGuard handshake
    Handshaking,

    /// Fully connected and ready for data
    Connected,

    /// Connection failed
    Failed,

    /// Connection closed
    Closed,
}

/// Connection offer (SDP-like)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionOffer {
    pub peer_id: PeerId,
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub candidates: Vec<Candidate>,
    pub wireguard_public_key: String,
}

/// Connection answer (SDP-like)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionAnswer {
    pub peer_id: PeerId,
    pub ice_ufrag: String,
    pub ice_pwd: String,
    pub candidates: Vec<Candidate>,
    pub wireguard_public_key: String,
}

/// Data to transmit (sans-IO)
#[derive(Debug, Clone)]
pub struct Transmit {
    pub destination: SocketAddr,
    pub payload: Vec<u8>,
}

/// P2P connection for direct analyst-agent communication
pub struct P2PConnection {
    /// Local peer ID
    local_id: PeerId,

    /// Remote peer ID
    remote_id: PeerId,

    /// ICE agent for NAT traversal
    ice_agent: ice::IceAgent,

    /// WireGuard tunnel for encryption
    wireguard: wireguard::WireGuardTunnel,

    /// Connection state
    state: ConnectionState,

    /// Configuration
    config: P2PConfig,

    /// Outbound transmit queue
    transmit_queue: VecDeque<Transmit>,

    /// Inbound data queue (decrypted)
    recv_queue: VecDeque<Vec<u8>>,

    /// Last keepalive sent
    last_keepalive: Instant,

    /// Connection start time
    started_at: Instant,
}

impl P2PConnection {
    /// Initiate a P2P connection to a remote agent
    pub fn initiate(remote_id: PeerId, relays: &[RelayServer], config: P2PConfig) -> Self {
        let local_id = PeerId::new();

        info!(
            "Initiating P2P connection from {} to {}",
            local_id, remote_id
        );

        let ice_agent = ice::IceAgent::new(ice::IceRole::Controlling, &config.stun_servers, relays);

        let wireguard = wireguard::WireGuardTunnel::new();

        Self {
            local_id,
            remote_id,
            ice_agent,
            wireguard,
            state: ConnectionState::Gathering,
            config,
            transmit_queue: VecDeque::new(),
            recv_queue: VecDeque::new(),
            last_keepalive: Instant::now(),
            started_at: Instant::now(),
        }
    }

    /// Accept an incoming P2P connection
    pub fn accept(offer: ConnectionOffer, relays: &[RelayServer], config: P2PConfig) -> Self {
        let local_id = PeerId::new();
        let remote_id = offer.peer_id;

        info!("Accepting P2P connection from {}", remote_id);

        let mut ice_agent =
            ice::IceAgent::new(ice::IceRole::Controlled, &config.stun_servers, relays);

        // Set remote ICE credentials
        ice_agent.set_remote_credentials(&offer.ice_ufrag, &offer.ice_pwd);

        // Add remote candidates
        for candidate in &offer.candidates {
            ice_agent.add_remote_candidate(candidate.clone());
        }

        let mut wireguard = wireguard::WireGuardTunnel::new();

        // Set peer public key
        if let Ok(peer_key) = hex::decode(&offer.wireguard_public_key) {
            if let Ok(key_bytes) = peer_key.try_into() {
                wireguard.set_peer_public_key(key_bytes);
            }
        }

        Self {
            local_id,
            remote_id,
            ice_agent,
            wireguard,
            state: ConnectionState::Connecting,
            config,
            transmit_queue: VecDeque::new(),
            recv_queue: VecDeque::new(),
            last_keepalive: Instant::now(),
            started_at: Instant::now(),
        }
    }

    /// Create connection offer
    pub fn create_offer(&mut self) -> ConnectionOffer {
        // Start gathering candidates
        self.ice_agent.gather_candidates();

        ConnectionOffer {
            peer_id: self.local_id,
            ice_ufrag: self.ice_agent.local_ufrag().to_string(),
            ice_pwd: self.ice_agent.local_pwd().to_string(),
            candidates: self.ice_agent.local_candidates().to_vec(),
            wireguard_public_key: hex::encode(self.wireguard.public_key()),
        }
    }

    /// Apply connection answer
    pub fn apply_answer(&mut self, answer: ConnectionAnswer) {
        info!("Applying answer from peer {}", answer.peer_id);

        // Set remote ICE credentials
        self.ice_agent
            .set_remote_credentials(&answer.ice_ufrag, &answer.ice_pwd);

        // Add remote candidates
        for candidate in answer.candidates {
            self.ice_agent.add_remote_candidate(candidate);
        }

        // Set peer public key
        if let Ok(peer_key) = hex::decode(&answer.wireguard_public_key) {
            if let Ok(key_bytes) = peer_key.try_into() {
                self.wireguard.set_peer_public_key(key_bytes);
            }
        }

        self.state = ConnectionState::Connecting;
    }

    /// Create connection answer
    pub fn create_answer(&mut self) -> ConnectionAnswer {
        // Start gathering candidates
        self.ice_agent.gather_candidates();

        ConnectionAnswer {
            peer_id: self.local_id,
            ice_ufrag: self.ice_agent.local_ufrag().to_string(),
            ice_pwd: self.ice_agent.local_pwd().to_string(),
            candidates: self.ice_agent.local_candidates().to_vec(),
            wireguard_public_key: hex::encode(self.wireguard.public_key()),
        }
    }

    /// Sans-IO: poll for data to transmit
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        // Check for timeout
        if self.started_at.elapsed() > self.config.connection_timeout
            && self.state != ConnectionState::Connected
        {
            error!("Connection timeout after {:?}", self.started_at.elapsed());
            self.state = ConnectionState::Failed;
        }

        // Poll ICE agent for transmits
        if let Some(transmit) = self.ice_agent.poll_transmit() {
            return Some(transmit);
        }

        // Send keepalives if connected
        if self.state == ConnectionState::Connected
            && self.last_keepalive.elapsed() > self.config.keepalive_interval
        {
            self.send_keepalive();
            self.last_keepalive = Instant::now();
        }

        // Return queued transmits
        self.transmit_queue.pop_front()
    }

    /// Sans-IO: handle incoming packet
    pub fn handle_input(&mut self, data: &[u8], source: SocketAddr, now: Instant) {
        match self.state {
            ConnectionState::Gathering
            | ConnectionState::WaitingForRemote
            | ConnectionState::Connecting => {
                // Pass to ICE agent
                self.ice_agent.handle_input(data, source, now);

                // Check if ICE is now connected
                if self.ice_agent.is_connected() {
                    info!("ICE connected, starting WireGuard handshake");
                    self.state = ConnectionState::Handshaking;
                    self.initiate_wireguard_handshake();
                }
            }
            ConnectionState::Handshaking | ConnectionState::Connected => {
                // Try to decrypt with WireGuard
                match self.wireguard.decapsulate(data) {
                    Ok(plaintext) => {
                        if !plaintext.is_empty() {
                            debug!("Received {} bytes of decrypted data", plaintext.len());
                            self.recv_queue.push_back(plaintext);

                            if self.state == ConnectionState::Handshaking {
                                info!("WireGuard handshake complete");
                                self.state = ConnectionState::Connected;
                            }
                        }
                    }
                    Err(e) => {
                        // Might be ICE control message
                        self.ice_agent.handle_input(data, source, now);
                    }
                }
            }
            ConnectionState::Failed | ConnectionState::Closed => {
                // Ignore packets
            }
        }
    }

    /// Send data through the tunnel
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.state != ConnectionState::Connected {
            return Err(anyhow!("Connection not established"));
        }

        // Encrypt with WireGuard
        let encrypted = self.wireguard.encapsulate(data)?;

        // Get selected ICE candidate pair
        if let Some(destination) = self.ice_agent.selected_address() {
            self.transmit_queue.push_back(Transmit {
                destination,
                payload: encrypted,
            });
            Ok(())
        } else {
            Err(anyhow!("No ICE candidate selected"))
        }
    }

    /// Receive data from the tunnel
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.recv_queue.pop_front()
    }

    /// Check if connection is established
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get local peer ID
    pub fn local_id(&self) -> PeerId {
        self.local_id
    }

    /// Get remote peer ID
    pub fn remote_id(&self) -> PeerId {
        self.remote_id
    }

    /// Close the connection
    pub fn close(&mut self) {
        info!("Closing P2P connection");
        self.state = ConnectionState::Closed;
    }

    /// Send keepalive packet
    fn send_keepalive(&mut self) {
        debug!("Sending keepalive");
        let _ = self.send(b"");
    }

    /// Initiate WireGuard handshake
    fn initiate_wireguard_handshake(&mut self) {
        debug!("Initiating WireGuard handshake");

        // Send handshake initiation
        if let Ok(handshake) = self.wireguard.create_handshake_initiation() {
            if let Some(destination) = self.ice_agent.selected_address() {
                self.transmit_queue.push_back(Transmit {
                    destination,
                    payload: handshake,
                });
            }
        }
    }

    /// Get connection statistics
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            state: self.state,
            duration: self.started_at.elapsed(),
            bytes_sent: self.wireguard.bytes_sent(),
            bytes_received: self.wireguard.bytes_received(),
            selected_candidate: self.ice_agent.selected_candidate(),
        }
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub state: ConnectionState,
    pub duration: Duration,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub selected_candidate: Option<Candidate>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id() {
        let id1 = PeerId::new();
        let id2 = PeerId::new();
        assert_ne!(id1, id2);

        let id_str = id1.to_string();
        let id3 = PeerId::from_string(&id_str).unwrap();
        assert_eq!(id1, id3);
    }

    #[test]
    fn test_connection_lifecycle() {
        let config = P2PConfig::default();
        let relays = vec![];

        // Create initiator
        let remote_id = PeerId::new();
        let mut initiator = P2PConnection::initiate(remote_id, &relays, config.clone());

        // Create offer
        let offer = initiator.create_offer();
        assert_eq!(offer.peer_id, initiator.local_id());

        // Create responder
        let mut responder = P2PConnection::accept(offer, &relays, config);

        // Create answer
        let answer = responder.create_answer();

        // Apply answer
        initiator.apply_answer(answer);

        assert_eq!(initiator.state(), ConnectionState::Connecting);
    }
}
