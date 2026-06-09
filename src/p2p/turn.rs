//! TURN (Traversal Using Relays around NAT) Implementation
//! Based on RFC 5766
//!
//! TURN provides relay functionality when direct P2P connection fails.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use super::stun::{AttributeType, StunMessage};
use super::Transmit;

/// TURN allocation lifetime (RFC 5766 default)
const DEFAULT_LIFETIME: Duration = Duration::from_secs(600); // 10 minutes

/// TURN client state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnState {
    /// Initial state
    Idle,

    /// Allocating relay
    Allocating,

    /// Allocation successful
    Allocated,

    /// Allocation failed
    Failed,

    /// Refreshing allocation
    Refreshing,
}

/// TURN client for relay fallback
pub struct TurnClient {
    /// TURN server address
    server: SocketAddr,

    /// Username for authentication
    username: String,

    /// Password for authentication
    password: String,

    /// Current state
    state: TurnState,

    /// Allocated relay address
    relayed_address: Option<SocketAddr>,

    /// Allocation lifetime
    lifetime: Duration,

    /// Last allocation time
    allocated_at: Option<Instant>,

    /// Channel bindings (peer -> channel number)
    channels: HashMap<SocketAddr, u16>,

    /// Next channel number to allocate
    next_channel: u16,

    /// Outbound transmit queue
    transmit_queue: VecDeque<Transmit>,

    /// Pending transaction IDs
    pending_transactions: HashMap<[u8; 12], TransactionType>,
}

#[derive(Debug, Clone, Copy)]
enum TransactionType {
    Allocate,
    Refresh,
    ChannelBind,
    CreatePermission,
}

impl TurnClient {
    /// Create new TURN client
    pub fn new(server: SocketAddr, username: &str, password: &str) -> Self {
        Self {
            server,
            username: username.to_string(),
            password: password.to_string(),
            state: TurnState::Idle,
            relayed_address: None,
            lifetime: DEFAULT_LIFETIME,
            allocated_at: None,
            channels: HashMap::new(),
            next_channel: 0x4000, // Channel numbers start at 0x4000
            transmit_queue: VecDeque::new(),
            pending_transactions: HashMap::new(),
        }
    }

    /// Allocate relay
    pub fn allocate(&mut self) {
        if self.state != TurnState::Idle {
            return;
        }

        info!("Allocating TURN relay at {}", self.server);
        self.state = TurnState::Allocating;

        let msg = self.create_allocate_request();
        let transaction_id = msg.transaction_id;

        self.transmit_queue.push_back(Transmit {
            destination: self.server,
            payload: msg.encode(),
        });

        self.pending_transactions
            .insert(transaction_id, TransactionType::Allocate);
    }

    /// Refresh allocation
    pub fn refresh(&mut self) {
        if self.state != TurnState::Allocated {
            return;
        }

        debug!("Refreshing TURN allocation");
        self.state = TurnState::Refreshing;

        let msg = self.create_refresh_request();
        let transaction_id = msg.transaction_id;

        self.transmit_queue.push_back(Transmit {
            destination: self.server,
            payload: msg.encode(),
        });

        self.pending_transactions
            .insert(transaction_id, TransactionType::Refresh);
    }

    /// Bind channel to peer
    pub fn bind_channel(&mut self, peer: SocketAddr) -> Option<u16> {
        if self.state != TurnState::Allocated {
            return None;
        }

        // Check if already bound
        if let Some(channel) = self.channels.get(&peer) {
            return Some(*channel);
        }

        let channel_number = self.next_channel;
        self.next_channel += 1;

        debug!("Binding TURN channel {} to peer {}", channel_number, peer);

        let msg = self.create_channel_bind_request(channel_number, peer);
        let transaction_id = msg.transaction_id;

        self.transmit_queue.push_back(Transmit {
            destination: self.server,
            payload: msg.encode(),
        });

        self.pending_transactions
            .insert(transaction_id, TransactionType::ChannelBind);
        self.channels.insert(peer, channel_number);

        Some(channel_number)
    }

    /// Send data to peer via relay
    pub fn send_to(&mut self, data: &[u8], peer: SocketAddr) {
        if self.state != TurnState::Allocated {
            return;
        }

        // Use channel data if bound
        if let Some(channel) = self.channels.get(&peer) {
            let packet = self.create_channel_data(*channel, data);
            self.transmit_queue.push_back(Transmit {
                destination: self.server,
                payload: packet,
            });
        } else {
            // Use Send indication
            let msg = self.create_send_indication(peer, data);
            self.transmit_queue.push_back(Transmit {
                destination: self.server,
                payload: msg.encode(),
            });
        }
    }

    /// Poll for data to transmit
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        // Check if we need to refresh
        if self.state == TurnState::Allocated {
            if let Some(allocated_at) = self.allocated_at {
                let refresh_time = self.lifetime.mul_f32(0.8); // Refresh at 80% of lifetime
                if allocated_at.elapsed() > refresh_time {
                    self.refresh();
                }
            }
        }

        self.transmit_queue.pop_front()
    }

    /// Handle incoming packet
    pub fn handle_input(&mut self, data: &[u8], source: SocketAddr) {
        // Try to parse as STUN message
        if let Ok(msg) = StunMessage::parse(data) {
            self.handle_stun_message(msg, source);
            return;
        }

        // Try to parse as channel data
        if data.len() >= 4 {
            let channel_number = u16::from_be_bytes([data[0], data[1]]);
            if channel_number >= 0x4000 && channel_number <= 0x7FFF {
                let length = u16::from_be_bytes([data[2], data[3]]) as usize;
                if data.len() >= 4 + length {
                    let channel_data = &data[4..4 + length];
                    self.handle_channel_data(channel_number, channel_data);
                }
            }
        }
    }

    /// Get relayed address
    pub fn relayed_address(&self) -> Option<SocketAddr> {
        self.relayed_address
    }

    /// Check if allocated
    pub fn is_allocated(&self) -> bool {
        self.state == TurnState::Allocated
    }

    // Private methods

    fn create_allocate_request(&self) -> StunMessage {
        let mut msg = StunMessage::new_binding_request();
        // In real implementation, add:
        // - REQUESTED-TRANSPORT attribute (UDP = 17)
        // - USERNAME attribute
        // - MESSAGE-INTEGRITY attribute
        msg
    }

    fn create_refresh_request(&self) -> StunMessage {
        let mut msg = StunMessage::new_binding_request();
        // In real implementation, add:
        // - LIFETIME attribute
        // - USERNAME attribute
        // - MESSAGE-INTEGRITY attribute
        msg
    }

    fn create_channel_bind_request(&self, channel: u16, peer: SocketAddr) -> StunMessage {
        let mut msg = StunMessage::new_binding_request();
        // In real implementation, add:
        // - CHANNEL-NUMBER attribute
        // - XOR-PEER-ADDRESS attribute
        // - USERNAME attribute
        // - MESSAGE-INTEGRITY attribute
        msg
    }

    fn create_send_indication(&self, peer: SocketAddr, data: &[u8]) -> StunMessage {
        let mut msg = StunMessage::new_binding_request();
        // In real implementation, add:
        // - XOR-PEER-ADDRESS attribute
        // - DATA attribute
        msg
    }

    fn create_channel_data(&self, channel: u16, data: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();

        // Channel number (2 bytes)
        packet.extend_from_slice(&channel.to_be_bytes());

        // Length (2 bytes)
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());

        // Data
        packet.extend_from_slice(data);

        // Padding to 4-byte boundary
        let padding = (4 - (data.len() % 4)) % 4;
        packet.resize(packet.len() + padding, 0);

        packet
    }

    fn handle_stun_message(&mut self, msg: StunMessage, source: SocketAddr) {
        if let Some(tx_type) = self.pending_transactions.remove(&msg.transaction_id) {
            match tx_type {
                TransactionType::Allocate => {
                    self.handle_allocate_response(msg);
                }
                TransactionType::Refresh => {
                    self.handle_refresh_response(msg);
                }
                TransactionType::ChannelBind => {
                    debug!("Channel bind successful");
                }
                TransactionType::CreatePermission => {
                    debug!("Permission created");
                }
            }
        }
    }

    fn handle_allocate_response(&mut self, msg: StunMessage) {
        // Extract relayed address from XOR-RELAYED-ADDRESS attribute
        if let Some(addr) = msg.get_mapped_address() {
            info!("TURN allocation successful: {}", addr);
            self.relayed_address = Some(addr);
            self.state = TurnState::Allocated;
            self.allocated_at = Some(Instant::now());
        } else {
            warn!("TURN allocation failed");
            self.state = TurnState::Failed;
        }
    }

    fn handle_refresh_response(&mut self, msg: StunMessage) {
        debug!("TURN allocation refreshed");
        self.state = TurnState::Allocated;
        self.allocated_at = Some(Instant::now());
    }

    fn handle_channel_data(&mut self, channel: u16, data: &[u8]) {
        // Find peer for this channel
        for (peer, ch) in &self.channels {
            if *ch == channel {
                debug!(
                    "Received {} bytes from peer {} via channel {}",
                    data.len(),
                    peer,
                    channel
                );
                // In real implementation, pass data to application
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_turn_client_creation() {
        let server: SocketAddr = "turn.example.com:3478".parse().unwrap();
        let client = TurnClient::new(server, "user", "pass");

        assert_eq!(client.state, TurnState::Idle);
        assert_eq!(client.server, server);
    }

    #[test]
    fn test_channel_binding() {
        let server: SocketAddr = "turn.example.com:3478".parse().unwrap();
        let mut client = TurnClient::new(server, "user", "pass");

        // Simulate successful allocation
        client.state = TurnState::Allocated;
        client.relayed_address = Some("1.2.3.4:5000".parse().unwrap());
        client.allocated_at = Some(Instant::now());

        let peer: SocketAddr = "192.168.1.100:6000".parse().unwrap();
        let channel = client.bind_channel(peer);

        assert!(channel.is_some());
        assert!(client.channels.contains_key(&peer));
    }

    #[test]
    fn test_channel_data_encoding() {
        let server: SocketAddr = "turn.example.com:3478".parse().unwrap();
        let client = TurnClient::new(server, "user", "pass");

        let data = b"Hello, world!";
        let packet = client.create_channel_data(0x4000, data);

        // Check structure
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), 0x4000);
        assert_eq!(
            u16::from_be_bytes([packet[2], packet[3]]),
            data.len() as u16
        );
        assert_eq!(&packet[4..4 + data.len()], data);

        // Check padding
        assert_eq!(packet.len() % 4, 0);
    }
}
