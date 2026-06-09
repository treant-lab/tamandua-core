//! ICE (Interactive Connectivity Establishment) Implementation
//! Based on RFC 8445
//!
//! ICE is used to establish peer-to-peer connections through NATs and firewalls.
//! It works by:
//! 1. Gathering local candidates (host, server-reflexive, relay)
//! 2. Exchanging candidates with remote peer via signaling
//! 3. Performing connectivity checks on candidate pairs
//! 4. Selecting the best working pair

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::{RelayServer, Transmit};
use crate::p2p::stun;
use crate::p2p::turn;

/// ICE agent role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// Controlling agent (initiator)
    Controlling,
    /// Controlled agent (responder)
    Controlled,
}

/// ICE agent state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    Gathering,
    Checking,
    Connected,
    Failed,
}

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Udp,
}

/// Candidate type (RFC 8445 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateType {
    /// Host candidate (local interface)
    Host,
    /// Server reflexive candidate (via STUN)
    ServerReflexive,
    /// Peer reflexive candidate (discovered during checks)
    PeerReflexive,
    /// Relay candidate (via TURN)
    Relay,
}

/// ICE candidate (RFC 8445 Section 5.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    /// Foundation (groups candidates from same interface)
    pub foundation: String,

    /// Component ID (1 = RTP, 2 = RTCP, for us always 1)
    pub component: u32,

    /// Transport protocol
    pub protocol: Protocol,

    /// Priority (higher = preferred)
    pub priority: u32,

    /// Candidate address
    pub address: SocketAddr,

    /// Candidate type
    pub candidate_type: CandidateType,

    /// Related address (for srflx/relay)
    pub related_address: Option<SocketAddr>,
}

impl Candidate {
    /// Calculate priority (RFC 8445 Section 5.1.2.1)
    pub fn calculate_priority(
        candidate_type: CandidateType,
        local_pref: u32,
        component: u32,
    ) -> u32 {
        let type_pref = match candidate_type {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        };

        (type_pref << 24) | (local_pref << 8) | (256 - component)
    }

    /// Generate foundation (groups candidates)
    fn generate_foundation(
        candidate_type: CandidateType,
        base_addr: SocketAddr,
        server: Option<SocketAddr>,
    ) -> String {
        use blake2::{Blake2b512, Digest};

        let mut hasher = Blake2b512::new();
        hasher.update(&[candidate_type as u8]);
        hasher.update(base_addr.to_string().as_bytes());
        if let Some(srv) = server {
            hasher.update(srv.to_string().as_bytes());
        }
        let result = hasher.finalize();
        hex::encode(&result[..4])
    }
}

/// Candidate pair for connectivity checks
#[derive(Debug, Clone)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
    pub priority: u64,
    pub state: CheckState,
    pub nominated: bool,
}

impl CandidatePair {
    /// Calculate pair priority (RFC 8445 Section 6.1.2.3)
    fn calculate_priority(local: &Candidate, remote: &Candidate, is_controlling: bool) -> u64 {
        let g = if is_controlling {
            local.priority
        } else {
            remote.priority
        };
        let d = if is_controlling {
            remote.priority
        } else {
            local.priority
        };

        (1u64 << 32) * g.min(d) as u64 + 2 * g.max(d) as u64 + (if g > d { 1 } else { 0 })
    }
}

/// Connectivity check state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
}

/// ICE agent for NAT traversal
pub struct IceAgent {
    /// Agent role
    role: IceRole,

    /// Current state
    state: IceState,

    /// Local ICE username fragment
    local_ufrag: String,

    /// Local ICE password
    local_pwd: String,

    /// Remote ICE username fragment
    remote_ufrag: Option<String>,

    /// Remote ICE password
    remote_pwd: Option<String>,

    /// Local candidates
    local_candidates: Vec<Candidate>,

    /// Remote candidates
    remote_candidates: Vec<Candidate>,

    /// Candidate pairs for connectivity checks
    candidate_pairs: Vec<CandidatePair>,

    /// Selected (nominated) pair
    selected_pair: Option<CandidatePair>,

    /// STUN servers for gathering
    stun_servers: Vec<SocketAddr>,

    /// TURN relays
    turn_relays: Vec<RelayServer>,

    /// STUN client for gathering
    stun_client: stun::StunClient,

    /// TURN clients
    turn_clients: Vec<turn::TurnClient>,

    /// Last check time
    last_check: Instant,

    /// Check interval
    check_interval: Duration,

    /// Transaction IDs for pending checks
    pending_checks: HashMap<[u8; 12], SocketAddr>,
}

impl IceAgent {
    /// Create new ICE agent
    pub fn new(role: IceRole, stun_servers: &[SocketAddr], turn_relays: &[RelayServer]) -> Self {
        let local_ufrag = Self::generate_ice_string(4);
        let local_pwd = Self::generate_ice_string(22);

        Self {
            role,
            state: IceState::Gathering,
            local_ufrag,
            local_pwd,
            remote_ufrag: None,
            remote_pwd: None,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            candidate_pairs: Vec::new(),
            selected_pair: None,
            stun_servers: stun_servers.to_vec(),
            turn_relays: turn_relays.to_vec(),
            stun_client: stun::StunClient::new(),
            turn_clients: Vec::new(),
            last_check: Instant::now(),
            check_interval: Duration::from_millis(50),
            pending_checks: HashMap::new(),
        }
    }

    /// Get local ICE username fragment
    pub fn local_ufrag(&self) -> &str {
        &self.local_ufrag
    }

    /// Get local ICE password
    pub fn local_pwd(&self) -> &str {
        &self.local_pwd
    }

    /// Get local candidates
    pub fn local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    /// Set remote ICE credentials
    pub fn set_remote_credentials(&mut self, ufrag: &str, pwd: &str) {
        self.remote_ufrag = Some(ufrag.to_string());
        self.remote_pwd = Some(pwd.to_string());
    }

    /// Add remote candidate
    pub fn add_remote_candidate(&mut self, candidate: Candidate) {
        debug!("Adding remote candidate: {:?}", candidate);
        self.remote_candidates.push(candidate.clone());

        // Form candidate pairs with all local candidates
        for local in &self.local_candidates {
            self.add_candidate_pair(local.clone(), candidate.clone());
        }
    }

    /// Gather local candidates
    pub fn gather_candidates(&mut self) {
        info!("Gathering ICE candidates");

        // 1. Gather host candidates (local interfaces)
        self.gather_host_candidates();

        // 2. Gather server-reflexive candidates (via STUN)
        self.gather_server_reflexive_candidates();

        // 3. Gather relay candidates (via TURN)
        self.gather_relay_candidates();

        info!("Gathered {} local candidates", self.local_candidates.len());
    }

    /// Poll for data to transmit
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        // Perform connectivity checks
        if self.state == IceState::Checking && self.last_check.elapsed() > self.check_interval {
            self.perform_connectivity_checks();
            self.last_check = Instant::now();
        }

        // Poll STUN client
        if let Some(transmit) = self.stun_client.poll_transmit() {
            return Some(transmit);
        }

        // Poll TURN clients
        for client in &mut self.turn_clients {
            if let Some(transmit) = client.poll_transmit() {
                return Some(transmit);
            }
        }

        None
    }

    /// Handle incoming packet
    pub fn handle_input(&mut self, data: &[u8], source: SocketAddr, now: Instant) {
        // Try to parse as STUN message
        if let Ok(msg) = stun::StunMessage::parse(data) {
            self.handle_stun_message(msg, source, now);
        }
    }

    /// Check if ICE is connected
    pub fn is_connected(&self) -> bool {
        self.state == IceState::Connected
    }

    /// Get selected address
    pub fn selected_address(&self) -> Option<SocketAddr> {
        self.selected_pair.as_ref().map(|p| p.remote.address)
    }

    /// Get selected candidate
    pub fn selected_candidate(&self) -> Option<Candidate> {
        self.selected_pair.as_ref().map(|p| p.remote.clone())
    }

    // Private methods

    fn gather_host_candidates(&mut self) {
        // Get local network interfaces
        if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
            for (name, ip) in interfaces {
                // Skip loopback
                if ip.is_loopback() {
                    continue;
                }

                let addr = SocketAddr::new(ip, 0); // Port will be bound later

                let foundation = Candidate::generate_foundation(CandidateType::Host, addr, None);

                let candidate = Candidate {
                    foundation,
                    component: 1,
                    protocol: Protocol::Udp,
                    priority: Candidate::calculate_priority(CandidateType::Host, 65535, 1),
                    address: addr,
                    candidate_type: CandidateType::Host,
                    related_address: None,
                };

                debug!("Host candidate: {} on {}", addr, name);
                self.local_candidates.push(candidate);
            }
        }
    }

    fn gather_server_reflexive_candidates(&mut self) {
        // Query STUN servers to discover public address
        for stun_server in &self.stun_servers {
            self.stun_client.send_binding_request(*stun_server);
        }
    }

    fn gather_relay_candidates(&mut self) {
        // Allocate TURN relays
        for relay in &self.turn_relays {
            let client = turn::TurnClient::new(relay.address, &relay.username, &relay.password);
            self.turn_clients.push(client);
        }
    }

    fn add_candidate_pair(&mut self, local: Candidate, remote: Candidate) {
        // Skip pairs with incompatible address families
        if local.address.is_ipv4() != remote.address.is_ipv4() {
            return;
        }

        let priority =
            CandidatePair::calculate_priority(&local, &remote, self.role == IceRole::Controlling);

        let pair = CandidatePair {
            local,
            remote,
            priority,
            state: CheckState::Waiting,
            nominated: false,
        };

        self.candidate_pairs.push(pair);

        // Sort by priority (highest first)
        self.candidate_pairs
            .sort_by(|a, b| b.priority.cmp(&a.priority));

        // Transition to checking state
        if self.state == IceState::Gathering {
            self.state = IceState::Checking;
        }
    }

    fn perform_connectivity_checks(&mut self) {
        // Find next pair to check
        let pair_to_check = self
            .candidate_pairs
            .iter_mut()
            .find(|p| p.state == CheckState::Waiting || p.state == CheckState::InProgress);

        if let Some(pair) = pair_to_check {
            if pair.state == CheckState::Waiting {
                debug!(
                    "Checking pair: {:?} -> {:?}",
                    pair.local.address, pair.remote.address
                );

                // Send STUN binding request
                let transaction_id = self.stun_client.send_binding_request(pair.remote.address);
                self.pending_checks
                    .insert(transaction_id, pair.remote.address);

                pair.state = CheckState::InProgress;
            }
        }
    }

    fn handle_stun_message(&mut self, msg: stun::StunMessage, source: SocketAddr, now: Instant) {
        match msg.message_type {
            stun::MessageType::BindingRequest => {
                self.handle_binding_request(msg, source);
            }
            stun::MessageType::BindingSuccessResponse => {
                self.handle_binding_response(msg, source);
            }
            stun::MessageType::BindingErrorResponse => {
                warn!("Binding error from {}: {:?}", source, msg);
            }
            _ => {}
        }
    }

    fn handle_binding_request(&mut self, msg: stun::StunMessage, source: SocketAddr) {
        debug!("Received binding request from {}", source);

        // Send binding response
        let response = self.stun_client.create_binding_response(&msg, source);
        // Response will be sent via poll_transmit
    }

    fn handle_binding_response(&mut self, msg: stun::StunMessage, source: SocketAddr) {
        debug!("Received binding response from {}", source);

        // Check if this was a pending check
        if let Some(addr) = self.pending_checks.remove(&msg.transaction_id) {
            // Find the pair index first
            let pair_idx = self
                .candidate_pairs
                .iter()
                .position(|p| p.remote.address == addr);

            if let Some(idx) = pair_idx {
                // Mark pair as succeeded
                self.candidate_pairs[idx].state = CheckState::Succeeded;

                // Nominate this pair if controlling
                if self.role == IceRole::Controlling {
                    let pair = self.candidate_pairs[idx].clone();
                    self.nominate_pair_by_value(pair);
                }
            }
        }

        // Check if this is a server-reflexive address discovery
        if let Some(mapped_addr) = msg.get_mapped_address() {
            self.add_server_reflexive_candidate(mapped_addr, source);
        }
    }

    fn add_server_reflexive_candidate(&mut self, mapped_addr: SocketAddr, stun_server: SocketAddr) {
        // Check if we already have this candidate
        if self
            .local_candidates
            .iter()
            .any(|c| c.address == mapped_addr)
        {
            return;
        }

        let foundation = Candidate::generate_foundation(
            CandidateType::ServerReflexive,
            mapped_addr,
            Some(stun_server),
        );

        let candidate = Candidate {
            foundation,
            component: 1,
            protocol: Protocol::Udp,
            priority: Candidate::calculate_priority(CandidateType::ServerReflexive, 65535, 1),
            address: mapped_addr,
            candidate_type: CandidateType::ServerReflexive,
            related_address: None, // Would be local address if we tracked it
        };

        debug!("Server-reflexive candidate: {}", mapped_addr);
        self.local_candidates.push(candidate.clone());

        // Form pairs with remote candidates
        for remote in self.remote_candidates.clone() {
            self.add_candidate_pair(candidate.clone(), remote);
        }
    }

    fn nominate_pair(&mut self, pair: &mut CandidatePair) {
        info!(
            "Nominating pair: {:?} -> {:?}",
            pair.local.address, pair.remote.address
        );
        pair.nominated = true;
        self.selected_pair = Some(pair.clone());
        self.state = IceState::Connected;
    }

    fn nominate_pair_by_value(&mut self, mut pair: CandidatePair) {
        info!(
            "Nominating pair: {:?} -> {:?}",
            pair.local.address, pair.remote.address
        );
        pair.nominated = true;
        self.selected_pair = Some(pair.clone());
        self.state = IceState::Connected;
    }

    fn generate_ice_string(len: usize) -> String {
        use rand::distributions::Alphanumeric;
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .map(char::from)
            .collect()
    }
}

// Mock local_ip_address for now
mod local_ip_address {
    use std::net::IpAddr;

    pub fn list_afinet_netifas() -> Result<Vec<(String, IpAddr)>, ()> {
        // In a real implementation, this would enumerate network interfaces
        // For now, return localhost
        Ok(vec![("lo".to_string(), "127.0.0.1".parse().unwrap())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_priority() {
        let host_prio = Candidate::calculate_priority(CandidateType::Host, 65535, 1);
        let srflx_prio = Candidate::calculate_priority(CandidateType::ServerReflexive, 65535, 1);
        let relay_prio = Candidate::calculate_priority(CandidateType::Relay, 65535, 1);

        assert!(host_prio > srflx_prio);
        assert!(srflx_prio > relay_prio);
    }

    #[test]
    fn test_ice_agent_creation() {
        let stun_servers = vec!["8.8.8.8:19302".parse().unwrap()];
        let agent = IceAgent::new(IceRole::Controlling, &stun_servers, &[]);

        assert_eq!(agent.role, IceRole::Controlling);
        assert_eq!(agent.state, IceState::Gathering);
        assert_eq!(agent.local_ufrag.len(), 4);
        assert_eq!(agent.local_pwd.len(), 22);
    }

    #[test]
    fn test_candidate_pairing() {
        let local = Candidate {
            foundation: "1".to_string(),
            component: 1,
            protocol: Protocol::Udp,
            priority: 1000,
            address: "192.168.1.100:5000".parse().unwrap(),
            candidate_type: CandidateType::Host,
            related_address: None,
        };

        let remote = Candidate {
            foundation: "2".to_string(),
            component: 1,
            protocol: Protocol::Udp,
            priority: 2000,
            address: "192.168.1.200:5000".parse().unwrap(),
            candidate_type: CandidateType::Host,
            related_address: None,
        };

        let priority = CandidatePair::calculate_priority(&local, &remote, true);
        assert!(priority > 0);
    }
}
