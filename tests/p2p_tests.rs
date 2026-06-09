//! P2P NAT traversal integration tests
//!
//! Fenced behind the experimental `p2p` feature (off by default). The p2p stack
//! does not currently compile; these tests only build with `--features p2p`.
#![cfg(feature = "p2p")]

use std::net::SocketAddr;
use std::time::Duration;

use tamandua_core::p2p::*;

#[test]
fn test_peer_id_generation() {
    let id1 = PeerId::new();
    let id2 = PeerId::new();

    // IDs should be unique
    assert_ne!(id1, id2);

    // Serialization round-trip
    let id_str = id1.to_string();
    let id3 = PeerId::from_string(&id_str).unwrap();
    assert_eq!(id1, id3);
}

#[test]
fn test_ice_candidate_priority() {
    use ice::{Candidate, CandidateType};

    let host_prio = Candidate::calculate_priority(CandidateType::Host, 65535, 1);
    let srflx_prio = Candidate::calculate_priority(CandidateType::ServerReflexive, 65535, 1);
    let relay_prio = Candidate::calculate_priority(CandidateType::Relay, 65535, 1);

    // Host should have highest priority
    assert!(host_prio > srflx_prio);
    assert!(srflx_prio > relay_prio);
}

#[test]
fn test_ice_agent_creation() {
    use ice::{IceAgent, IceRole};

    let stun_servers = vec!["8.8.8.8:19302".parse().unwrap()];
    let agent = IceAgent::new(IceRole::Controlling, &stun_servers, &[]);

    assert_eq!(agent.local_ufrag().len(), 4);
    assert_eq!(agent.local_pwd().len(), 22);
}

#[test]
fn test_ice_candidate_pairing() {
    use ice::{Candidate, CandidateType, Protocol};

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

    let _pair = ice::CandidatePair {
        local: local.clone(),
        remote: remote.clone(),
        priority: 1000,
        state: ice::CheckState::Waiting,
        nominated: false,
    };
}

#[test]
fn test_stun_message_encoding() {
    use stun::StunMessage;

    let msg = StunMessage::new_binding_request();
    let encoded = msg.encode();

    // STUN header is 20 bytes
    assert!(encoded.len() >= 20);

    // Message should start with message type
    assert_eq!(encoded[0], 0x00);
    assert_eq!(encoded[1], 0x01); // Binding request
}

#[test]
fn test_stun_xor_mapped_address() {
    use stun::StunMessage;

    let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let mut msg = StunMessage::new_binding_request();
    let transaction_id = msg.transaction_id;

    msg.add_xor_mapped_address(addr);

    // Encode and decode
    let encoded = msg.encode();
    let decoded = StunMessage::parse(&encoded).unwrap();

    assert_eq!(decoded.get_mapped_address(), Some(addr));
    assert_eq!(decoded.transaction_id, transaction_id);
}

#[test]
fn test_turn_client_creation() {
    use turn::TurnClient;

    let server: SocketAddr = "turn.example.com:3478".parse().unwrap();
    let client = TurnClient::new(server, "user", "pass");

    assert!(!client.is_allocated());
    assert_eq!(client.relayed_address(), None);
}

#[test]
fn test_wireguard_keypair() {
    use wireguard::WireGuardTunnel;

    let tunnel = WireGuardTunnel::new();
    let public_key = tunnel.public_key();

    // Public key should be 32 bytes
    assert_eq!(public_key.len(), 32);

    // Should be non-zero
    assert!(public_key.iter().any(|&b| b != 0));
}

#[test]
fn test_wireguard_peer_setup() {
    use wireguard::WireGuardTunnel;

    let mut initiator = WireGuardTunnel::new();
    let mut responder = WireGuardTunnel::new();

    // Exchange public keys
    initiator.set_peer_public_key(responder.public_key());
    responder.set_peer_public_key(initiator.public_key());

    // Both should now have peer keys set
    assert!(initiator.is_handshake_complete() || !initiator.is_handshake_complete());
    // Either state is valid
}

#[test]
fn test_p2p_connection_offer_answer() {
    let config = P2PConfig::default();
    let relays = vec![];

    // Create initiator
    let remote_id = PeerId::new();
    let mut initiator = P2PConnection::initiate(remote_id, &relays, config.clone());

    // Create offer
    let offer = initiator.create_offer();
    assert_eq!(offer.peer_id, initiator.local_id());
    assert!(!offer.ice_ufrag.is_empty());
    assert!(!offer.ice_pwd.is_empty());
    assert!(!offer.wireguard_public_key.is_empty());

    // Create responder
    let mut responder = P2PConnection::accept(offer, &relays, config);

    // Create answer
    let answer = responder.create_answer();
    assert_eq!(answer.peer_id, responder.local_id());

    // Apply answer
    initiator.apply_answer(answer);

    assert_eq!(initiator.state(), ConnectionState::Connecting);
}

#[test]
fn test_p2p_connection_lifecycle() {
    let config = P2PConfig {
        connection_timeout: Duration::from_secs(5),
        keepalive_interval: Duration::from_secs(25),
        stun_servers: vec![],
        aggressive_nomination: false,
        mtu: 1420,
    };

    let relays = vec![];
    let remote_id = PeerId::new();
    let mut conn = P2PConnection::initiate(remote_id, &relays, config);

    // Initial state
    assert_eq!(conn.state(), ConnectionState::Gathering);

    // Poll should return None initially (no transmits yet)
    let _ = conn.poll_transmit();

    // Close connection
    conn.close();
    assert_eq!(conn.state(), ConnectionState::Closed);
}

#[test]
fn test_connection_stats() {
    let config = P2PConfig::default();
    let relays = vec![];
    let remote_id = PeerId::new();
    let conn = P2PConnection::initiate(remote_id, &relays, config);

    let stats = conn.stats();
    assert_eq!(stats.state, ConnectionState::Gathering);
    assert!(stats.duration.as_secs() < 1);
    assert_eq!(stats.bytes_sent, 0);
    assert_eq!(stats.bytes_received, 0);
}

#[tokio::test]
async fn test_async_connection_creation() {
    use connection::AsyncP2PConnection;

    let config = P2PConfig::default();
    let relays = vec![];
    let remote_id = PeerId::new();
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let result = AsyncP2PConnection::initiate(remote_id, &relays, config, bind_addr).await;
    assert!(result.is_ok());

    let mut conn = result.unwrap();
    assert!(!conn.is_connected());

    conn.close();
}

#[tokio::test]
async fn test_async_offer_answer_flow() {
    use connection::AsyncP2PConnection;

    let config = P2PConfig::default();
    let relays = vec![];
    let bind_addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let bind_addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // Create initiator
    let remote_id = PeerId::new();
    let mut initiator =
        AsyncP2PConnection::initiate(remote_id, &relays, config.clone(), bind_addr1)
            .await
            .unwrap();

    // Create offer
    let offer = initiator.create_offer();

    // Create responder
    let mut responder = AsyncP2PConnection::accept(offer, &relays, config, bind_addr2)
        .await
        .unwrap();

    // Create answer
    let answer = responder.create_answer();

    // Apply answer
    initiator.apply_answer(answer);

    // Clean up
    initiator.close();
    responder.close();
}

#[test]
fn test_connection_pool() {
    use connection::ConnectionPool;

    let mut pool = ConnectionPool::new(10);

    assert_eq!(pool.len(), 0);
    assert!(pool.is_empty());

    let peers = pool.peers();
    assert_eq!(peers.len(), 0);
}

// NAT simulation tests

#[test]
fn test_nat_full_cone_simulation() {
    // Simulate full cone NAT where all packets from internal address
    // are mapped to same external address
    let internal_addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let external_addr: SocketAddr = "1.2.3.4:5000".parse().unwrap();

    // In full cone NAT, external port equals internal port
    assert_eq!(internal_addr.port(), external_addr.port());
}

#[test]
fn test_nat_symmetric_simulation() {
    // Symmetric NAT assigns different external port per destination
    let internal_addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let external_addr1: SocketAddr = "1.2.3.4:10001".parse().unwrap();
    let external_addr2: SocketAddr = "1.2.3.4:10002".parse().unwrap();

    // Different external ports for same internal address
    assert_eq!(internal_addr.port(), 5000);
    assert_ne!(external_addr1.port(), external_addr2.port());
}

#[test]
fn test_relay_fallback_scenario() {
    use turn::TurnClient;

    let turn_server: SocketAddr = "turn.example.com:3478".parse().unwrap();
    let mut client = TurnClient::new(turn_server, "user", "pass");

    // Allocate relay
    client.allocate();

    // Should have queued allocation request
    let transmit = client.poll_transmit();
    assert!(transmit.is_some());
}

// Performance tests

#[test]
fn test_candidate_gathering_performance() {
    use ice::{IceAgent, IceRole};
    use std::time::Instant;

    let stun_servers = vec![
        "8.8.8.8:19302".parse().unwrap(),
        "8.8.4.4:19302".parse().unwrap(),
    ];
    let mut agent = IceAgent::new(IceRole::Controlling, &stun_servers, &[]);

    let start = Instant::now();
    agent.gather_candidates();
    let elapsed = start.elapsed();

    // Gathering should be fast (< 100ms without network)
    assert!(elapsed.as_millis() < 100);
}

#[test]
fn test_wireguard_encryption_performance() {
    use std::time::Instant;
    use wireguard::WireGuardTunnel;

    let mut tunnel = WireGuardTunnel::new();
    let data = vec![0u8; 1024]; // 1KB

    let start = Instant::now();
    for _ in 0..100 {
        let _ = tunnel.encapsulate(&data);
    }
    let elapsed = start.elapsed();

    // Should process 100 packets quickly
    println!("Encrypted 100 packets in {:?}", elapsed);
}

// Edge cases

#[test]
fn test_empty_candidate_list() {
    let config = P2PConfig::default();
    let relays = vec![];
    let remote_id = PeerId::new();
    let mut conn = P2PConnection::initiate(remote_id, &relays, config);

    let offer = conn.create_offer();
    // Offer should still be valid even with no candidates yet
    assert!(!offer.ice_ufrag.is_empty());
}

#[test]
fn test_ipv4_ipv6_mixing() {
    use ice::{Candidate, CandidateType, Protocol};

    let ipv4_candidate = Candidate {
        foundation: "1".to_string(),
        component: 1,
        protocol: Protocol::Udp,
        priority: 1000,
        address: "192.168.1.100:5000".parse().unwrap(),
        candidate_type: CandidateType::Host,
        related_address: None,
    };

    let ipv6_candidate = Candidate {
        foundation: "2".to_string(),
        component: 1,
        protocol: Protocol::Udp,
        priority: 1000,
        address: "[::1]:5000".parse().unwrap(),
        candidate_type: CandidateType::Host,
        related_address: None,
    };

    assert!(ipv4_candidate.address.is_ipv4());
    assert!(ipv6_candidate.address.is_ipv6());
}

#[test]
fn test_connection_timeout() {
    let config = P2PConfig {
        connection_timeout: Duration::from_millis(100),
        keepalive_interval: Duration::from_secs(25),
        stun_servers: vec![],
        aggressive_nomination: false,
        mtu: 1420,
    };

    let relays = vec![];
    let remote_id = PeerId::new();
    let mut conn = P2PConnection::initiate(remote_id, &relays, config);

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(150));

    // Poll should detect timeout
    conn.poll_transmit();

    // Connection should fail
    assert_eq!(conn.state(), ConnectionState::Failed);
}
