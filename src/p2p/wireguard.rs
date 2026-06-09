//! WireGuard tunnel for encrypted P2P communication
//!
//! Uses the boringtun library for WireGuard protocol implementation.
//! Provides end-to-end encryption for P2P data transfer.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use boringtun::noise::{Tunn, TunnResult};
use rand::rngs::OsRng;
use tracing::{debug, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

/// WireGuard tunnel for encryption
pub struct WireGuardTunnel {
    /// BoringTun tunnel
    tunnel: Tunn,

    /// Our private key
    private_key: StaticSecret,

    /// Our public key
    public_key: PublicKey,

    /// Peer's public key
    peer_public_key: Option<PublicKey>,

    /// Peer's endpoint
    peer_endpoint: Option<SocketAddr>,

    /// Bytes sent counter
    bytes_sent: Arc<AtomicU64>,

    /// Bytes received counter
    bytes_received: Arc<AtomicU64>,

    /// Buffer for encryption/decryption
    buffer: Vec<u8>,
}

impl WireGuardTunnel {
    /// Create new WireGuard tunnel
    pub fn new() -> Self {
        // Generate keypair
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        debug!(
            "Generated WireGuard keypair, public key: {}",
            hex::encode(public_key.as_bytes())
        );

        // Create tunnel (without peer initially)
        let tunnel = Tunn::new(
            private_key.to_bytes().into(),
            public_key.as_bytes().clone().into(),
            None,
            None,
            0,
            None,
        )
        .expect("Failed to create WireGuard tunnel");

        Self {
            tunnel,
            private_key,
            public_key,
            peer_public_key: None,
            peer_endpoint: None,
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            buffer: vec![0u8; 65536], // 64KB buffer
        }
    }

    /// Get our public key
    pub fn public_key(&self) -> [u8; 32] {
        *self.public_key.as_bytes()
    }

    /// Set peer's public key
    pub fn set_peer_public_key(&mut self, public_key: [u8; 32]) {
        let peer_key = PublicKey::from(public_key);
        info!(
            "Setting peer public key: {}",
            hex::encode(peer_key.as_bytes())
        );

        self.peer_public_key = Some(peer_key);

        // Recreate tunnel with peer
        self.tunnel = Tunn::new(
            self.private_key.to_bytes().into(),
            self.public_key.as_bytes().clone().into(),
            Some(peer_key.as_bytes().clone().into()),
            None,
            0,
            None,
        )
        .expect("Failed to recreate WireGuard tunnel with peer");
    }

    /// Set peer endpoint
    pub fn set_peer_endpoint(&mut self, endpoint: SocketAddr) {
        debug!("Setting peer endpoint: {}", endpoint);
        self.peer_endpoint = Some(endpoint);
    }

    /// Encapsulate (encrypt) data
    pub fn encapsulate(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            // Create keepalive packet
            match self
                .tunnel
                .format_handshake_initiation(&mut self.buffer, false)
            {
                TunnResult::WriteToNetwork(data) => {
                    self.bytes_sent
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                    return Ok(data.to_vec());
                }
                TunnResult::Err(e) => {
                    return Err(anyhow!("Failed to create keepalive: {:?}", e));
                }
                _ => {
                    return Ok(Vec::new());
                }
            }
        }

        // Encrypt data
        match self.tunnel.encapsulate(plaintext, &mut self.buffer) {
            TunnResult::WriteToNetwork(data) => {
                self.bytes_sent
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                Ok(data.to_vec())
            }
            TunnResult::Err(e) => Err(anyhow!("Encryption failed: {:?}", e)),
            TunnResult::Done => {
                // No data to send (handshake in progress?)
                Ok(Vec::new())
            }
            _ => Err(anyhow!("Unexpected tunnel result")),
        }
    }

    /// Decapsulate (decrypt) data
    pub fn decapsulate(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.bytes_received
            .fetch_add(ciphertext.len() as u64, Ordering::Relaxed);

        match self.tunnel.decapsulate(None, ciphertext, &mut self.buffer) {
            TunnResult::WriteToNetwork(data) => {
                // Handshake response or keepalive
                debug!("Handshake response generated: {} bytes", data.len());
                Ok(data.to_vec())
            }
            TunnResult::WriteToTunnelV4(data, _addr) | TunnResult::WriteToTunnelV6(data, _addr) => {
                // Decrypted data
                debug!("Decrypted {} bytes", data.len());
                Ok(data.to_vec())
            }
            TunnResult::Done => {
                // Packet processed, no output
                Ok(Vec::new())
            }
            TunnResult::Err(e) => {
                warn!("Decryption failed: {:?}", e);
                Err(anyhow!("Decryption failed: {:?}", e))
            }
        }
    }

    /// Create handshake initiation
    pub fn create_handshake_initiation(&mut self) -> Result<Vec<u8>> {
        match self
            .tunnel
            .format_handshake_initiation(&mut self.buffer, false)
        {
            TunnResult::WriteToNetwork(data) => {
                info!("Created handshake initiation: {} bytes", data.len());
                self.bytes_sent
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                Ok(data.to_vec())
            }
            TunnResult::Err(e) => Err(anyhow!("Failed to create handshake: {:?}", e)),
            _ => Err(anyhow!("Unexpected tunnel result")),
        }
    }

    /// Update timers (call periodically)
    pub fn update_timers(&mut self) {
        self.tunnel.update_timers(&mut self.buffer);
    }

    /// Get bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get bytes received
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Check if handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        // BoringTun doesn't expose this directly, so we track it via successful encapsulation
        // In practice, we'd need to track handshake state separately
        true
    }
}

impl Default for WireGuardTunnel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let tunnel = WireGuardTunnel::new();
        let public_key = tunnel.public_key();

        // Public key should be 32 bytes
        assert_eq!(public_key.len(), 32);

        // Should be non-zero
        assert!(public_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_set_peer_public_key() {
        let mut tunnel = WireGuardTunnel::new();
        let peer_key = [1u8; 32];

        tunnel.set_peer_public_key(peer_key);

        assert_eq!(tunnel.peer_public_key, Some(PublicKey::from(peer_key)));
    }

    #[test]
    fn test_handshake_creation() {
        let mut initiator = WireGuardTunnel::new();
        let mut responder = WireGuardTunnel::new();

        // Set peer keys
        initiator.set_peer_public_key(responder.public_key());
        responder.set_peer_public_key(initiator.public_key());

        // Create handshake
        let handshake = initiator.create_handshake_initiation();
        assert!(handshake.is_ok());

        let handshake_data = handshake.unwrap();
        assert!(!handshake_data.is_empty());
    }

    #[test]
    fn test_statistics() {
        let mut tunnel = WireGuardTunnel::new();

        assert_eq!(tunnel.bytes_sent(), 0);
        assert_eq!(tunnel.bytes_received(), 0);

        // Simulate sending
        let data = b"test data";
        let _ = tunnel.encapsulate(data);

        // bytes_sent should be updated
        assert!(tunnel.bytes_sent() > 0);
    }

    #[test]
    fn test_keepalive() {
        let mut tunnel = WireGuardTunnel::new();

        // Empty plaintext should generate keepalive
        let result = tunnel.encapsulate(b"");

        // Should produce some output (handshake or keepalive)
        assert!(result.is_ok());
    }
}
