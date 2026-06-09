//! STUN (Session Traversal Utilities for NAT) Implementation
//! Based on RFC 5389
//!
//! STUN is used to discover public IP addresses and NAT types.

use std::collections::{HashMap, VecDeque};
use std::io::{Cursor, Read, Write};
use std::net::SocketAddr;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::Rng;
use tracing::debug;

use super::Transmit;

/// STUN magic cookie (RFC 5389)
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingSuccessResponse = 0x0101,
    BindingErrorResponse = 0x0111,
}

impl MessageType {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(MessageType::BindingRequest),
            0x0101 => Some(MessageType::BindingSuccessResponse),
            0x0111 => Some(MessageType::BindingErrorResponse),
            _ => None,
        }
    }
}

/// STUN attribute types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000A,
    Realm = 0x0014,
    Nonce = 0x0015,
    XorMappedAddress = 0x0020,
    Priority = 0x0024,
    UseCandidate = 0x0025,
    Software = 0x8022,
    Fingerprint = 0x8028,
    IceControlled = 0x8029,
    IceControlling = 0x802A,
}

impl AttributeType {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(AttributeType::MappedAddress),
            0x0006 => Some(AttributeType::Username),
            0x0008 => Some(AttributeType::MessageIntegrity),
            0x0009 => Some(AttributeType::ErrorCode),
            0x000A => Some(AttributeType::UnknownAttributes),
            0x0014 => Some(AttributeType::Realm),
            0x0015 => Some(AttributeType::Nonce),
            0x0020 => Some(AttributeType::XorMappedAddress),
            0x0024 => Some(AttributeType::Priority),
            0x0025 => Some(AttributeType::UseCandidate),
            0x8022 => Some(AttributeType::Software),
            0x8028 => Some(AttributeType::Fingerprint),
            0x8029 => Some(AttributeType::IceControlled),
            0x802A => Some(AttributeType::IceControlling),
            _ => None,
        }
    }
}

/// STUN attribute
#[derive(Debug, Clone)]
pub struct Attribute {
    pub attr_type: u16,
    pub value: Vec<u8>,
}

/// STUN message
#[derive(Debug, Clone)]
pub struct StunMessage {
    pub message_type: MessageType,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<Attribute>,
}

impl StunMessage {
    /// Create new binding request
    pub fn new_binding_request() -> Self {
        let mut transaction_id = [0u8; 12];
        rand::thread_rng().fill(&mut transaction_id);

        Self {
            message_type: MessageType::BindingRequest,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Create binding response
    pub fn new_binding_response(transaction_id: [u8; 12]) -> Self {
        Self {
            message_type: MessageType::BindingSuccessResponse,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Add XOR-MAPPED-ADDRESS attribute
    pub fn add_xor_mapped_address(&mut self, addr: SocketAddr) {
        let value = Self::encode_xor_mapped_address(addr, &self.transaction_id);
        self.attributes.push(Attribute {
            attr_type: AttributeType::XorMappedAddress as u16,
            value,
        });
    }

    /// Get mapped address from response
    pub fn get_mapped_address(&self) -> Option<SocketAddr> {
        // Try XOR-MAPPED-ADDRESS first
        for attr in &self.attributes {
            if attr.attr_type == AttributeType::XorMappedAddress as u16 {
                return Self::decode_xor_mapped_address(&attr.value, &self.transaction_id);
            }
        }

        // Fall back to MAPPED-ADDRESS
        for attr in &self.attributes {
            if attr.attr_type == AttributeType::MappedAddress as u16 {
                return Self::decode_mapped_address(&attr.value);
            }
        }

        None
    }

    /// Encode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Message type (2 bytes)
        buf.write_u16::<BigEndian>(self.message_type as u16)
            .unwrap();

        // Message length (2 bytes) - placeholder
        let length_pos = buf.len();
        buf.write_u16::<BigEndian>(0).unwrap();

        // Magic cookie (4 bytes)
        buf.write_u32::<BigEndian>(MAGIC_COOKIE).unwrap();

        // Transaction ID (12 bytes)
        buf.write_all(&self.transaction_id).unwrap();

        // Attributes
        let attr_start = buf.len();
        for attr in &self.attributes {
            // Attribute type (2 bytes)
            buf.write_u16::<BigEndian>(attr.attr_type).unwrap();

            // Attribute length (2 bytes)
            buf.write_u16::<BigEndian>(attr.value.len() as u16).unwrap();

            // Attribute value
            buf.write_all(&attr.value).unwrap();

            // Padding to 4-byte boundary
            let padding = (4 - (attr.value.len() % 4)) % 4;
            for _ in 0..padding {
                buf.write_u8(0).unwrap();
            }
        }

        // Update message length
        let attr_length = buf.len() - attr_start;
        buf[length_pos..length_pos + 2].copy_from_slice(&(attr_length as u16).to_be_bytes());

        buf
    }

    /// Parse from bytes
    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 20 {
            return Err("Message too short");
        }

        let mut cursor = Cursor::new(data);

        // Message type
        let msg_type_raw = cursor.read_u16::<BigEndian>().unwrap();
        let message_type = MessageType::from_u16(msg_type_raw).ok_or("Unknown message type")?;

        // Message length
        let msg_length = cursor.read_u16::<BigEndian>().unwrap() as usize;

        // Magic cookie
        let magic = cursor.read_u32::<BigEndian>().unwrap();
        if magic != MAGIC_COOKIE {
            return Err("Invalid magic cookie");
        }

        // Transaction ID
        let mut transaction_id = [0u8; 12];
        cursor
            .read_exact(&mut transaction_id)
            .map_err(|_| "Failed to read transaction ID")?;

        // Attributes
        let mut attributes = Vec::new();
        let mut attr_bytes_read = 0;

        while attr_bytes_read < msg_length {
            if cursor.position() as usize + 4 > data.len() {
                break;
            }

            let attr_type = cursor.read_u16::<BigEndian>().unwrap();
            let attr_length = cursor.read_u16::<BigEndian>().unwrap() as usize;

            if cursor.position() as usize + attr_length > data.len() {
                break;
            }

            let mut value = vec![0u8; attr_length];
            cursor
                .read_exact(&mut value)
                .map_err(|_| "Failed to read attribute value")?;

            attributes.push(Attribute { attr_type, value });

            // Skip padding
            let padding = (4 - (attr_length % 4)) % 4;
            cursor.set_position(cursor.position() + padding as u64);

            attr_bytes_read += 4 + attr_length + padding;
        }

        Ok(Self {
            message_type,
            transaction_id,
            attributes,
        })
    }

    fn encode_xor_mapped_address(addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut buf = Vec::new();

        // Reserved (1 byte) + Family (1 byte)
        buf.write_u8(0).unwrap();
        let family = if addr.is_ipv4() { 0x01 } else { 0x02 };
        buf.write_u8(family).unwrap();

        // XOR port with magic cookie high 16 bits
        let xor_port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
        buf.write_u16::<BigEndian>(xor_port).unwrap();

        // XOR address
        match addr.ip() {
            std::net::IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    buf.write_u8(octets[i] ^ magic_bytes[i]).unwrap();
                }
            }
            std::net::IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                let magic_bytes = MAGIC_COOKIE.to_be_bytes();
                for i in 0..4 {
                    buf.write_u8(octets[i] ^ magic_bytes[i]).unwrap();
                }
                for i in 4..16 {
                    buf.write_u8(octets[i] ^ transaction_id[i - 4]).unwrap();
                }
            }
        }

        buf
    }

    fn decode_xor_mapped_address(data: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
        if data.len() < 4 {
            return None;
        }

        let mut cursor = Cursor::new(data);
        cursor.read_u8().ok()?; // Reserved
        let family = cursor.read_u8().ok()?;

        let xor_port = cursor.read_u16::<BigEndian>().ok()?;
        let port = xor_port ^ ((MAGIC_COOKIE >> 16) as u16);

        let magic_bytes = MAGIC_COOKIE.to_be_bytes();

        match family {
            0x01 => {
                // IPv4
                let mut octets = [0u8; 4];
                cursor.read_exact(&mut octets).ok()?;
                for i in 0..4 {
                    octets[i] ^= magic_bytes[i];
                }
                Some(SocketAddr::new(std::net::IpAddr::V4(octets.into()), port))
            }
            0x02 => {
                // IPv6
                let mut octets = [0u8; 16];
                cursor.read_exact(&mut octets).ok()?;
                for i in 0..4 {
                    octets[i] ^= magic_bytes[i];
                }
                for i in 4..16 {
                    octets[i] ^= transaction_id[i - 4];
                }
                Some(SocketAddr::new(std::net::IpAddr::V6(octets.into()), port))
            }
            _ => None,
        }
    }

    fn decode_mapped_address(data: &[u8]) -> Option<SocketAddr> {
        if data.len() < 4 {
            return None;
        }

        let mut cursor = Cursor::new(data);
        cursor.read_u8().ok()?; // Reserved
        let family = cursor.read_u8().ok()?;
        let port = cursor.read_u16::<BigEndian>().ok()?;

        match family {
            0x01 => {
                // IPv4
                let mut octets = [0u8; 4];
                cursor.read_exact(&mut octets).ok()?;
                Some(SocketAddr::new(std::net::IpAddr::V4(octets.into()), port))
            }
            0x02 => {
                // IPv6
                let mut octets = [0u8; 16];
                cursor.read_exact(&mut octets).ok()?;
                Some(SocketAddr::new(std::net::IpAddr::V6(octets.into()), port))
            }
            _ => None,
        }
    }
}

/// STUN client
pub struct StunClient {
    /// Pending requests
    pending: HashMap<[u8; 12], SocketAddr>,

    /// Outbound transmit queue
    transmit_queue: VecDeque<Transmit>,

    /// Pending responses to send
    response_queue: VecDeque<(StunMessage, SocketAddr)>,
}

impl StunClient {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            transmit_queue: VecDeque::new(),
            response_queue: VecDeque::new(),
        }
    }

    /// Send binding request
    pub fn send_binding_request(&mut self, destination: SocketAddr) -> [u8; 12] {
        let msg = StunMessage::new_binding_request();
        let transaction_id = msg.transaction_id;

        debug!("Sending STUN binding request to {}", destination);

        let payload = msg.encode();
        self.transmit_queue.push_back(Transmit {
            destination,
            payload,
        });

        self.pending.insert(transaction_id, destination);
        transaction_id
    }

    /// Create binding response
    pub fn create_binding_response(&mut self, request: &StunMessage, source: SocketAddr) {
        let mut response = StunMessage::new_binding_response(request.transaction_id);
        response.add_xor_mapped_address(source);

        self.response_queue.push_back((response, source));
    }

    /// Poll for data to transmit
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        // Send queued responses first
        if let Some((msg, destination)) = self.response_queue.pop_front() {
            return Some(Transmit {
                destination,
                payload: msg.encode(),
            });
        }

        self.transmit_queue.pop_front()
    }

    /// Handle incoming response
    pub fn handle_response(&mut self, msg: StunMessage, source: SocketAddr) {
        if self.pending.remove(&msg.transaction_id).is_some() {
            debug!("Received STUN response from {}", source);
        }
    }
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_message_encode_decode() {
        let mut msg = StunMessage::new_binding_request();
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        msg.add_xor_mapped_address(addr);

        let encoded = msg.encode();
        let decoded = StunMessage::parse(&encoded).unwrap();

        assert_eq!(decoded.message_type, MessageType::BindingRequest);
        assert_eq!(decoded.transaction_id, msg.transaction_id);
        assert_eq!(decoded.get_mapped_address(), Some(addr));
    }

    #[test]
    fn test_xor_mapped_address() {
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let transaction_id = [0u8; 12];

        let encoded = StunMessage::encode_xor_mapped_address(addr, &transaction_id);
        let decoded = StunMessage::decode_xor_mapped_address(&encoded, &transaction_id).unwrap();

        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_stun_client() {
        let mut client = StunClient::new();
        let dest: SocketAddr = "8.8.8.8:19302".parse().unwrap();

        let transaction_id = client.send_binding_request(dest);

        let transmit = client.poll_transmit().unwrap();
        assert_eq!(transmit.destination, dest);

        let msg = StunMessage::parse(&transmit.payload).unwrap();
        assert_eq!(msg.transaction_id, transaction_id);
    }
}
