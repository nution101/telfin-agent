use crate::error::{AgentError, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;
use uuid::Uuid;

/// Maximum payload size (1MB)
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Message types matching gateway protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Data = 0x01,
    Close = 0x02,
    Ping = 0x03,
    Pong = 0x04,
    Error = 0x05,
    /// Version check notification from gateway
    VersionCheck = 0x20,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(MessageType::Data),
            0x02 => Some(MessageType::Close),
            0x03 => Some(MessageType::Ping),
            0x04 => Some(MessageType::Pong),
            0x05 => Some(MessageType::Error),
            0x20 => Some(MessageType::VersionCheck),
            _ => None,
        }
    }
}

/// Binary message structure
///
/// Format (matches gateway protocol):
/// ┌─────────┬───────────────────┬─────────────┬─────────────┐
/// │ Type    │ Session ID        │ Length      │ Payload     │
/// │ 1 byte  │ 16 bytes (UUID)   │ 4 bytes     │ N bytes     │
/// └─────────┴───────────────────┴─────────────┴─────────────┘
/// Minimum size: 21 bytes (header only)
#[derive(Debug)]
pub struct Message {
    pub msg_type: MessageType,
    pub session_id: Uuid,
    pub payload: Vec<u8>,
}

impl Message {
    /// Create a new message
    pub fn new(msg_type: MessageType, session_id: Uuid, payload: Vec<u8>) -> Self {
        Self {
            msg_type,
            session_id,
            payload,
        }
    }

    /// Create a data message
    pub fn data(session_id: Uuid, data: Vec<u8>) -> Self {
        Self::new(MessageType::Data, session_id, data)
    }

    /// Create a close message
    #[allow(dead_code)]
    pub fn close(session_id: Uuid) -> Self {
        Self::new(MessageType::Close, session_id, vec![])
    }

    /// Create a ping message
    pub fn ping(session_id: Uuid) -> Self {
        Self::new(MessageType::Ping, session_id, vec![])
    }

    /// Create a pong message
    pub fn pong(session_id: Uuid) -> Self {
        Self::new(MessageType::Pong, session_id, vec![])
    }

    /// Encode message to binary format
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let total_len = 1 + 16 + 4 + self.payload.len();

        let mut buf = BytesMut::with_capacity(total_len);

        // Write message type
        buf.put_u8(self.msg_type as u8);

        // Write session ID (16 bytes)
        buf.put_slice(self.session_id.as_bytes());

        // Write payload length
        buf.put_u32(payload_len);

        // Write payload
        buf.put_slice(&self.payload);

        buf.to_vec()
    }

    /// Decode message from binary format
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 21 {
            return Err(AgentError::ProtocolError(format!(
                "Message too short: {} bytes (minimum 21)",
                data.len()
            )));
        }

        let bytes = Bytes::copy_from_slice(data);
        let mut cursor = Cursor::new(bytes);

        // Read message type
        let msg_type_byte = cursor.get_u8();
        let msg_type = MessageType::from_u8(msg_type_byte).ok_or_else(|| {
            AgentError::ProtocolError(format!("Unknown message type: {}", msg_type_byte))
        })?;

        // Read session ID (16 bytes)
        let mut session_id_bytes = [0u8; 16];
        cursor.copy_to_slice(&mut session_id_bytes);
        let session_id = Uuid::from_bytes(session_id_bytes);

        // Read payload length
        let payload_len = cursor.get_u32() as usize;

        // Validate payload size
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(AgentError::ProtocolError(format!(
                "Payload too large: {} bytes (max {})",
                payload_len, MAX_PAYLOAD_SIZE
            )));
        }

        // Read payload
        let position = cursor.position() as usize;
        let remaining = cursor.into_inner().slice(position..);

        if remaining.len() != payload_len {
            return Err(AgentError::ProtocolError(format!(
                "Invalid payload length: expected {}, got {}",
                payload_len,
                remaining.len()
            )));
        }

        Ok(Self {
            msg_type,
            session_id,
            payload: remaining.to_vec(),
        })
    }
}

/// Terminal data payload sub-types
/// Used within Data messages to distinguish terminal operations
#[repr(u8)]
pub enum DataSubType {
    /// Raw terminal I/O data
    RawData = 0x00,
    /// Terminal resize event
    Resize = 0x01,
}

/// Terminal resize payload
#[derive(Debug, Clone, Copy)]
pub struct ResizePayload {
    pub cols: u16,
    pub rows: u16,
}

impl ResizePayload {
    /// Encode resize payload with sub-type header
    #[allow(dead_code)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(5);
        buffer.push(DataSubType::Resize as u8);
        buffer.extend_from_slice(&self.cols.to_be_bytes());
        buffer.extend_from_slice(&self.rows.to_be_bytes());
        buffer
    }

    /// Decode resize payload (expects sub-type byte)
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(AgentError::ProtocolError(format!(
                "Invalid resize payload length: {}",
                data.len()
            )));
        }

        if data[0] != DataSubType::Resize as u8 {
            return Err(AgentError::ProtocolError(format!(
                "Invalid resize sub-type: expected {}, got {}",
                DataSubType::Resize as u8,
                data[0]
            )));
        }

        let cols = u16::from_be_bytes([data[1], data[2]]);
        let rows = u16::from_be_bytes([data[3], data[4]]);

        // Validate terminal dimensions
        if cols == 0 || rows == 0 || cols > 500 || rows > 500 {
            return Err(AgentError::ProtocolError(format!(
                "Invalid terminal size: {}x{} (must be 1-500)",
                cols, rows
            )));
        }

        Ok(Self { cols, rows })
    }

    /// Decode resize payload without sub-type header (for backward compatibility)
    #[allow(dead_code)]
    pub fn decode_raw(data: &[u8]) -> Result<Self> {
        if data.len() != 4 {
            return Err(AgentError::ProtocolError(format!(
                "Invalid resize payload length: {}",
                data.len()
            )));
        }

        let cols = u16::from_be_bytes([data[0], data[1]]);
        let rows = u16::from_be_bytes([data[2], data[3]]);

        // Validate terminal dimensions
        if cols == 0 || rows == 0 || cols > 500 || rows > 500 {
            return Err(AgentError::ProtocolError(format!(
                "Invalid terminal size: {}x{} (must be 1-500)",
                cols, rows
            )));
        }

        Ok(Self { cols, rows })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_encode_decode() {
        let session_id = Uuid::new_v4();
        let original = Message::data(session_id, b"Hello, world!".to_vec());

        let encoded = original.encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.msg_type, MessageType::Data);
        assert_eq!(decoded.session_id, session_id);
        assert_eq!(decoded.payload, b"Hello, world!");
    }

    #[test]
    fn test_empty_payload() {
        let session_id = Uuid::new_v4();
        let original = Message::ping(session_id);

        let encoded = original.encode();
        assert_eq!(encoded.len(), 21); // Header only

        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type, MessageType::Ping);
        assert_eq!(decoded.session_id, session_id);
        assert_eq!(decoded.payload.len(), 0);
    }

    #[test]
    fn test_resize_payload() {
        let resize = ResizePayload { cols: 80, rows: 24 };
        let encoded = resize.encode();
        let decoded = ResizePayload::decode(&encoded).unwrap();

        assert_eq!(decoded.cols, 80);
        assert_eq!(decoded.rows, 24);
    }

    #[test]
    fn test_invalid_message() {
        let result = Message::decode(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_message_type() {
        let session_id = Uuid::new_v4();
        let mut buf = BytesMut::with_capacity(21);
        buf.put_u8(99); // Invalid type
        buf.put_slice(session_id.as_bytes());
        buf.put_u32(0);

        let result = Message::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_payload_too_large() {
        let session_id = Uuid::new_v4();
        let mut buf = BytesMut::with_capacity(21);
        buf.put_u8(MessageType::Data as u8);
        buf.put_slice(session_id.as_bytes());
        buf.put_u32((MAX_PAYLOAD_SIZE + 1) as u32);

        let result = Message::decode(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_resize_bounds_validation() {
        // Test zero dimensions
        let zero_cols = ResizePayload { cols: 0, rows: 24 }.encode();
        assert!(ResizePayload::decode(&zero_cols).is_err());

        let zero_rows = ResizePayload { cols: 80, rows: 0 }.encode();
        assert!(ResizePayload::decode(&zero_rows).is_err());

        // Test too large dimensions
        let large_cols = ResizePayload {
            cols: 501,
            rows: 24,
        }
        .encode();
        assert!(ResizePayload::decode(&large_cols).is_err());

        let large_rows = ResizePayload {
            cols: 80,
            rows: 501,
        }
        .encode();
        assert!(ResizePayload::decode(&large_rows).is_err());

        // Test valid dimensions
        let valid = ResizePayload { cols: 80, rows: 24 }.encode();
        assert!(ResizePayload::decode(&valid).is_ok());

        let max_valid = ResizePayload {
            cols: 500,
            rows: 500,
        }
        .encode();
        assert!(ResizePayload::decode(&max_valid).is_ok());

        let min_valid = ResizePayload { cols: 1, rows: 1 }.encode();
        assert!(ResizePayload::decode(&min_valid).is_ok());
    }

    #[test]
    fn test_message_size() {
        let session_id = Uuid::new_v4();
        let msg = Message::ping(session_id);
        let encoded = msg.encode();

        // Minimum message: 1 (type) + 16 (UUID) + 4 (length) = 21 bytes
        assert_eq!(encoded.len(), 21);
    }

    #[test]
    fn test_payload_length_mismatch() {
        let session_id = Uuid::new_v4();
        let mut buf = BytesMut::with_capacity(25);
        buf.put_u8(MessageType::Data as u8);
        buf.put_slice(session_id.as_bytes());
        buf.put_u32(10); // Says 10 bytes
        buf.put_slice(b"short"); // But only 5 bytes

        let result = Message::decode(&buf);
        assert!(result.is_err());
    }
}
