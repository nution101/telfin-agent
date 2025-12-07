use crate::error::{AgentError, Result};

/// Binary protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum payload size (1MB)
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    SessionStart = 0x01,
    TerminalInput = 0x02,
    TerminalOutput = 0x03,
    TerminalResize = 0x04,
    SessionEnd = 0x05,
    Heartbeat = 0x06,
    Error = 0x07,
}

impl MessageType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(MessageType::SessionStart),
            0x02 => Some(MessageType::TerminalInput),
            0x03 => Some(MessageType::TerminalOutput),
            0x04 => Some(MessageType::TerminalResize),
            0x05 => Some(MessageType::SessionEnd),
            0x06 => Some(MessageType::Heartbeat),
            0x07 => Some(MessageType::Error),
            _ => None,
        }
    }
}

/// Binary message structure
///
/// Header format (10 bytes):
/// ┌─────────┬─────────┬───────────────┬─────────────┐
/// │ Version │ Type    │ Session ID    │ Length      │
/// │ 1 byte  │ 1 byte  │ 4 bytes       │ 4 bytes     │
/// └─────────┴─────────┴───────────────┴─────────────┘
#[derive(Debug)]
pub struct Message {
    pub version: u8,
    pub msg_type: MessageType,
    pub session_id: u32,
    pub payload: Vec<u8>,
}

impl Message {
    /// Create a new message
    pub fn new(msg_type: MessageType, session_id: u32, payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            msg_type,
            session_id,
            payload,
        }
    }

    /// Encode message to binary format
    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut buffer = Vec::with_capacity(10 + self.payload.len());

        // Header
        buffer.push(self.version);
        buffer.push(self.msg_type as u8);
        buffer.extend_from_slice(&self.session_id.to_be_bytes());
        buffer.extend_from_slice(&payload_len.to_be_bytes());

        // Payload
        buffer.extend_from_slice(&self.payload);

        buffer
    }

    /// Decode message from binary format
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 10 {
            return Err(AgentError::ProtocolError(format!(
                "Message too short: {} bytes",
                data.len()
            )));
        }

        let version = data[0];
        if version != PROTOCOL_VERSION {
            return Err(AgentError::ProtocolError(format!(
                "Unsupported protocol version: {}",
                version
            )));
        }

        let msg_type = MessageType::from_u8(data[1]).ok_or_else(|| {
            AgentError::ProtocolError(format!("Unknown message type: {}", data[1]))
        })?;

        let session_id = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let payload_len = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;

        // Validate payload size
        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(AgentError::ProtocolError(format!(
                "Payload too large: {} bytes (max {})",
                payload_len, MAX_PAYLOAD_SIZE
            )));
        }

        if data.len() != 10 + payload_len {
            return Err(AgentError::ProtocolError(format!(
                "Invalid payload length: expected {}, got {}",
                payload_len,
                data.len() - 10
            )));
        }

        let payload = data[10..].to_vec();

        Ok(Self {
            version,
            msg_type,
            session_id,
            payload,
        })
    }
}

/// Terminal resize payload
#[derive(Debug, Clone, Copy)]
pub struct ResizePayload {
    pub cols: u16,
    pub rows: u16,
}

impl ResizePayload {
    #[allow(dead_code)]
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(4);
        buffer.extend_from_slice(&self.cols.to_be_bytes());
        buffer.extend_from_slice(&self.rows.to_be_bytes());
        buffer
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
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
        let original = Message::new(
            MessageType::TerminalOutput,
            12345,
            b"Hello, world!".to_vec(),
        );

        let encoded = original.encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.msg_type, MessageType::TerminalOutput);
        assert_eq!(decoded.session_id, 12345);
        assert_eq!(decoded.payload, b"Hello, world!");
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
        let data = vec![1, 99, 0, 0, 0, 1, 0, 0, 0, 0];
        let result = Message::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_payload_too_large() {
        // Create header with payload size larger than MAX_PAYLOAD_SIZE
        let mut data = vec![1, 1, 0, 0, 0, 1];
        let large_size = (MAX_PAYLOAD_SIZE + 1) as u32;
        data.extend_from_slice(&large_size.to_be_bytes());

        let result = Message::decode(&data);
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
        let large_cols = ResizePayload { cols: 501, rows: 24 }.encode();
        assert!(ResizePayload::decode(&large_cols).is_err());

        let large_rows = ResizePayload { cols: 80, rows: 501 }.encode();
        assert!(ResizePayload::decode(&large_rows).is_err());

        // Test valid dimensions
        let valid = ResizePayload { cols: 80, rows: 24 }.encode();
        assert!(ResizePayload::decode(&valid).is_ok());

        let max_valid = ResizePayload { cols: 500, rows: 500 }.encode();
        assert!(ResizePayload::decode(&max_valid).is_ok());

        let min_valid = ResizePayload { cols: 1, rows: 1 }.encode();
        assert!(ResizePayload::decode(&min_valid).is_ok());
    }
}
