//! Protocol module for pod-enclave communication
//!
//! Defines the binary message format with fixed-size headers for efficient
//! vsock communication between the pod and enclave binaries.

use std::io::{Read, Write};
use thiserror::Error;

/// Maximum payload size (1MB) to prevent memory exhaustion
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Message types for the protocol
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Ping = 0,
    Pong = 1,
    JsonRequest = 2,
    JsonResponse = 3,
    SignRequest = 4,
    SignResponse = 5,
}

impl MessageType {
    /// Convert a u8 value to a MessageType
    pub fn from_u8(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(MessageType::Ping),
            1 => Ok(MessageType::Pong),
            2 => Ok(MessageType::JsonRequest),
            3 => Ok(MessageType::JsonResponse),
            4 => Ok(MessageType::SignRequest),
            5 => Ok(MessageType::SignResponse),
            _ => Err(ProtocolError::InvalidMessageType(value)),
        }
    }

    /// Convert MessageType to its u8 representation
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Fixed-size message header (5 bytes)
///
/// The header contains:
/// - msg_type: 1 byte message type identifier
/// - payload_len: 4 bytes payload length (little-endian)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    pub msg_type: u8,
    pub payload_len: u32,
}

impl MessageHeader {
    /// Size of the header in bytes
    pub const SIZE: usize = 5;

    /// Create a new message header
    pub fn new(msg_type: MessageType, payload_len: u32) -> Self {
        Self {
            msg_type: msg_type.as_u8(),
            payload_len,
        }
    }

    /// Get the message type from the header
    pub fn message_type(&self) -> Result<MessageType, ProtocolError> {
        MessageType::from_u8(self.msg_type)
    }
}

/// Complete message with header and payload
#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub payload: Vec<u8>,
}

impl Message {
    /// Create a new message with the given type and payload
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Result<Self, ProtocolError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge(payload.len()));
        }

        Ok(Self {
            header: MessageHeader::new(msg_type, payload.len() as u32),
            payload,
        })
    }

    /// Create a ping message with the given payload
    pub fn ping(payload: Vec<u8>) -> Result<Self, ProtocolError> {
        Self::new(MessageType::Ping, payload)
    }

    /// Create a pong message with the given payload
    pub fn pong(payload: Vec<u8>) -> Result<Self, ProtocolError> {
        Self::new(MessageType::Pong, payload)
    }

    /// Get the message type
    pub fn message_type(&self) -> Result<MessageType, ProtocolError> {
        self.header.message_type()
    }

    /// Serialize message to bytes for transmission
    ///
    /// The format is:
    /// - 1 byte: message type
    /// - 4 bytes: payload length (little-endian)
    /// - N bytes: payload
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.header.payload_len;
        let mut bytes = Vec::with_capacity(MessageHeader::SIZE + payload_len as usize);
        bytes.push(self.header.msg_type);
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize message from bytes
    ///
    /// Returns an error if:
    /// - The data is too short to contain a valid header
    /// - The message type is invalid
    /// - The payload length exceeds MAX_PAYLOAD_SIZE
    /// - The data doesn't contain the full payload
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < MessageHeader::SIZE {
            return Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Data too short for message header",
            )));
        }

        let msg_type = data[0];
        let payload_len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);

        // Validate message type
        MessageType::from_u8(msg_type)?;

        // Validate payload size
        if payload_len as usize > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge(payload_len as usize));
        }

        let total_len = MessageHeader::SIZE + payload_len as usize;
        if data.len() < total_len {
            return Err(ProtocolError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Data too short for payload",
            )));
        }

        let payload = data[MessageHeader::SIZE..total_len].to_vec();

        Ok(Self {
            header: MessageHeader {
                msg_type,
                payload_len,
            },
            payload,
        })
    }

    /// Read message from a stream
    ///
    /// Reads the header first, then reads the payload based on the header's
    /// payload length field.
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, ProtocolError> {
        // Read header
        let mut header_buf = [0u8; MessageHeader::SIZE];
        reader.read_exact(&mut header_buf)?;

        let msg_type = header_buf[0];
        let payload_len = u32::from_le_bytes([
            header_buf[1],
            header_buf[2],
            header_buf[3],
            header_buf[4],
        ]);

        // Validate message type
        MessageType::from_u8(msg_type)?;

        // Validate payload size
        if payload_len as usize > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge(payload_len as usize));
        }

        // Read payload
        let mut payload = vec![0u8; payload_len as usize];
        if payload_len > 0 {
            reader.read_exact(&mut payload)?;
        }

        Ok(Self {
            header: MessageHeader {
                msg_type,
                payload_len,
            },
            payload,
        })
    }

    /// Write message to a stream
    ///
    /// Writes the serialized message bytes to the stream.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), ProtocolError> {
        let bytes = self.to_bytes();
        writer.write_all(&bytes)?;
        Ok(())
    }
}

/// Protocol errors that can occur during message handling
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("Payload too large: {0} bytes")]
    PayloadTooLarge(usize),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    // Feature: enclave-perf-cli, Property 1: Message Serialization Round-Trip
    // **Validates: Requirements 3.1, 8.1, 8.2**
    //
    // For any valid Message with any MessageType and any payload bytes,
    // serializing the message to bytes and then deserializing should produce
    // an equivalent message with the same type and payload.

    /// Strategy to generate arbitrary MessageType values (0-5)
    fn arb_message_type() -> impl Strategy<Value = MessageType> {
        (0u8..=5u8).prop_map(|v| MessageType::from_u8(v).unwrap())
    }

    /// Strategy to generate arbitrary payload bytes up to 1000 bytes
    fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..=1000)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        // Feature: enclave-perf-cli, Property 1: Message Serialization Round-Trip
        // **Validates: Requirements 3.1, 8.1, 8.2**
        #[test]
        fn prop_message_to_bytes_from_bytes_roundtrip(
            msg_type in arb_message_type(),
            payload in arb_payload()
        ) {
            // Create original message
            let original = Message::new(msg_type, payload.clone()).unwrap();

            // Serialize to bytes
            let bytes = original.to_bytes();

            // Deserialize from bytes
            let restored = Message::from_bytes(&bytes).unwrap();

            // Verify equivalence
            prop_assert_eq!(original.message_type().unwrap(), restored.message_type().unwrap());
            prop_assert_eq!(original.payload, restored.payload);
        }

        // Feature: enclave-perf-cli, Property 1: Message Serialization Round-Trip
        // **Validates: Requirements 3.1, 8.1, 8.2**
        #[test]
        fn prop_message_write_to_read_from_roundtrip(
            msg_type in arb_message_type(),
            payload in arb_payload()
        ) {
            // Create original message
            let original = Message::new(msg_type, payload.clone()).unwrap();

            // Write to buffer
            let mut write_buffer = Cursor::new(Vec::new());
            original.write_to(&mut write_buffer).unwrap();

            // Read from buffer
            let written = write_buffer.into_inner();
            let mut read_cursor = Cursor::new(written);
            let restored = Message::read_from(&mut read_cursor).unwrap();

            // Verify equivalence
            prop_assert_eq!(original.message_type().unwrap(), restored.message_type().unwrap());
            prop_assert_eq!(original.payload, restored.payload);
        }
    }

    #[test]
    fn test_message_type_from_u8_valid() {
        assert_eq!(MessageType::from_u8(0).unwrap(), MessageType::Ping);
        assert_eq!(MessageType::from_u8(1).unwrap(), MessageType::Pong);
        assert_eq!(MessageType::from_u8(2).unwrap(), MessageType::JsonRequest);
        assert_eq!(MessageType::from_u8(3).unwrap(), MessageType::JsonResponse);
        assert_eq!(MessageType::from_u8(4).unwrap(), MessageType::SignRequest);
        assert_eq!(MessageType::from_u8(5).unwrap(), MessageType::SignResponse);
    }

    #[test]
    fn test_message_type_from_u8_invalid() {
        assert!(matches!(
            MessageType::from_u8(6),
            Err(ProtocolError::InvalidMessageType(6))
        ));
        assert!(matches!(
            MessageType::from_u8(255),
            Err(ProtocolError::InvalidMessageType(255))
        ));
    }

    #[test]
    fn test_message_type_as_u8() {
        assert_eq!(MessageType::Ping.as_u8(), 0);
        assert_eq!(MessageType::Pong.as_u8(), 1);
        assert_eq!(MessageType::JsonRequest.as_u8(), 2);
        assert_eq!(MessageType::JsonResponse.as_u8(), 3);
        assert_eq!(MessageType::SignRequest.as_u8(), 4);
        assert_eq!(MessageType::SignResponse.as_u8(), 5);
    }

    #[test]
    fn test_message_header_new() {
        let header = MessageHeader::new(MessageType::Ping, 100);
        assert_eq!(header.msg_type, 0);
        // Copy payload_len to avoid unaligned access on packed struct
        let payload_len = header.payload_len;
        assert_eq!(payload_len, 100);
    }

    #[test]
    fn test_message_header_size() {
        assert_eq!(MessageHeader::SIZE, 5);
        assert_eq!(std::mem::size_of::<MessageHeader>(), 5);
    }

    #[test]
    fn test_message_new() {
        let payload = vec![1, 2, 3, 4, 5];
        let msg = Message::new(MessageType::Ping, payload.clone()).unwrap();
        assert_eq!(msg.header.msg_type, 0);
        // Copy payload_len to avoid unaligned access on packed struct
        let payload_len = msg.header.payload_len;
        assert_eq!(payload_len, 5);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_message_payload_too_large() {
        let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let result = Message::new(MessageType::Ping, payload);
        assert!(matches!(result, Err(ProtocolError::PayloadTooLarge(_))));
    }

    #[test]
    fn test_message_ping_pong_helpers() {
        let payload = vec![1, 2, 3];
        
        let ping = Message::ping(payload.clone()).unwrap();
        assert_eq!(ping.message_type().unwrap(), MessageType::Ping);
        assert_eq!(ping.payload, payload);

        let pong = Message::pong(payload.clone()).unwrap();
        assert_eq!(pong.message_type().unwrap(), MessageType::Pong);
        assert_eq!(pong.payload, payload);
    }

    #[test]
    fn test_message_empty_payload() {
        let msg = Message::new(MessageType::JsonRequest, vec![]).unwrap();
        // Copy payload_len to avoid unaligned access on packed struct
        let payload_len = msg.header.payload_len;
        assert_eq!(payload_len, 0);
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn test_message_to_bytes() {
        let payload = vec![1, 2, 3, 4, 5];
        let msg = Message::new(MessageType::Ping, payload.clone()).unwrap();
        let bytes = msg.to_bytes();

        // Header: 1 byte msg_type + 4 bytes payload_len + 5 bytes payload
        assert_eq!(bytes.len(), 10);
        assert_eq!(bytes[0], 0); // Ping = 0
        assert_eq!(&bytes[1..5], &5u32.to_le_bytes()); // payload_len = 5
        assert_eq!(&bytes[5..], &payload[..]); // payload
    }

    #[test]
    fn test_message_to_bytes_empty_payload() {
        let msg = Message::new(MessageType::Pong, vec![]).unwrap();
        let bytes = msg.to_bytes();

        assert_eq!(bytes.len(), 5); // Just header
        assert_eq!(bytes[0], 1); // Pong = 1
        assert_eq!(&bytes[1..5], &0u32.to_le_bytes()); // payload_len = 0
    }

    #[test]
    fn test_message_from_bytes() {
        let payload = vec![10, 20, 30];
        let mut bytes = vec![2u8]; // JsonRequest = 2
        bytes.extend_from_slice(&3u32.to_le_bytes()); // payload_len = 3
        bytes.extend_from_slice(&payload);

        let msg = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg.message_type().unwrap(), MessageType::JsonRequest);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_message_from_bytes_empty_payload() {
        let mut bytes = vec![3u8]; // JsonResponse = 3
        bytes.extend_from_slice(&0u32.to_le_bytes()); // payload_len = 0

        let msg = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg.message_type().unwrap(), MessageType::JsonResponse);
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn test_message_from_bytes_too_short_header() {
        let bytes = vec![0, 1, 2]; // Only 3 bytes, need 5 for header
        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ProtocolError::Io(_))));
    }

    #[test]
    fn test_message_from_bytes_too_short_payload() {
        let mut bytes = vec![0u8]; // Ping
        bytes.extend_from_slice(&10u32.to_le_bytes()); // payload_len = 10
        bytes.extend_from_slice(&[1, 2, 3]); // Only 3 bytes of payload

        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ProtocolError::Io(_))));
    }

    #[test]
    fn test_message_from_bytes_invalid_type() {
        let mut bytes = vec![255u8]; // Invalid message type
        bytes.extend_from_slice(&0u32.to_le_bytes());

        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ProtocolError::InvalidMessageType(255))));
    }

    #[test]
    fn test_message_from_bytes_payload_too_large() {
        let mut bytes = vec![0u8]; // Ping
        let large_size = (MAX_PAYLOAD_SIZE + 1) as u32;
        bytes.extend_from_slice(&large_size.to_le_bytes());

        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ProtocolError::PayloadTooLarge(_))));
    }

    #[test]
    fn test_message_roundtrip() {
        let original = Message::new(MessageType::SignRequest, vec![100, 200, 255, 0, 1]).unwrap();
        let bytes = original.to_bytes();
        let restored = Message::from_bytes(&bytes).unwrap();

        assert_eq!(original.message_type().unwrap(), restored.message_type().unwrap());
        assert_eq!(original.payload, restored.payload);
    }

    #[test]
    fn test_message_read_from() {
        use std::io::Cursor;

        let payload = vec![5, 10, 15, 20];
        let mut bytes = vec![4u8]; // SignRequest = 4
        bytes.extend_from_slice(&4u32.to_le_bytes()); // payload_len = 4
        bytes.extend_from_slice(&payload);

        let mut cursor = Cursor::new(bytes);
        let msg = Message::read_from(&mut cursor).unwrap();

        assert_eq!(msg.message_type().unwrap(), MessageType::SignRequest);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_message_read_from_empty_payload() {
        use std::io::Cursor;

        let mut bytes = vec![5u8]; // SignResponse = 5
        bytes.extend_from_slice(&0u32.to_le_bytes()); // payload_len = 0

        let mut cursor = Cursor::new(bytes);
        let msg = Message::read_from(&mut cursor).unwrap();

        assert_eq!(msg.message_type().unwrap(), MessageType::SignResponse);
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn test_message_read_from_incomplete_header() {
        use std::io::Cursor;

        let bytes = vec![0, 1, 2]; // Only 3 bytes
        let mut cursor = Cursor::new(bytes);
        let result = Message::read_from(&mut cursor);

        assert!(matches!(result, Err(ProtocolError::Io(_))));
    }

    #[test]
    fn test_message_read_from_incomplete_payload() {
        use std::io::Cursor;

        let mut bytes = vec![0u8]; // Ping
        bytes.extend_from_slice(&10u32.to_le_bytes()); // payload_len = 10
        bytes.extend_from_slice(&[1, 2, 3]); // Only 3 bytes

        let mut cursor = Cursor::new(bytes);
        let result = Message::read_from(&mut cursor);

        assert!(matches!(result, Err(ProtocolError::Io(_))));
    }

    #[test]
    fn test_message_read_from_invalid_type() {
        use std::io::Cursor;

        let mut bytes = vec![100u8]; // Invalid type
        bytes.extend_from_slice(&0u32.to_le_bytes());

        let mut cursor = Cursor::new(bytes);
        let result = Message::read_from(&mut cursor);

        assert!(matches!(result, Err(ProtocolError::InvalidMessageType(100))));
    }

    #[test]
    fn test_message_read_from_payload_too_large() {
        use std::io::Cursor;

        let mut bytes = vec![0u8]; // Ping
        let large_size = (MAX_PAYLOAD_SIZE + 1) as u32;
        bytes.extend_from_slice(&large_size.to_le_bytes());

        let mut cursor = Cursor::new(bytes);
        let result = Message::read_from(&mut cursor);

        assert!(matches!(result, Err(ProtocolError::PayloadTooLarge(_))));
    }

    #[test]
    fn test_message_write_to() {
        use std::io::Cursor;

        let msg = Message::new(MessageType::Pong, vec![1, 2, 3]).unwrap();
        let mut buffer = Cursor::new(Vec::new());
        msg.write_to(&mut buffer).unwrap();

        let written = buffer.into_inner();
        assert_eq!(written.len(), 8); // 5 header + 3 payload
        assert_eq!(written[0], 1); // Pong = 1
        assert_eq!(&written[1..5], &3u32.to_le_bytes());
        assert_eq!(&written[5..], &[1, 2, 3]);
    }

    #[test]
    fn test_message_write_read_roundtrip() {
        use std::io::Cursor;

        let original = Message::new(MessageType::JsonRequest, vec![42, 43, 44, 45]).unwrap();
        
        // Write to buffer
        let mut buffer = Cursor::new(Vec::new());
        original.write_to(&mut buffer).unwrap();

        // Read back from buffer
        let written = buffer.into_inner();
        let mut read_cursor = Cursor::new(written);
        let restored = Message::read_from(&mut read_cursor).unwrap();

        assert_eq!(original.message_type().unwrap(), restored.message_type().unwrap());
        assert_eq!(original.payload, restored.payload);
    }
}
