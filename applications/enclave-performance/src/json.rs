//! JSON payload types for enclave performance testing.
//!
//! This module defines the JSON payload structures used for measuring
//! JSON serialization/deserialization overhead in vsock communication.

use serde::{Deserialize, Serialize};

/// Test payload for JSON serialization measurements.
///
/// This struct is used to measure the overhead of JSON serialization
/// and deserialization in the pod-enclave communication path.
///
/// # Requirements
/// - 4.1: Pod binary serializes this payload to JSON and sends to enclave
/// - 4.2: Enclave deserializes, re-serializes, and returns this payload
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonTestPayload {
    /// Timestamp in microseconds (typically from measurement start)
    pub timestamp: u64,
    /// Sequence number for ordering/tracking requests
    pub sequence: u32,
    /// Arbitrary data payload for testing different sizes
    pub data: String,
}

impl JsonTestPayload {
    /// Creates a new JsonTestPayload with the given values.
    pub fn new(timestamp: u64, sequence: u32, data: String) -> Self {
        Self {
            timestamp,
            sequence,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Feature: enclave-perf-cli, Property 3: JSON Payload Round-Trip
    // **Validates: Requirements 4.1, 4.2**
    //
    // For any valid JsonTestPayload, serializing to JSON and then deserializing
    // should produce an equivalent payload with the same timestamp, sequence,
    // and data fields.

    /// Strategy to generate arbitrary data strings (limited to 1000 chars for test speed)
    fn arb_data_string() -> impl Strategy<Value = String> {
        prop::string::string_regex(".{0,1000}").unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        // Feature: enclave-perf-cli, Property 3: JSON Payload Round-Trip
        // **Validates: Requirements 4.1, 4.2**
        #[test]
        fn prop_json_payload_roundtrip(
            timestamp in any::<u64>(),
            sequence in any::<u32>(),
            data in arb_data_string()
        ) {
            // Create original payload
            let original = JsonTestPayload::new(timestamp, sequence, data);

            // Serialize to JSON
            let json = serde_json::to_string(&original)
                .expect("serialization should succeed");

            // Deserialize from JSON
            let restored: JsonTestPayload = serde_json::from_str(&json)
                .expect("deserialization should succeed");

            // Verify all fields match
            prop_assert_eq!(original.timestamp, restored.timestamp);
            prop_assert_eq!(original.sequence, restored.sequence);
            prop_assert_eq!(&original.data, &restored.data);
            prop_assert_eq!(&original, &restored);
        }
    }

    #[test]
    fn test_json_payload_creation() {
        let payload = JsonTestPayload::new(1234567890, 42, "test data".to_string());
        
        assert_eq!(payload.timestamp, 1234567890);
        assert_eq!(payload.sequence, 42);
        assert_eq!(payload.data, "test data");
    }

    #[test]
    fn test_json_payload_serialization() {
        let payload = JsonTestPayload::new(1000, 1, "hello".to_string());
        
        let json = serde_json::to_string(&payload).expect("serialization should succeed");
        
        // Verify the JSON contains expected fields
        assert!(json.contains("\"timestamp\":1000"));
        assert!(json.contains("\"sequence\":1"));
        assert!(json.contains("\"data\":\"hello\""));
    }

    #[test]
    fn test_json_payload_deserialization() {
        let json = r#"{"timestamp":2000,"sequence":5,"data":"world"}"#;
        
        let payload: JsonTestPayload = serde_json::from_str(json)
            .expect("deserialization should succeed");
        
        assert_eq!(payload.timestamp, 2000);
        assert_eq!(payload.sequence, 5);
        assert_eq!(payload.data, "world");
    }

    #[test]
    fn test_json_payload_round_trip() {
        let original = JsonTestPayload::new(999999, 100, "round trip test".to_string());
        
        let json = serde_json::to_string(&original).expect("serialization should succeed");
        let deserialized: JsonTestPayload = serde_json::from_str(&json)
            .expect("deserialization should succeed");
        
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_json_payload_with_empty_data() {
        let payload = JsonTestPayload::new(0, 0, String::new());
        
        let json = serde_json::to_string(&payload).expect("serialization should succeed");
        let deserialized: JsonTestPayload = serde_json::from_str(&json)
            .expect("deserialization should succeed");
        
        assert_eq!(payload, deserialized);
        assert!(deserialized.data.is_empty());
    }

    #[test]
    fn test_json_payload_with_special_characters() {
        let payload = JsonTestPayload::new(
            123,
            456,
            "special chars: \"quotes\", \\backslash, \n newline".to_string(),
        );
        
        let json = serde_json::to_string(&payload).expect("serialization should succeed");
        let deserialized: JsonTestPayload = serde_json::from_str(&json)
            .expect("deserialization should succeed");
        
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_json_payload_with_unicode() {
        let payload = JsonTestPayload::new(
            789,
            10,
            "unicode: 你好世界 🚀 émojis".to_string(),
        );
        
        let json = serde_json::to_string(&payload).expect("serialization should succeed");
        let deserialized: JsonTestPayload = serde_json::from_str(&json)
            .expect("deserialization should succeed");
        
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_json_payload_with_max_values() {
        let payload = JsonTestPayload::new(u64::MAX, u32::MAX, "max values".to_string());
        
        let json = serde_json::to_string(&payload).expect("serialization should succeed");
        let deserialized: JsonTestPayload = serde_json::from_str(&json)
            .expect("deserialization should succeed");
        
        assert_eq!(payload, deserialized);
    }

    #[test]
    fn test_json_payload_clone() {
        let original = JsonTestPayload::new(111, 222, "clone test".to_string());
        let cloned = original.clone();
        
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_json_payload_debug() {
        let payload = JsonTestPayload::new(100, 1, "debug".to_string());
        let debug_str = format!("{:?}", payload);
        
        assert!(debug_str.contains("JsonTestPayload"));
        assert!(debug_str.contains("timestamp: 100"));
        assert!(debug_str.contains("sequence: 1"));
        assert!(debug_str.contains("data: \"debug\""));
    }
}
