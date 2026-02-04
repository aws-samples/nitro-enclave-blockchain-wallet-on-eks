//! Enclave Binary
//!
//! Runs inside the Nitro Enclave, listens on vsock, and handles
//! measurement requests from the pod binary.

use clap::{Parser, ValueEnum};
use enclave_performance::json::JsonTestPayload;
use enclave_performance::protocol::{Message, MessageType, ProtocolError};
use enclave_performance::transport::{TransportConfig, TransportListener, TransportStream};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::OsRng;
use std::process;
use thiserror::Error;

/// Default vsock port for the enclave server
const DEFAULT_PORT: u32 = 5000;

/// Transport mode selection for CLI
///
/// Determines which underlying transport mechanism to use for communication.
/// Defaults to `Vsock` for backward compatibility with existing deployments.
///
/// # Requirements
/// - 1.1: WHEN the Enclave_Binary is started with `--transport vsock`, THE Enclave_Binary SHALL use vsock for listening
/// - 1.2: WHEN the Enclave_Binary is started with `--transport tcp`, THE Enclave_Binary SHALL use TCP socket for listening
/// - 1.3: WHEN the Enclave_Binary is started without `--transport` flag, THE Enclave_Binary SHALL default to vsock transport
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum TransportMode {
    /// Virtual Socket transport for Nitro Enclave communication (default)
    #[default]
    Vsock,
    /// Standard TCP socket transport for local development and testing
    Tcp,
}

/// Command-line arguments for the enclave binary
///
/// # Requirements
/// - 1.1, 1.2, 1.3: Transport mode selection with vsock default
/// - 2.1, 2.2, 2.3: TCP bind address configuration
#[derive(Parser, Debug)]
#[command(name = "enclave")]
#[command(about = "Enclave server for performance measurements")]
pub struct EnclaveArgs {
    /// Transport mode (vsock or tcp)
    ///
    /// Use 'vsock' for Nitro Enclave deployments (default).
    /// Use 'tcp' for local development and testing.
    #[arg(long, value_enum, default_value = "vsock")]
    pub transport: TransportMode,

    /// Bind address for TCP mode (e.g., 127.0.0.1, 0.0.0.0)
    ///
    /// Required when using TCP transport mode.
    /// Use 127.0.0.1 for loopback-only access.
    /// Use 0.0.0.0 to bind to all available interfaces.
    #[arg(long, required_if_eq("transport", "tcp"))]
    pub bind_address: Option<String>,

    /// Port number (used for both vsock and TCP)
    #[arg(short, long, default_value = "5000")]
    pub port: u32,
}

impl EnclaveArgs {
    /// Convert CLI arguments to a TransportConfig
    ///
    /// Creates the appropriate transport configuration based on the
    /// selected transport mode and provided parameters.
    pub fn to_transport_config(&self) -> TransportConfig {
        match self.transport {
            TransportMode::Vsock => TransportConfig::Vsock {
                cid: None, // Server doesn't need CID
                port: self.port,
            },
            TransportMode::Tcp => TransportConfig::Tcp {
                address: self.bind_address.clone().unwrap_or_default(),
                port: self.port,
            },
        }
    }
}

/// Enclave configuration
pub struct EnclaveConfig {
    /// The port to listen on
    pub port: u32,
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        Self { port: DEFAULT_PORT }
    }
}

impl From<&EnclaveArgs> for EnclaveConfig {
    fn from(args: &EnclaveArgs) -> Self {
        Self { port: args.port }
    }
}

/// Errors that can occur in the enclave server
#[derive(Debug, Error)]
pub enum EnclaveError {
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Vsock error: {0}")]
    Vsock(#[from] std::io::Error),
}

/// Main enclave server
///
/// Handles vsock connections and processes measurement requests from the pod binary.
pub struct EnclaveServer {
    config: EnclaveConfig,
    signing_key: SigningKey,
}

impl EnclaveServer {
    /// Create a new enclave server with the given configuration.
    ///
    /// Generates a new secp256k1 signing key at startup.
    ///
    /// # Requirements
    /// - 5.1: WHEN the Enclave_Binary starts, THE Enclave_Binary SHALL generate
    ///   or load a secp256k1 private key for signing operations
    pub fn new(config: EnclaveConfig) -> Self {
        // Generate signing key at startup using k256 crate
        let signing_key = SigningKey::random(&mut OsRng);

        Self {
            config,
            signing_key,
        }
    }

    /// Run the enclave server (blocking).
    ///
    /// Binds to a listener on the configured transport and accepts incoming connections.
    ///
    /// # Requirements
    /// - 1.1: WHEN the Enclave_Binary is started with `--transport vsock`, THE Enclave_Binary SHALL use vsock for listening
    /// - 1.2: WHEN the Enclave_Binary is started with `--transport tcp`, THE Enclave_Binary SHALL use TCP socket for listening
    /// - 5.1: WHEN the Enclave_Binary starts with TCP transport, THE Enclave_Binary SHALL bind to a TCP listener
    /// - 5.2: WHEN the Enclave_Binary successfully binds to TCP, THE Enclave_Binary SHALL log the bind address and port
    /// - 5.3: IF the Enclave_Binary fails to bind to the TCP address, THEN THE Enclave_Binary SHALL exit with non-zero status
    /// - 5.4: WHILE the Enclave_Binary is running with TCP transport, THE Enclave_Binary SHALL accept incoming TCP connections
    pub fn run(&self, transport_config: TransportConfig) -> Result<(), EnclaveError> {
        // Bind to the configured transport
        let listener = TransportListener::bind(&transport_config)?;

        // Log the listening address
        println!(
            "Enclave listening on {}, port: {}",
            listener.local_addr_string(),
            self.config.port
        );

        // Accept incoming connections
        // Error handling: The server continues listening even after errors
        // (Requirement 8.3: log error and continue listening)
        loop {
            match listener.accept() {
                Ok(stream) => {
                    if let Err(e) = self.handle_connection(stream) {
                        // Connection error: log and continue accepting new connections
                        eprintln!("Error handling connection: {}", e);
                    }
                }
                Err(e) => {
                    // Accept error: log and continue accepting new connections
                    eprintln!("Error accepting connection: {}", e);
                }
            }
        }
    }

    /// Handle a single client connection.
    ///
    /// Reads requests from the stream and sends responses.
    ///
    /// # Requirements
    /// - 5.5: WHEN a TCP connection is accepted, THE Enclave_Binary SHALL handle requests using the same protocol as vsock
    ///
    /// # Error Handling (Requirement 8.3)
    /// - Malformed messages (invalid message type, payload too large) are logged
    ///   and the connection is closed, but the server continues listening
    /// - Connection errors are logged and the server continues accepting new connections
    /// - The server never crashes on errors
    fn handle_connection(&self, mut stream: TransportStream) -> Result<(), EnclaveError> {
        // Read and process requests until the connection is closed
        loop {
            match Message::read_from(&mut stream) {
                Ok(request) => {
                    match self.process_request(request) {
                        Ok(response) => {
                            if let Err(e) = response.write_to(&mut stream) {
                                eprintln!("Error writing response: {}", e);
                                return Err(EnclaveError::Protocol(e));
                            }
                        }
                        Err(e) => {
                            // Requirement 8.3: Log error and continue processing requests
                            // on this connection (e.g., invalid JSON payload)
                            eprintln!("Error processing request: {}", e);
                        }
                    }
                }
                Err(ProtocolError::Io(ref e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Client closed connection gracefully
                    break;
                }
                Err(e) => {
                    // Requirement 8.3: Log malformed message error
                    // Close this connection but continue listening for new connections
                    // (We can't reliably continue on this connection because we don't
                    // know how many bytes to skip for a malformed message)
                    eprintln!("Error reading request (malformed message): {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Process a single request and return a response.
    ///
    /// Dispatches to the appropriate handler based on message type:
    /// - Ping: Returns pong with same payload (Requirement 3.2)
    /// - JsonRequest: Deserializes, re-serializes, returns as JsonResponse (Requirement 4.2)
    /// - SignRequest: Signs payload bytes, returns signature as SignResponse (Requirement 5.3)
    ///
    /// # Requirements
    /// - 3.2: WHEN the Enclave_Binary receives a ping message, THE Enclave_Binary
    ///   SHALL immediately respond with a pong message
    /// - 4.2: WHEN the Enclave_Binary receives a JSON payload, THE Enclave_Binary
    ///   SHALL deserialize the payload, re-serialize it, and send it back
    /// - 5.3: WHEN the Enclave_Binary receives a signing request, THE Enclave_Binary
    ///   SHALL sign the message using secp256k1 and return the signature
    fn process_request(&self, request: Message) -> Result<Message, EnclaveError> {
        let msg_type = request.message_type()?;

        match msg_type {
            MessageType::Ping => {
                // Requirement 3.2: Return pong with same payload
                self.handle_ping(request.payload)
            }
            MessageType::JsonRequest => {
                // Requirement 4.2: Deserialize, re-serialize, and return
                self.handle_json(request.payload)
            }
            MessageType::SignRequest => {
                // Requirement 5.3: Sign message and return signature
                self.handle_sign(request.payload)
            }
            // Response types should not be received by the enclave
            MessageType::Pong | MessageType::JsonResponse | MessageType::SignResponse => {
                Err(EnclaveError::Protocol(ProtocolError::InvalidMessageType(
                    msg_type.as_u8(),
                )))
            }
        }
    }

    /// Handle a ping request by returning a pong with the same payload.
    ///
    /// # Requirement 3.2
    /// WHEN the Enclave_Binary receives a ping message, THE Enclave_Binary
    /// SHALL immediately respond with a pong message
    fn handle_ping(&self, payload: Vec<u8>) -> Result<Message, EnclaveError> {
        Ok(Message::pong(payload)?)
    }

    /// Handle a JSON request by deserializing, re-serializing, and returning.
    ///
    /// # Requirement 4.2
    /// WHEN the Enclave_Binary receives a JSON payload, THE Enclave_Binary
    /// SHALL deserialize the payload, re-serialize it, and send it back
    fn handle_json(&self, payload: Vec<u8>) -> Result<Message, EnclaveError> {
        // Deserialize the JSON payload
        let json_payload: JsonTestPayload = serde_json::from_slice(&payload)
            .map_err(ProtocolError::Serialization)?;

        // Re-serialize the payload
        let response_bytes = serde_json::to_vec(&json_payload)
            .map_err(ProtocolError::Serialization)?;

        // Return as JsonResponse
        Ok(Message::new(MessageType::JsonResponse, response_bytes)?)
    }

    /// Handle a sign request by signing the payload and returning the signature.
    ///
    /// # Requirement 5.3
    /// WHEN the Enclave_Binary receives a signing request, THE Enclave_Binary
    /// SHALL sign the message using secp256k1 and return the signature
    fn handle_sign(&self, payload: Vec<u8>) -> Result<Message, EnclaveError> {
        // Sign the message using secp256k1
        let signature: Signature = self.signing_key.sign(&payload);

        // Return signature bytes as SignResponse
        let signature_bytes = signature.to_bytes().to_vec();
        Ok(Message::new(MessageType::SignResponse, signature_bytes)?)
    }
}

fn main() {
    // Parse command-line arguments
    let args = EnclaveArgs::parse();

    // Create server configuration from CLI args
    let config = EnclaveConfig::from(&args);
    let server = EnclaveServer::new(config);

    // Build transport configuration from CLI args
    let transport_config = args.to_transport_config();

    // Run the server with the specified transport
    // If binding fails, exit with non-zero status code (Requirement 5.3)
    if let Err(e) = server.run(transport_config) {
        eprintln!("Enclave server error: {}", e);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::Verifier, VerifyingKey};
    use proptest::prelude::*;

    // =========================================================================
    // Task 2.2: Unit tests for enclave CLI argument parsing
    // Requirements: 1.1, 1.2, 1.3, 2.1
    // =========================================================================

    /// Test that the default transport mode is vsock
    /// Validates: Requirement 1.3 - WHEN the Enclave_Binary is started without `--transport` flag,
    /// THE Enclave_Binary SHALL default to vsock transport for backward compatibility
    #[test]
    fn test_transport_mode_default_is_vsock() {
        let mode = TransportMode::default();
        assert_eq!(mode, TransportMode::Vsock);
    }

    /// Test parsing `--transport vsock` works correctly
    /// Validates: Requirement 1.1 - WHEN the Enclave_Binary is started with `--transport vsock`,
    /// THE Enclave_Binary SHALL use vsock for listening
    #[test]
    fn test_parse_transport_vsock() {
        let args = EnclaveArgs::try_parse_from(["enclave", "--transport", "vsock"]).unwrap();
        assert_eq!(args.transport, TransportMode::Vsock);
    }

    /// Test parsing `--transport tcp` works correctly
    /// Validates: Requirement 1.2 - WHEN the Enclave_Binary is started with `--transport tcp`,
    /// THE Enclave_Binary SHALL use TCP socket for listening
    #[test]
    fn test_parse_transport_tcp() {
        let args = EnclaveArgs::try_parse_from([
            "enclave",
            "--transport", "tcp",
            "--bind-address", "127.0.0.1",
        ]).unwrap();
        assert_eq!(args.transport, TransportMode::Tcp);
    }

    /// Test that `--bind-address` is required when using TCP mode
    /// Validates: Requirement 2.1 - WHEN the Enclave_Binary is started with `--transport tcp`,
    /// THE Enclave_Binary SHALL require a `--bind-address` parameter
    #[test]
    fn test_bind_address_required_for_tcp() {
        let result = EnclaveArgs::try_parse_from(["enclave", "--transport", "tcp"]);
        assert!(result.is_err(), "Should fail when --bind-address is missing for TCP mode");
        
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("bind-address") || err_str.contains("required"),
            "Error message should mention bind-address requirement: {}",
            err_str
        );
    }

    /// Test that `--bind-address` is optional when using vsock mode
    /// Validates: Requirement 1.1 - vsock mode should work without bind-address
    #[test]
    fn test_bind_address_optional_for_vsock() {
        let args = EnclaveArgs::try_parse_from(["enclave", "--transport", "vsock"]).unwrap();
        assert_eq!(args.transport, TransportMode::Vsock);
        assert!(args.bind_address.is_none());
    }

    /// Test that default arguments (no flags) result in vsock transport
    /// Validates: Requirement 1.3 - default to vsock transport for backward compatibility
    #[test]
    fn test_default_args_use_vsock() {
        let args = EnclaveArgs::try_parse_from(["enclave"]).unwrap();
        assert_eq!(args.transport, TransportMode::Vsock);
        assert!(args.bind_address.is_none());
        assert_eq!(args.port, DEFAULT_PORT);
    }

    /// Test port parsing works correctly with default value
    #[test]
    fn test_port_default_value() {
        let args = EnclaveArgs::try_parse_from(["enclave"]).unwrap();
        assert_eq!(args.port, 5000);
    }

    /// Test port parsing works correctly with custom value
    #[test]
    fn test_port_custom_value() {
        let args = EnclaveArgs::try_parse_from(["enclave", "--port", "8080"]).unwrap();
        assert_eq!(args.port, 8080);
    }

    /// Test port parsing with short flag
    #[test]
    fn test_port_short_flag() {
        let args = EnclaveArgs::try_parse_from(["enclave", "-p", "3000"]).unwrap();
        assert_eq!(args.port, 3000);
    }

    /// Test `to_transport_config()` produces correct TransportConfig for vsock mode
    /// Validates: Requirement 1.1 - vsock transport configuration
    #[test]
    fn test_to_transport_config_vsock() {
        let args = EnclaveArgs::try_parse_from(["enclave", "--transport", "vsock", "--port", "6000"]).unwrap();
        let config = args.to_transport_config();
        
        match config {
            TransportConfig::Vsock { cid, port } => {
                assert_eq!(cid, None, "Server should not need CID");
                assert_eq!(port, 6000);
            }
            _ => panic!("Expected Vsock config"),
        }
    }

    /// Test `to_transport_config()` produces correct TransportConfig for TCP mode
    /// Validates: Requirements 1.2, 2.1, 2.2 - TCP transport configuration
    #[test]
    fn test_to_transport_config_tcp() {
        let args = EnclaveArgs::try_parse_from([
            "enclave",
            "--transport", "tcp",
            "--bind-address", "127.0.0.1",
            "--port", "8080",
        ]).unwrap();
        let config = args.to_transport_config();
        
        match config {
            TransportConfig::Tcp { address, port } => {
                assert_eq!(address, "127.0.0.1");
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected Tcp config"),
        }
    }

    /// Test `to_transport_config()` with TCP and 0.0.0.0 bind address
    /// Validates: Requirement 2.3 - bind to all available interfaces
    #[test]
    fn test_to_transport_config_tcp_all_interfaces() {
        let args = EnclaveArgs::try_parse_from([
            "enclave",
            "--transport", "tcp",
            "--bind-address", "0.0.0.0",
            "--port", "5000",
        ]).unwrap();
        let config = args.to_transport_config();
        
        match config {
            TransportConfig::Tcp { address, port } => {
                assert_eq!(address, "0.0.0.0");
                assert_eq!(port, 5000);
            }
            _ => panic!("Expected Tcp config"),
        }
    }

    /// Test that bind_address can be provided with vsock (but is ignored)
    #[test]
    fn test_bind_address_with_vsock_is_allowed() {
        let args = EnclaveArgs::try_parse_from([
            "enclave",
            "--transport", "vsock",
            "--bind-address", "127.0.0.1",
        ]).unwrap();
        assert_eq!(args.transport, TransportMode::Vsock);
        assert_eq!(args.bind_address, Some("127.0.0.1".to_string()));
        
        // But to_transport_config should still produce Vsock config
        let config = args.to_transport_config();
        match config {
            TransportConfig::Vsock { .. } => {} // Expected
            _ => panic!("Expected Vsock config even when bind_address is provided"),
        }
    }

    /// Test TransportMode enum equality
    #[test]
    fn test_transport_mode_equality() {
        assert_eq!(TransportMode::Vsock, TransportMode::Vsock);
        assert_eq!(TransportMode::Tcp, TransportMode::Tcp);
        assert_ne!(TransportMode::Vsock, TransportMode::Tcp);
    }

    /// Test TransportMode clone and copy
    #[test]
    fn test_transport_mode_clone_copy() {
        let mode = TransportMode::Tcp;
        let cloned = mode.clone();
        let copied: TransportMode = mode; // Copy trait
        assert_eq!(mode, cloned);
        assert_eq!(mode, copied);
    }

    /// Test TransportMode debug format
    #[test]
    fn test_transport_mode_debug() {
        assert_eq!(format!("{:?}", TransportMode::Vsock), "Vsock");
        assert_eq!(format!("{:?}", TransportMode::Tcp), "Tcp");
    }

    /// Test EnclaveArgs debug format
    #[test]
    fn test_enclave_args_debug() {
        let args = EnclaveArgs::try_parse_from([
            "enclave",
            "--transport", "tcp",
            "--bind-address", "127.0.0.1",
            "--port", "5000",
        ]).unwrap();
        let debug_str = format!("{:?}", args);
        assert!(debug_str.contains("Tcp"));
        assert!(debug_str.contains("127.0.0.1"));
        assert!(debug_str.contains("5000"));
    }

    /// Test invalid transport mode is rejected
    #[test]
    fn test_invalid_transport_mode() {
        let result = EnclaveArgs::try_parse_from(["enclave", "--transport", "invalid"]);
        assert!(result.is_err(), "Should fail with invalid transport mode");
    }

    // =========================================================================
    // End of Task 2.2 tests
    // =========================================================================

    #[test]
    fn test_enclave_config_default() {
        let config = EnclaveConfig::default();
        assert_eq!(config.port, DEFAULT_PORT);
    }

    #[test]
    fn test_enclave_server_new_generates_signing_key() {
        let config = EnclaveConfig::default();
        let server = EnclaveServer::new(config);
        
        // Verify that a signing key was generated (we can't check the actual key,
        // but we can verify the server was created successfully)
        assert_eq!(server.config.port, DEFAULT_PORT);
    }

    #[test]
    fn test_enclave_config_custom_port() {
        let config = EnclaveConfig { port: 6000 };
        assert_eq!(config.port, 6000);
    }

    // Tests for Task 6.2: Request Handlers

    #[test]
    fn test_handle_ping_returns_pong_with_same_payload() {
        // Requirement 3.2: Ping handler returns pong with same payload
        let server = EnclaveServer::new(EnclaveConfig::default());
        let payload = vec![1, 2, 3, 4, 5];

        let request = Message::ping(payload.clone()).unwrap();
        let response = server.process_request(request).unwrap();

        assert_eq!(response.message_type().unwrap(), MessageType::Pong);
        assert_eq!(response.payload, payload);
    }

    #[test]
    fn test_handle_ping_empty_payload() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let payload = vec![];

        let request = Message::ping(payload.clone()).unwrap();
        let response = server.process_request(request).unwrap();

        assert_eq!(response.message_type().unwrap(), MessageType::Pong);
        assert!(response.payload.is_empty());
    }

    #[test]
    fn test_handle_ping_large_payload() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let payload = vec![42u8; 1000];

        let request = Message::ping(payload.clone()).unwrap();
        let response = server.process_request(request).unwrap();

        assert_eq!(response.message_type().unwrap(), MessageType::Pong);
        assert_eq!(response.payload, payload);
    }

    #[test]
    fn test_handle_json_deserializes_and_reserializes() {
        // Requirement 4.2: JSON handler deserializes, re-serializes, and returns
        let server = EnclaveServer::new(EnclaveConfig::default());
        let json_payload = JsonTestPayload::new(1234567890, 42, "test data".to_string());
        let payload = serde_json::to_vec(&json_payload).unwrap();

        let request = Message::new(MessageType::JsonRequest, payload).unwrap();
        let response = server.process_request(request).unwrap();

        assert_eq!(response.message_type().unwrap(), MessageType::JsonResponse);

        // Deserialize the response and verify it matches
        let response_payload: JsonTestPayload = serde_json::from_slice(&response.payload).unwrap();
        assert_eq!(response_payload, json_payload);
    }

    #[test]
    fn test_handle_json_with_empty_data() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let json_payload = JsonTestPayload::new(0, 0, String::new());
        let payload = serde_json::to_vec(&json_payload).unwrap();

        let request = Message::new(MessageType::JsonRequest, payload).unwrap();
        let response = server.process_request(request).unwrap();

        assert_eq!(response.message_type().unwrap(), MessageType::JsonResponse);

        let response_payload: JsonTestPayload = serde_json::from_slice(&response.payload).unwrap();
        assert_eq!(response_payload, json_payload);
    }

    #[test]
    fn test_handle_json_with_unicode() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let json_payload = JsonTestPayload::new(999, 123, "unicode: 你好世界 🚀".to_string());
        let payload = serde_json::to_vec(&json_payload).unwrap();

        let request = Message::new(MessageType::JsonRequest, payload).unwrap();
        let response = server.process_request(request).unwrap();

        assert_eq!(response.message_type().unwrap(), MessageType::JsonResponse);

        let response_payload: JsonTestPayload = serde_json::from_slice(&response.payload).unwrap();
        assert_eq!(response_payload, json_payload);
    }

    #[test]
    fn test_handle_json_invalid_payload() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let invalid_json = b"not valid json".to_vec();

        let request = Message::new(MessageType::JsonRequest, invalid_json).unwrap();
        let result = server.process_request(request);

        assert!(result.is_err());
    }

    #[test]
    fn test_handle_sign_returns_valid_signature() {
        // Requirement 5.3: Sign handler signs message and returns signature
        let server = EnclaveServer::new(EnclaveConfig::default());
        let message = b"message to sign".to_vec();

        let request = Message::new(MessageType::SignRequest, message.clone()).unwrap();
        let response = server.process_request(request).unwrap();

        assert_eq!(response.message_type().unwrap(), MessageType::SignResponse);

        // Verify the signature is valid using the public key
        let verifying_key = VerifyingKey::from(&server.signing_key);
        let signature = Signature::from_slice(&response.payload).unwrap();
        assert!(verifying_key.verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_handle_sign_empty_message() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let message = vec![];

        let request = Message::new(MessageType::SignRequest, message.clone()).unwrap();
        let response = server.process_request(request).unwrap();

        assert_eq!(response.message_type().unwrap(), MessageType::SignResponse);

        // Verify the signature is valid
        let verifying_key = VerifyingKey::from(&server.signing_key);
        let signature = Signature::from_slice(&response.payload).unwrap();
        assert!(verifying_key.verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_handle_sign_large_message() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let message = vec![0xABu8; 10000];

        let request = Message::new(MessageType::SignRequest, message.clone()).unwrap();
        let response = server.process_request(request).unwrap();

        assert_eq!(response.message_type().unwrap(), MessageType::SignResponse);

        // Verify the signature is valid
        let verifying_key = VerifyingKey::from(&server.signing_key);
        let signature = Signature::from_slice(&response.payload).unwrap();
        assert!(verifying_key.verify(&message, &signature).is_ok());
    }

    #[test]
    fn test_handle_sign_different_messages_produce_different_signatures() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let message1 = b"message one".to_vec();
        let message2 = b"message two".to_vec();

        let request1 = Message::new(MessageType::SignRequest, message1).unwrap();
        let request2 = Message::new(MessageType::SignRequest, message2).unwrap();

        let response1 = server.process_request(request1).unwrap();
        let response2 = server.process_request(request2).unwrap();

        // Different messages should produce different signatures
        assert_ne!(response1.payload, response2.payload);
    }

    #[test]
    fn test_process_request_rejects_pong_message() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let request = Message::pong(vec![1, 2, 3]).unwrap();

        let result = server.process_request(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_request_rejects_json_response_message() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let request = Message::new(MessageType::JsonResponse, vec![1, 2, 3]).unwrap();

        let result = server.process_request(request);
        assert!(result.is_err());
    }

    #[test]
    fn test_process_request_rejects_sign_response_message() {
        let server = EnclaveServer::new(EnclaveConfig::default());
        let request = Message::new(MessageType::SignResponse, vec![1, 2, 3]).unwrap();

        let result = server.process_request(request);
        assert!(result.is_err());
    }

    // Unit tests for EnclaveError (Task 8.1)

    #[test]
    fn test_enclave_error_protocol_variant() {
        // Test that EnclaveError::Protocol can be created from ProtocolError
        let protocol_error = ProtocolError::InvalidMessageType(99);
        let enclave_error: EnclaveError = protocol_error.into();
        
        // Verify the error message contains the expected text
        let error_msg = format!("{}", enclave_error);
        assert!(error_msg.contains("Protocol error"));
        assert!(error_msg.contains("99"));
    }

    #[test]
    fn test_enclave_error_vsock_variant() {
        // Test that EnclaveError::Vsock can be created from std::io::Error
        let io_error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
        let enclave_error: EnclaveError = io_error.into();
        
        // Verify the error message contains the expected text
        let error_msg = format!("{}", enclave_error);
        assert!(error_msg.contains("Vsock error"));
        assert!(error_msg.contains("connection refused"));
    }

    #[test]
    fn test_enclave_error_debug_format() {
        // Test that EnclaveError implements Debug correctly
        let protocol_error = ProtocolError::PayloadTooLarge(2000000);
        let enclave_error: EnclaveError = protocol_error.into();
        
        let debug_str = format!("{:?}", enclave_error);
        assert!(debug_str.contains("Protocol"));
    }

    #[test]
    fn test_enclave_error_from_protocol_error_conversion() {
        // Test the From<ProtocolError> implementation
        let protocol_error = ProtocolError::InvalidMessageType(255);
        let enclave_error = EnclaveError::from(protocol_error);
        
        match enclave_error {
            EnclaveError::Protocol(_) => {} // Expected
            _ => panic!("Expected Protocol variant"),
        }
    }

    #[test]
    fn test_enclave_error_from_io_error_conversion() {
        // Test the From<std::io::Error> implementation
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let enclave_error = EnclaveError::from(io_error);
        
        match enclave_error {
            EnclaveError::Vsock(_) => {} // Expected
            _ => panic!("Expected Vsock variant"),
        }
    }

    // Tests for Task 8.2: Error Handling
    // Requirement 8.3: WHEN the Enclave_Binary receives a malformed message,
    // THE Enclave_Binary SHALL log an error and continue listening

    #[test]
    fn test_error_handling_invalid_json_returns_error() {
        // Requirement 8.3: Malformed JSON should return an error but not crash
        let server = EnclaveServer::new(EnclaveConfig::default());
        let invalid_json = b"{ invalid json }".to_vec();

        let request = Message::new(MessageType::JsonRequest, invalid_json).unwrap();
        let result = server.process_request(request);

        // Should return an error, not panic
        assert!(result.is_err());
        
        // Verify the error is a Protocol error with Serialization variant
        match result {
            Err(EnclaveError::Protocol(ProtocolError::Serialization(_))) => {} // Expected
            Err(e) => panic!("Expected Serialization error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    #[test]
    fn test_error_handling_server_continues_after_invalid_json() {
        // Requirement 8.3: Server should continue processing after errors
        let server = EnclaveServer::new(EnclaveConfig::default());

        // First request: invalid JSON (should fail)
        let invalid_json = b"not json".to_vec();
        let request1 = Message::new(MessageType::JsonRequest, invalid_json).unwrap();
        let result1 = server.process_request(request1);
        assert!(result1.is_err());

        // Second request: valid ping (should succeed)
        let request2 = Message::ping(vec![1, 2, 3]).unwrap();
        let result2 = server.process_request(request2);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().message_type().unwrap(), MessageType::Pong);
    }

    #[test]
    fn test_error_handling_invalid_message_type_in_process_request() {
        // Test that response message types are rejected
        let server = EnclaveServer::new(EnclaveConfig::default());

        // Pong messages should not be processed by the enclave
        let pong = Message::pong(vec![1, 2, 3]).unwrap();
        let result = server.process_request(pong);
        assert!(result.is_err());
        
        match result {
            Err(EnclaveError::Protocol(ProtocolError::InvalidMessageType(_))) => {} // Expected
            Err(e) => panic!("Expected InvalidMessageType error, got: {:?}", e),
            Ok(_) => panic!("Expected error, got success"),
        }
    }

    #[test]
    fn test_error_handling_multiple_errors_dont_crash() {
        // Requirement 8.3: Multiple errors should not crash the server
        let server = EnclaveServer::new(EnclaveConfig::default());

        // Multiple invalid requests
        for _ in 0..10 {
            let invalid_json = b"invalid".to_vec();
            let request = Message::new(MessageType::JsonRequest, invalid_json).unwrap();
            let _ = server.process_request(request); // Ignore errors
        }

        // Server should still work after multiple errors
        let valid_request = Message::ping(vec![42]).unwrap();
        let result = server.process_request(valid_request);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().payload, vec![42]);
    }

    #[test]
    fn test_error_handling_empty_json_payload() {
        // Empty payload should fail JSON deserialization gracefully
        let server = EnclaveServer::new(EnclaveConfig::default());
        let empty_payload = vec![];

        let request = Message::new(MessageType::JsonRequest, empty_payload).unwrap();
        let result = server.process_request(request);

        // Should return an error, not panic
        assert!(result.is_err());
    }

    #[test]
    fn test_error_handling_truncated_json_payload() {
        // Truncated JSON should fail gracefully
        let server = EnclaveServer::new(EnclaveConfig::default());
        let truncated_json = b"{\"timestamp\":123,\"sequence\":".to_vec();

        let request = Message::new(MessageType::JsonRequest, truncated_json).unwrap();
        let result = server.process_request(request);

        // Should return an error, not panic
        assert!(result.is_err());
    }

    // Property-based tests
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        // Feature: enclave-perf-cli, Property 5: Ping-Pong Response Correctness
        // **Validates: Requirements 3.2**
        //
        // Property: For any ping request message, the enclave request handler should
        // produce a pong response message with the same payload.
        #[test]
        fn prop_ping_pong_response_correctness(payload in proptest::collection::vec(any::<u8>(), 0..1000)) {
            let server = EnclaveServer::new(EnclaveConfig::default());

            // Create a ping message with the arbitrary payload
            let ping_request = Message::ping(payload.clone()).unwrap();

            // Process the request through the enclave server
            let response = server.process_request(ping_request).unwrap();

            // Verify the response is a pong message
            prop_assert_eq!(response.message_type().unwrap(), MessageType::Pong);

            // Verify the response payload matches the original payload
            prop_assert_eq!(response.payload, payload);
        }

        // Feature: enclave-perf-cli, Property 4: Secp256k1 Signature Validity
        // **Validates: Requirements 5.1, 5.3**
        //
        // Property: For any randomly generated secp256k1 signing key and any message bytes,
        // signing the message should produce a signature that can be verified using the
        // corresponding public key.
        #[test]
        fn prop_secp256k1_signature_validity(message in proptest::collection::vec(any::<u8>(), 0..1000)) {
            // Create a new enclave server (which generates a random secp256k1 signing key)
            let server = EnclaveServer::new(EnclaveConfig::default());

            // Create a SignRequest message with the arbitrary payload
            let sign_request = Message::new(MessageType::SignRequest, message.clone()).unwrap();

            // Process the request through the enclave server
            let response = server.process_request(sign_request).unwrap();

            // Verify the response is a SignResponse
            prop_assert_eq!(response.message_type().unwrap(), MessageType::SignResponse);

            // Extract the signature from the response
            let signature = Signature::from_slice(&response.payload)
                .expect("Response should contain a valid signature");

            // Get the verifying key (public key) from the server's signing key
            let verifying_key = VerifyingKey::from(&server.signing_key);

            // Verify the signature using the public key
            prop_assert!(
                verifying_key.verify(&message, &signature).is_ok(),
                "Signature verification should succeed for the signed message"
            );
        }
    }
}
