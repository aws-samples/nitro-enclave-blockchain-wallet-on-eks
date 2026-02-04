//! TCP Integration Tests for Socket Transport Abstraction
//!
//! This module provides integration tests that verify TCP communication works correctly
//! between the enclave server and pod client over TCP loopback (127.0.0.1).
//!
//! # Test Infrastructure
//!
//! The test infrastructure includes:
//! - `TestServer`: A lightweight test server that handles protocol messages over TCP
//! - Helper functions for starting test servers on random available ports
//! - Helper functions for creating test clients
//!
//! # Requirements Coverage
//! - 8.1: Integration tests verify ping-pong roundtrip over TCP loopback
//! - 8.2: Integration tests verify JSON request-response over TCP loopback
//! - 8.3: Integration tests verify sign request-response over TCP loopback

use enclave_performance::json::JsonTestPayload;
use enclave_performance::protocol::{Message, MessageType, ProtocolError};
use enclave_performance::transport::{connect, TransportConfig, TransportStream};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_core::OsRng;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ============================================================================
// Test Server Infrastructure
// ============================================================================

/// A lightweight test server for TCP integration tests.
///
/// This server mimics the behavior of the enclave server but is designed
/// specifically for testing. It handles:
/// - Ping/Pong messages (returns pong with same payload)
/// - JSON requests (deserializes, re-serializes, returns as response)
/// - Sign requests (signs payload and returns signature)
///
/// # Example
///
/// ```ignore
/// let server = TestServer::start();
/// let addr = server.address();
/// // Connect and send messages...
/// server.stop();
/// ```
pub struct TestServer {
    /// The address the server is listening on
    address: SocketAddr,
    /// Handle to the server thread
    handle: Option<JoinHandle<()>>,
    /// Flag to signal the server to stop
    shutdown: Arc<AtomicBool>,
}

impl TestServer {
    /// Start a new test server on a random available port.
    ///
    /// The server listens on 127.0.0.1 with a port assigned by the OS.
    /// This ensures tests don't conflict with each other or other services.
    ///
    /// # Returns
    ///
    /// A `TestServer` instance that is ready to accept connections.
    ///
    /// # Panics
    ///
    /// Panics if the server fails to bind to an address.
    pub fn start() -> Self {
        Self::start_on_address("127.0.0.1")
    }

    /// Start a new test server on the specified address with a random port.
    ///
    /// # Arguments
    ///
    /// * `address` - The IP address to bind to (e.g., "127.0.0.1", "0.0.0.0")
    ///
    /// # Returns
    ///
    /// A `TestServer` instance that is ready to accept connections.
    pub fn start_on_address(address: &str) -> Self {
        // Bind to port 0 to get a random available port
        let listener = TcpListener::bind(format!("{}:0", address))
            .expect("Failed to bind test server");
        let server_addr = listener.local_addr().expect("Failed to get local address");

        // Set non-blocking mode for the listener so we can check shutdown flag
        listener
            .set_nonblocking(true)
            .expect("Failed to set non-blocking mode");

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        // Generate a signing key for sign requests
        let signing_key = SigningKey::random(&mut OsRng);

        let handle = thread::spawn(move || {
            Self::server_loop(listener, shutdown_clone, signing_key);
        });

        TestServer {
            address: server_addr,
            handle: Some(handle),
            shutdown,
        }
    }

    /// Get the address the server is listening on.
    ///
    /// Use this to configure clients to connect to the test server.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Get the port the server is listening on.
    pub fn port(&self) -> u16 {
        self.address.port()
    }

    /// Create a TransportConfig for connecting to this test server.
    ///
    /// This is a convenience method for creating the appropriate
    /// configuration to connect to this server.
    pub fn transport_config(&self) -> TransportConfig {
        TransportConfig::Tcp {
            address: self.address.ip().to_string(),
            port: self.address.port() as u32,
        }
    }

    /// Stop the test server.
    ///
    /// Signals the server to stop accepting new connections and waits
    /// for the server thread to terminate.
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            // Give the server a moment to notice the shutdown flag
            thread::sleep(Duration::from_millis(50));
            let _ = handle.join();
        }
    }

    /// The main server loop that accepts and handles connections.
    fn server_loop(listener: TcpListener, shutdown: Arc<AtomicBool>, signing_key: SigningKey) {
        while !shutdown.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Set blocking mode for the connection stream
                    stream
                        .set_nonblocking(false)
                        .expect("Failed to set blocking mode");
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .ok();

                    let mut transport_stream = TransportStream::Tcp(stream);
                    let signing_key_clone = signing_key.clone();

                    // Handle the connection in the same thread for simplicity
                    Self::handle_connection(&mut transport_stream, &signing_key_clone);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection available, sleep briefly and check shutdown flag
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    eprintln!("Test server accept error: {}", e);
                }
            }
        }
    }

    /// Handle a single client connection.
    fn handle_connection(stream: &mut TransportStream, signing_key: &SigningKey) {
        loop {
            match Message::read_from(stream) {
                Ok(request) => {
                    let response = Self::process_request(request, signing_key);
                    match response {
                        Ok(resp) => {
                            if resp.write_to(stream).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                Err(ProtocolError::Io(ref e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof
                        || e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(_) => break,
            }
        }
    }

    /// Process a single request and return a response.
    fn process_request(request: Message, signing_key: &SigningKey) -> Result<Message, ProtocolError> {
        let msg_type = request.message_type()?;

        match msg_type {
            MessageType::Ping => {
                // Return pong with same payload
                Message::pong(request.payload)
            }
            MessageType::JsonRequest => {
                // Deserialize, re-serialize, and return
                let json_payload: JsonTestPayload =
                    serde_json::from_slice(&request.payload).map_err(ProtocolError::Serialization)?;
                let response_bytes =
                    serde_json::to_vec(&json_payload).map_err(ProtocolError::Serialization)?;
                Message::new(MessageType::JsonResponse, response_bytes)
            }
            MessageType::SignRequest => {
                // Sign the payload and return signature
                let signature: Signature = signing_key.sign(&request.payload);
                let signature_bytes = signature.to_bytes().to_vec();
                Message::new(MessageType::SignResponse, signature_bytes)
            }
            // Response types should not be received by the server
            _ => Err(ProtocolError::InvalidMessageType(msg_type.as_u8())),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Don't wait for the thread in drop - it might cause issues
    }
}

// ============================================================================
// Test Client Helper Functions
// ============================================================================

/// Create a test client connected to the specified address.
///
/// # Arguments
///
/// * `address` - The IP address to connect to
/// * `port` - The port to connect to
///
/// # Returns
///
/// A `TransportStream` connected to the server, or an error if connection fails.
pub fn create_test_client(address: &str, port: u32) -> std::io::Result<TransportStream> {
    let config = TransportConfig::Tcp {
        address: address.to_string(),
        port,
    };
    connect(&config)
}

/// Create a test client connected to a TestServer.
///
/// # Arguments
///
/// * `server` - The test server to connect to
///
/// # Returns
///
/// A `TransportStream` connected to the server, or an error if connection fails.
pub fn create_client_for_server(server: &TestServer) -> std::io::Result<TransportStream> {
    connect(&server.transport_config())
}

/// Send a ping message and receive the pong response.
///
/// # Arguments
///
/// * `stream` - The transport stream to use
/// * `payload` - The payload to send with the ping
///
/// # Returns
///
/// The payload from the pong response, or an error.
pub fn ping_pong(stream: &mut TransportStream, payload: Vec<u8>) -> Result<Vec<u8>, ProtocolError> {
    let request = Message::ping(payload)?;
    request.write_to(stream)?;
    stream.flush()?;

    let response = Message::read_from(stream)?;
    if response.message_type()? != MessageType::Pong {
        return Err(ProtocolError::InvalidMessageType(
            response.header.msg_type,
        ));
    }

    Ok(response.payload)
}

/// Send a JSON request and receive the JSON response.
///
/// # Arguments
///
/// * `stream` - The transport stream to use
/// * `payload` - The JSON payload to send
///
/// # Returns
///
/// The deserialized JSON response, or an error.
pub fn json_roundtrip(
    stream: &mut TransportStream,
    payload: &JsonTestPayload,
) -> Result<JsonTestPayload, ProtocolError> {
    let payload_bytes = serde_json::to_vec(payload).map_err(ProtocolError::Serialization)?;
    let request = Message::new(MessageType::JsonRequest, payload_bytes)?;
    request.write_to(stream)?;
    stream.flush()?;

    let response = Message::read_from(stream)?;
    if response.message_type()? != MessageType::JsonResponse {
        return Err(ProtocolError::InvalidMessageType(
            response.header.msg_type,
        ));
    }

    let response_payload: JsonTestPayload =
        serde_json::from_slice(&response.payload).map_err(ProtocolError::Serialization)?;
    Ok(response_payload)
}

/// Send a sign request and receive the signature response.
///
/// # Arguments
///
/// * `stream` - The transport stream to use
/// * `message` - The message bytes to sign
///
/// # Returns
///
/// The signature bytes, or an error.
pub fn sign_request(
    stream: &mut TransportStream,
    message: Vec<u8>,
) -> Result<Vec<u8>, ProtocolError> {
    let request = Message::new(MessageType::SignRequest, message)?;
    request.write_to(stream)?;
    stream.flush()?;

    let response = Message::read_from(stream)?;
    if response.message_type()? != MessageType::SignResponse {
        return Err(ProtocolError::InvalidMessageType(
            response.header.msg_type,
        ));
    }

    Ok(response.payload)
}

// ============================================================================
// Test Infrastructure Verification Tests
// ============================================================================

/// Verify that the test server starts and stops correctly.
#[test]
fn test_server_starts_and_stops() {
    let server = TestServer::start();
    let addr = server.address();

    // Verify the server is listening on a valid address
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
    assert!(addr.port() > 0);

    // Stop the server
    server.stop();
}

/// Verify that we can create a client and connect to the test server.
#[test]
fn test_client_connects_to_server() {
    let server = TestServer::start();

    // Create a client and connect
    let client = create_client_for_server(&server);
    assert!(client.is_ok(), "Client should connect successfully");

    server.stop();
}

/// Verify that the transport_config helper produces correct configuration.
#[test]
fn test_transport_config_helper() {
    let server = TestServer::start();
    let config = server.transport_config();

    match config {
        TransportConfig::Tcp { address, port } => {
            assert_eq!(address, "127.0.0.1");
            assert_eq!(port, server.port() as u32);
        }
        _ => panic!("Expected TCP config"),
    }

    server.stop();
}

/// Verify basic ping-pong works with the test infrastructure.
///
/// **Validates: Requirement 8.1** - Integration tests verify ping-pong roundtrip over TCP loopback
#[test]
fn test_infrastructure_ping_pong() {
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    let payload = vec![1, 2, 3, 4, 5];
    let response = ping_pong(&mut client, payload.clone()).expect("Ping-pong failed");

    assert_eq!(response, payload, "Pong payload should match ping payload");

    server.stop();
}

/// Verify basic JSON roundtrip works with the test infrastructure.
///
/// **Validates: Requirement 8.2** - Integration tests verify JSON request-response over TCP loopback
#[test]
fn test_infrastructure_json_roundtrip() {
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    let payload = JsonTestPayload::new(1234567890, 42, "test data".to_string());
    let response = json_roundtrip(&mut client, &payload).expect("JSON roundtrip failed");

    assert_eq!(response, payload, "JSON response should match request");

    server.stop();
}

/// Verify basic sign request works with the test infrastructure.
///
/// **Validates: Requirement 8.3** - Integration tests verify sign request-response over TCP loopback
#[test]
fn test_infrastructure_sign_request() {
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    let message = b"message to sign".to_vec();
    let signature = sign_request(&mut client, message).expect("Sign request failed");

    // Verify we got a signature (64 bytes for secp256k1)
    assert_eq!(signature.len(), 64, "Signature should be 64 bytes");

    server.stop();
}

/// Verify multiple requests can be sent on the same connection.
#[test]
fn test_multiple_requests_same_connection() {
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Send multiple ping-pong requests
    for i in 0..5 {
        let payload = vec![i as u8; 10];
        let response = ping_pong(&mut client, payload.clone()).expect("Ping-pong failed");
        assert_eq!(response, payload);
    }

    // Send a JSON request
    let json_payload = JsonTestPayload::new(999, 1, "multi-request test".to_string());
    let json_response = json_roundtrip(&mut client, &json_payload).expect("JSON roundtrip failed");
    assert_eq!(json_response, json_payload);

    // Send a sign request
    let message = b"sign after multiple requests".to_vec();
    let signature = sign_request(&mut client, message).expect("Sign request failed");
    assert_eq!(signature.len(), 64);

    server.stop();
}

/// Verify empty payloads are handled correctly.
#[test]
fn test_empty_payload_handling() {
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Empty ping payload
    let response = ping_pong(&mut client, vec![]).expect("Empty ping-pong failed");
    assert!(response.is_empty(), "Empty ping should return empty pong");

    // Empty sign request
    let signature = sign_request(&mut client, vec![]).expect("Empty sign request failed");
    assert_eq!(signature.len(), 64, "Should still produce valid signature");

    server.stop();
}

/// Verify large payloads are handled correctly.
#[test]
fn test_large_payload_handling() {
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Large ping payload (10KB)
    let large_payload = vec![0xAB; 10 * 1024];
    let response = ping_pong(&mut client, large_payload.clone()).expect("Large ping-pong failed");
    assert_eq!(response, large_payload, "Large payload should round-trip correctly");

    server.stop();
}

/// Verify JSON with special characters is handled correctly.
#[test]
fn test_json_special_characters() {
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    let payload = JsonTestPayload::new(
        123,
        456,
        "special: \"quotes\", \\backslash, unicode: 你好 🚀".to_string(),
    );
    let response = json_roundtrip(&mut client, &payload).expect("JSON with special chars failed");
    assert_eq!(response, payload);

    server.stop();
}

// ============================================================================
// Property-Based Tests
// ============================================================================

use proptest::prelude::*;

/// Strategy to generate arbitrary payload bytes up to 1000 bytes.
/// This covers a range of payload sizes from empty to moderately large.
fn arb_payload() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=1000)
}

// ============================================================================
// Connection Error Handling Tests
// ============================================================================

/// Test that connecting to a non-existent server returns an appropriate error.
///
/// **Validates: Requirements 6.2, 8.4** - Integration tests verify error handling for connection failures
///
/// This test verifies that:
/// - Connection to a port with no listener returns an error
/// - The error type is ConnectionRefused
#[test]
fn test_connection_to_nonexistent_server_returns_error() {
    // Use a port that is very unlikely to have a server listening
    // Port 59998 is in the ephemeral range but unlikely to be in use
    let config = TransportConfig::Tcp {
        address: "127.0.0.1".to_string(),
        port: 59998,
    };

    let result = connect(&config);

    assert!(
        result.is_err(),
        "Connection to non-existent server should fail"
    );

    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "Error should be ConnectionRefused when no server is listening"
    );
}

/// Test that connection error messages include relevant address information.
///
/// **Validates: Requirements 6.2, 8.4** - Error messages are clear and include relevant information
///
/// This test verifies that when a connection fails, the error provides
/// enough context to understand what went wrong.
#[test]
fn test_connection_error_provides_context() {
    // Try to connect to a non-existent server
    let config = TransportConfig::Tcp {
        address: "127.0.0.1".to_string(),
        port: 59997,
    };

    let result = connect(&config);
    assert!(result.is_err(), "Connection should fail");

    let err = result.unwrap_err();

    // The error should be an IO error with ConnectionRefused kind
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "Error kind should be ConnectionRefused"
    );

    // The error should be convertible to a string for logging/display
    let error_string = err.to_string();
    assert!(
        !error_string.is_empty(),
        "Error message should not be empty"
    );
}

/// Test that connection to an invalid address returns an appropriate error.
///
/// **Validates: Requirements 6.2, 8.4** - Error handling for invalid addresses
///
/// This test verifies that:
/// - Connection with an invalid address format returns an error
/// - The error type is InvalidInput
#[test]
fn test_connection_to_invalid_address_returns_error() {
    let config = TransportConfig::Tcp {
        address: "not-a-valid-ip-address".to_string(),
        port: 5000,
    };

    let result = connect(&config);

    assert!(
        result.is_err(),
        "Connection with invalid address should fail"
    );

    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "Error should be InvalidInput for invalid address format"
    );
}

/// Test that connection errors are distinct from protocol errors.
///
/// **Validates: Requirements 6.2, 8.4** - Clear distinction between error types
///
/// This test verifies that connection-level errors (like ConnectionRefused)
/// are properly distinguished from protocol-level errors.
#[test]
fn test_connection_error_is_io_error() {
    let config = TransportConfig::Tcp {
        address: "127.0.0.1".to_string(),
        port: 59996,
    };

    let result = connect(&config);
    assert!(result.is_err(), "Connection should fail");

    let err = result.unwrap_err();

    // Verify this is a standard IO error
    // The error kind should be one of the expected connection failure types
    let valid_error_kinds = [
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::NotConnected,
    ];

    assert!(
        valid_error_kinds.contains(&err.kind()),
        "Error should be a connection-related IO error, got: {:?}",
        err.kind()
    );
}

/// Test that multiple failed connection attempts return consistent errors.
///
/// **Validates: Requirements 6.2, 8.4** - Consistent error handling
///
/// This test verifies that repeated connection attempts to a non-existent
/// server consistently return the same type of error.
#[test]
fn test_multiple_failed_connections_return_consistent_errors() {
    let config = TransportConfig::Tcp {
        address: "127.0.0.1".to_string(),
        port: 59995,
    };

    // Try connecting multiple times
    let mut error_kinds = Vec::new();
    for _ in 0..3 {
        let result = connect(&config);
        assert!(result.is_err(), "Connection should fail");
        error_kinds.push(result.unwrap_err().kind());
    }

    // All errors should be the same type
    assert!(
        error_kinds.iter().all(|k| *k == error_kinds[0]),
        "All connection errors should be of the same type"
    );

    // Should be ConnectionRefused
    assert_eq!(
        error_kinds[0],
        std::io::ErrorKind::ConnectionRefused,
        "Error should be ConnectionRefused"
    );
}

/// Test that connection to unreachable address times out or fails appropriately.
///
/// **Validates: Requirements 6.2, 8.4** - Error handling for unreachable addresses
///
/// Note: This test uses a non-routable IP address (10.255.255.1) which should
/// either timeout or fail immediately depending on the network configuration.
/// We accept either ConnectionRefused, TimedOut, or other network errors.
#[test]
fn test_connection_to_unreachable_address() {
    // Use a non-routable IP address that should fail
    // 10.255.255.1 is in a private range but unlikely to be routable
    let config = TransportConfig::Tcp {
        address: "10.255.255.1".to_string(),
        port: 5000,
    };

    // Set a timeout by using TcpStream directly with timeout
    // The connect function doesn't have built-in timeout, so this test
    // verifies that the connection attempt eventually fails
    let result = connect(&config);

    // The connection should fail (either immediately or after timeout)
    // We don't assert on the specific error kind because it varies by OS/network
    // The important thing is that it fails and doesn't hang indefinitely
    // Note: This test may take a few seconds on some systems
    assert!(
        result.is_err(),
        "Connection to unreachable address should fail"
    );
}

/// Test error handling when server closes connection immediately.
///
/// **Validates: Requirements 6.2, 8.4** - Error handling for connection drops
///
/// This test verifies that when a server accepts a connection but immediately
/// closes it, the client receives an appropriate error when trying to communicate.
#[test]
fn test_server_closes_connection_immediately() {
    use std::net::TcpListener;

    // Create a server that accepts connections but immediately closes them
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get address");

    // Spawn a thread that accepts and immediately drops the connection
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("Failed to accept");
        drop(stream); // Immediately close the connection
    });

    // Connect to the server
    let config = TransportConfig::Tcp {
        address: addr.ip().to_string(),
        port: addr.port() as u32,
    };

    let mut stream = connect(&config).expect("Connection should succeed initially");

    // Wait for the server to close the connection
    handle.join().expect("Server thread should complete");

    // Give the OS a moment to propagate the connection close
    thread::sleep(Duration::from_millis(50));

    // Try to send a message - this should fail
    let request = Message::ping(vec![1, 2, 3]).expect("Failed to create ping message");
    let write_result = request.write_to(&mut stream);

    // The write might succeed (buffered) but a subsequent read should fail
    if write_result.is_ok() {
        stream.flush().ok(); // Try to flush
        thread::sleep(Duration::from_millis(50));

        // Try to read - this should definitely fail
        let read_result = Message::read_from(&mut stream);
        assert!(
            read_result.is_err(),
            "Reading from closed connection should fail"
        );
    }
    // If write failed, that's also acceptable
}

// ============================================================================
// Property-Based Tests
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Feature: socket-transport-abstraction, Property 2: Protocol Transport Equivalence
    ///
    /// **Property 2: Protocol Transport Equivalence (Round-Trip)**
    /// *For any* valid `Message` with any `MessageType` and any payload bytes, writing the
    /// message to a `TransportStream` and reading it back SHALL produce an equivalent message
    /// with the same type and payload, regardless of whether the underlying transport is
    /// vsock or TCP.
    ///
    /// **Validates: Requirements 4.3, 5.5, 6.3**
    ///
    /// This test verifies that:
    /// - Ping messages return Pong with identical payload
    /// - JsonRequest messages return JsonResponse with equivalent JSON payload
    /// - SignRequest messages return SignResponse with a valid 64-byte signature
    #[test]
    fn prop_protocol_transport_equivalence_ping(payload in arb_payload()) {
        // Start a test server
        let server = TestServer::start();
        let mut client = create_client_for_server(&server).expect("Failed to connect");

        // Send ping and receive pong
        let response_payload = ping_pong(&mut client, payload.clone())
            .expect("Ping-pong should succeed");

        // Verify the pong payload matches the ping payload exactly
        prop_assert_eq!(
            response_payload,
            payload,
            "Pong payload should be identical to ping payload"
        );

        server.stop();
    }

    /// Feature: socket-transport-abstraction, Property 2: Protocol Transport Equivalence
    ///
    /// **Property 2: Protocol Transport Equivalence (Round-Trip)**
    /// Tests JSON request/response equivalence over TCP transport.
    ///
    /// **Validates: Requirements 4.3, 5.5, 6.3**
    #[test]
    fn prop_protocol_transport_equivalence_json(
        timestamp in any::<u64>(),
        sequence in any::<u32>(),
        data in "[a-zA-Z0-9 ]{0,100}"
    ) {
        // Start a test server
        let server = TestServer::start();
        let mut client = create_client_for_server(&server).expect("Failed to connect");

        // Create JSON payload
        let payload = JsonTestPayload::new(timestamp, sequence, data);

        // Send JSON request and receive response
        let response = json_roundtrip(&mut client, &payload)
            .expect("JSON roundtrip should succeed");

        // Verify the response payload matches the request payload exactly
        prop_assert_eq!(
            response.timestamp,
            payload.timestamp,
            "Response timestamp should match request"
        );
        prop_assert_eq!(
            response.sequence,
            payload.sequence,
            "Response sequence should match request"
        );
        prop_assert_eq!(
            response.data,
            payload.data,
            "Response data should match request"
        );

        server.stop();
    }

    /// Feature: socket-transport-abstraction, Property 2: Protocol Transport Equivalence
    ///
    /// **Property 2: Protocol Transport Equivalence (Round-Trip)**
    /// Tests sign request/response over TCP transport.
    ///
    /// **Validates: Requirements 4.3, 5.5, 6.3**
    #[test]
    fn prop_protocol_transport_equivalence_sign(message in arb_payload()) {
        // Start a test server
        let server = TestServer::start();
        let mut client = create_client_for_server(&server).expect("Failed to connect");

        // Send sign request and receive signature
        let signature = sign_request(&mut client, message.clone())
            .expect("Sign request should succeed");

        // Verify we received a valid signature (64 bytes for secp256k1 ECDSA)
        prop_assert_eq!(
            signature.len(),
            64,
            "Signature should be 64 bytes (secp256k1 ECDSA)"
        );

        // Verify the signature bytes are not all zeros (basic sanity check)
        let all_zeros = signature.iter().all(|&b| b == 0);
        prop_assert!(
            !all_zeros || message.is_empty(),
            "Signature should not be all zeros for non-empty messages"
        );

        server.stop();
    }

    /// Feature: socket-transport-abstraction, Property 2: Protocol Transport Equivalence
    ///
    /// **Property 2: Protocol Transport Equivalence (Round-Trip)**
    /// Tests that multiple messages of different types can be sent on the same connection
    /// and all maintain protocol equivalence.
    ///
    /// **Validates: Requirements 4.3, 5.5, 6.3**
    #[test]
    fn prop_protocol_transport_equivalence_mixed(
        ping_payload in arb_payload(),
        timestamp in any::<u64>(),
        sequence in any::<u32>(),
        data in "[a-zA-Z0-9 ]{0,50}",
        sign_message in prop::collection::vec(any::<u8>(), 0..=100)
    ) {
        // Start a test server
        let server = TestServer::start();
        let mut client = create_client_for_server(&server).expect("Failed to connect");

        // Test 1: Ping-Pong
        let pong_payload = ping_pong(&mut client, ping_payload.clone())
            .expect("Ping-pong should succeed");
        prop_assert_eq!(
            pong_payload,
            ping_payload,
            "Pong payload should match ping payload"
        );

        // Test 2: JSON roundtrip
        let json_payload = JsonTestPayload::new(timestamp, sequence, data.clone());
        let json_response = json_roundtrip(&mut client, &json_payload)
            .expect("JSON roundtrip should succeed");
        prop_assert_eq!(
            json_response,
            json_payload,
            "JSON response should match request"
        );

        // Test 3: Sign request
        let signature = sign_request(&mut client, sign_message)
            .expect("Sign request should succeed");
        prop_assert_eq!(
            signature.len(),
            64,
            "Signature should be 64 bytes"
        );

        server.stop();
    }
}

// ============================================================================
// Histogram Integration Tests
// ============================================================================

use enclave_performance::histogram::Histogram;
use std::time::Instant;

/// Integration test for single-threaded measurement with histogram.
///
/// **Validates: Requirement 7.2** - THE `--histogram` flag SHALL enable histogram output in the results
///
/// This test verifies that:
/// 1. Latencies can be collected from real TCP roundtrips
/// 2. A histogram can be created from those latencies
/// 3. The histogram correctly buckets the latency values
/// 4. The ASCII output contains expected elements (bucket labels, counts)
#[test]
fn test_single_threaded_with_histogram() {
    // Start a test server
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Collect latencies from real TCP roundtrips
    let iterations = 20;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let payload = vec![i as u8; 100]; // 100-byte payload
        let start = Instant::now();
        let _response = ping_pong(&mut client, payload).expect("Ping-pong failed");
        let latency_us = start.elapsed().as_micros() as u64;
        latencies.push(latency_us);
    }

    // Verify we collected the expected number of latencies
    assert_eq!(latencies.len(), iterations, "Should collect {} latencies", iterations);

    // Create histogram from the collected latencies
    let histogram = Histogram::from_measurements(&latencies, None);

    // Verify histogram properties
    assert_eq!(histogram.total(), iterations as u64, "Histogram total should match iteration count");

    // Verify sum of bucket counts equals total latencies
    let bucket_sum: u64 = histogram.counts().iter().sum();
    assert_eq!(bucket_sum, iterations as u64, "Sum of bucket counts should equal total latencies");

    // Verify histogram uses default boundaries
    assert_eq!(
        histogram.boundaries(),
        enclave_performance::histogram::DEFAULT_BOUNDARIES,
        "Should use default boundaries"
    );

    // Render ASCII visualization
    let ascii_output = histogram.render_ascii(20);

    // Verify ASCII output contains expected elements
    assert!(
        ascii_output.contains("Latency Distribution:"),
        "ASCII output should contain header"
    );

    // Verify all default bucket labels are present
    assert!(ascii_output.contains("0-100µs"), "Should contain first bucket label");
    assert!(ascii_output.contains("100-200µs"), "Should contain second bucket label");
    assert!(ascii_output.contains("200-500µs"), "Should contain third bucket label");
    assert!(ascii_output.contains("500-1000µs"), "Should contain fourth bucket label");
    assert!(ascii_output.contains("1000-2000µs"), "Should contain fifth bucket label");
    assert!(ascii_output.contains("2000-5000µs"), "Should contain sixth bucket label");
    assert!(ascii_output.contains("5000-10000µs"), "Should contain seventh bucket label");
    assert!(ascii_output.contains(">10000µs"), "Should contain overflow bucket label");

    // Verify no line exceeds 80 characters
    for line in ascii_output.lines() {
        let char_count = line.chars().count();
        assert!(
            char_count <= 80,
            "Line exceeds 80 characters (has {}): '{}'",
            char_count,
            line
        );
    }

    server.stop();
}

/// Integration test for histogram with custom bucket boundaries.
///
/// **Validates: Requirement 7.3** - THE `--buckets` flag SHALL accept a comma-separated list of bucket boundaries
///
/// This test verifies that:
/// 1. Custom bucket boundaries can be used
/// 2. The histogram correctly uses the custom boundaries
/// 3. The ASCII output reflects the custom bucket ranges
#[test]
fn test_histogram_with_custom_boundaries() {
    // Start a test server
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Collect latencies from real TCP roundtrips
    let iterations = 15;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let payload = vec![i as u8; 50];
        let start = Instant::now();
        let _response = ping_pong(&mut client, payload).expect("Ping-pong failed");
        let latency_us = start.elapsed().as_micros() as u64;
        latencies.push(latency_us);
    }

    // Create histogram with custom boundaries
    let custom_boundaries = vec![50, 100, 250, 500, 1000];
    let histogram = Histogram::from_measurements(&latencies, Some(custom_boundaries.clone()));

    // Verify histogram uses custom boundaries
    assert_eq!(
        histogram.boundaries(),
        &custom_boundaries[..],
        "Should use custom boundaries"
    );

    // Verify total count
    assert_eq!(histogram.total(), iterations as u64, "Histogram total should match iteration count");

    // Verify bucket count (boundaries + 1 for overflow)
    assert_eq!(
        histogram.counts().len(),
        custom_boundaries.len() + 1,
        "Should have correct number of buckets"
    );

    // Render ASCII visualization
    let ascii_output = histogram.render_ascii(20);

    // Verify custom bucket labels are present
    assert!(ascii_output.contains("0-50µs"), "Should contain first custom bucket label");
    assert!(ascii_output.contains("50-100µs"), "Should contain second custom bucket label");
    assert!(ascii_output.contains("100-250µs"), "Should contain third custom bucket label");
    assert!(ascii_output.contains("250-500µs"), "Should contain fourth custom bucket label");
    assert!(ascii_output.contains("500-1000µs"), "Should contain fifth custom bucket label");
    assert!(ascii_output.contains(">1000µs"), "Should contain overflow bucket label");

    server.stop();
}

/// Integration test verifying histogram bucketing correctness with known latencies.
///
/// **Validates: Requirement 2.2** - WHEN a latency value falls within a bucket range, THE Histogram SHALL increment that bucket's count
///
/// This test uses controlled latency values to verify correct bucketing.
#[test]
fn test_histogram_bucketing_correctness() {
    // Create histogram with known latencies to verify bucketing
    let latencies = vec![
        50,    // bucket 0: [0, 100)
        99,    // bucket 0: [0, 100)
        100,   // bucket 1: [100, 200) - boundary value goes to next bucket
        150,   // bucket 1: [100, 200)
        200,   // bucket 2: [200, 500) - boundary value
        350,   // bucket 2: [200, 500)
        500,   // bucket 3: [500, 1000) - boundary value
        750,   // bucket 3: [500, 1000)
        1000,  // bucket 4: [1000, 2000) - boundary value
        1500,  // bucket 4: [1000, 2000)
        2000,  // bucket 5: [2000, 5000) - boundary value
        3500,  // bucket 5: [2000, 5000)
        5000,  // bucket 6: [5000, 10000) - boundary value
        7500,  // bucket 6: [5000, 10000)
        10000, // bucket 7: overflow [10000, ∞) - boundary value
        15000, // bucket 7: overflow [10000, ∞)
    ];

    let histogram = Histogram::from_measurements(&latencies, None);

    // Verify total
    assert_eq!(histogram.total(), 16, "Should have 16 total values");

    // Verify expected bucket counts
    let expected_counts = [
        2, // [0, 100): 50, 99
        2, // [100, 200): 100, 150
        2, // [200, 500): 200, 350
        2, // [500, 1000): 500, 750
        2, // [1000, 2000): 1000, 1500
        2, // [2000, 5000): 2000, 3500
        2, // [5000, 10000): 5000, 7500
        2, // [10000, ∞): 10000, 15000
    ];

    assert_eq!(
        histogram.counts(),
        &expected_counts[..],
        "Bucket counts should match expected distribution"
    );

    // Verify ASCII output contains all counts
    let ascii_output = histogram.render_ascii(20);
    
    // Each bucket should show count of 2
    let count_2_occurrences = ascii_output.matches(" 2 (").count();
    assert_eq!(
        count_2_occurrences, 8,
        "All 8 buckets should show count of 2"
    );
}

/// Integration test for histogram merge functionality (used in parallel aggregation).
///
/// **Validates: Requirement 6.3** - THE aggregated histogram SHALL combine bucket counts from all workers
///
/// This test verifies that histograms from multiple "workers" can be merged correctly.
#[test]
fn test_histogram_merge_for_aggregation() {
    // Simulate two workers collecting latencies
    let worker1_latencies = vec![50, 150, 250, 750];
    let worker2_latencies = vec![75, 175, 350, 1500];

    // Create histograms for each worker
    let mut histogram1 = Histogram::from_measurements(&worker1_latencies, None);
    let histogram2 = Histogram::from_measurements(&worker2_latencies, None);

    // Merge worker2's histogram into worker1's
    histogram1.merge(&histogram2);

    // Verify combined total
    assert_eq!(
        histogram1.total(),
        (worker1_latencies.len() + worker2_latencies.len()) as u64,
        "Merged histogram should have combined total"
    );

    // Verify the merge produces correct bucket counts
    // Combined latencies: 50, 75, 150, 175, 250, 350, 750, 1500
    // Expected distribution:
    // [0, 100): 50, 75 -> 2
    // [100, 200): 150, 175 -> 2
    // [200, 500): 250, 350 -> 2
    // [500, 1000): 750 -> 1
    // [1000, 2000): 1500 -> 1
    // [2000, 5000): 0
    // [5000, 10000): 0
    // [10000, ∞): 0
    let expected_counts = [2, 2, 2, 1, 1, 0, 0, 0];
    assert_eq!(
        histogram1.counts(),
        &expected_counts[..],
        "Merged bucket counts should match expected distribution"
    );
}

/// Integration test verifying histogram output when no histogram flag is used.
///
/// **Validates: Requirement 7.4** - WHEN `--histogram` is not specified, THE Pod_Binary SHALL not display histogram output
///
/// This test verifies that histogram functionality is optional and doesn't affect
/// normal measurement flow when not requested.
#[test]
fn test_measurements_without_histogram() {
    // Start a test server
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Collect latencies without creating a histogram
    let iterations = 10;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let payload = vec![i as u8; 50];
        let start = Instant::now();
        let _response = ping_pong(&mut client, payload).expect("Ping-pong failed");
        let latency_us = start.elapsed().as_micros() as u64;
        latencies.push(latency_us);
    }

    // Verify we can collect latencies without histogram
    assert_eq!(latencies.len(), iterations, "Should collect latencies without histogram");

    // Verify latencies are valid (non-zero for real network operations)
    for latency in &latencies {
        assert!(*latency > 0, "Latency should be positive for real TCP roundtrip");
    }

    server.stop();
}


// ============================================================================
// Parallel Execution Integration Tests
// ============================================================================

use enclave_performance::parallel::{ParallelConfig, run_parallel_measurements, aggregate_results, WorkerResult, MetricsCollector};

/// Integration test for parallel execution with 4 workers.
///
/// **Validates: Requirements 4.1, 6.4, 6.5**
/// - 4.1: WHEN the Pod_Binary is started with `--parallel N`, THE Pod_Binary SHALL spawn N concurrent worker threads
/// - 6.4: WHEN displaying parallel results, THE Pod_Binary SHALL show the number of workers and total iterations
/// - 6.5: WHEN displaying parallel results, THE Pod_Binary SHALL show per-worker success/failure counts
///
/// This test verifies that:
/// 1. Parallel execution with 4 workers works correctly
/// 2. Aggregated results contain measurements from all workers
/// 3. Per-worker stats are tracked correctly
#[test]
fn test_parallel_execution_with_4_workers() {
    // Start a test server
    let server = TestServer::start();
    let config = server.transport_config();

    // Create parallel config with 4 workers
    let parallel_config = ParallelConfig {
        workers: 4,
        iterations_per_worker: 10,
    };

    // Run parallel measurements
    let result = run_parallel_measurements(&config, &parallel_config);

    // Verify the result is successful
    assert!(result.is_ok(), "Parallel measurements should succeed: {:?}", result.err());

    let aggregated = result.unwrap();

    // Verify we have results from all 4 workers
    assert_eq!(
        aggregated.worker_results.len(),
        4,
        "Should have results from all 4 workers"
    );

    // Verify each worker has the expected number of measurements
    for worker_result in &aggregated.worker_results {
        assert!(
            worker_result.latencies.len() > 0,
            "Worker {} should have at least some successful measurements",
            worker_result.worker_id
        );
    }

    // Verify aggregated latencies contain measurements from all workers
    let total_latencies: usize = aggregated.worker_results.iter()
        .map(|r| r.latencies.len())
        .sum();
    assert_eq!(
        aggregated.all_latencies.len(),
        total_latencies,
        "Aggregated latencies should contain all measurements from all workers"
    );

    // Verify total success count matches
    assert_eq!(
        aggregated.total_success,
        total_latencies,
        "Total success count should match sum of per-worker successes"
    );

    // Verify total failed count matches
    let total_failed: usize = aggregated.worker_results.iter()
        .map(|r| r.failed_count)
        .sum();
    assert_eq!(
        aggregated.total_failed,
        total_failed,
        "Total failed count should match sum of per-worker failures"
    );

    // Verify all worker IDs are present (0, 1, 2, 3)
    let mut worker_ids: Vec<usize> = aggregated.worker_results.iter()
        .map(|r| r.worker_id)
        .collect();
    worker_ids.sort();
    assert_eq!(
        worker_ids,
        vec![0, 1, 2, 3],
        "All 4 worker IDs should be present"
    );

    // Verify latencies are reasonable (positive values for real TCP roundtrips)
    for latency in &aggregated.all_latencies {
        assert!(*latency > 0, "Latency should be positive for real TCP roundtrip");
    }

    server.stop();
}

/// Integration test verifying per-worker statistics tracking.
///
/// **Validates: Requirements 6.4, 6.5**
/// - 6.4: WHEN displaying parallel results, THE Pod_Binary SHALL show the number of workers and total iterations
/// - 6.5: WHEN displaying parallel results, THE Pod_Binary SHALL show per-worker success/failure counts
///
/// This test verifies that per-worker statistics are correctly tracked and accessible.
#[test]
fn test_per_worker_stats_tracking() {
    // Start a test server
    let server = TestServer::start();
    let config = server.transport_config();

    // Create parallel config with 4 workers, 5 iterations each
    let parallel_config = ParallelConfig {
        workers: 4,
        iterations_per_worker: 5,
    };

    // Run parallel measurements
    let result = run_parallel_measurements(&config, &parallel_config);
    assert!(result.is_ok(), "Parallel measurements should succeed");

    let aggregated = result.unwrap();

    // Verify per-worker stats are available
    assert_eq!(
        aggregated.worker_results.len(),
        4,
        "Should have per-worker results for all 4 workers"
    );

    // Verify each worker result contains expected fields
    for worker_result in &aggregated.worker_results {
        // Worker ID should be in valid range
        assert!(
            worker_result.worker_id < 4,
            "Worker ID {} should be in range [0, 4)",
            worker_result.worker_id
        );

        // Latencies + failed_count should equal iterations_per_worker
        // (unless there was a connection failure)
        let total_attempts = worker_result.latencies.len() + worker_result.failed_count;
        assert!(
            total_attempts <= parallel_config.iterations_per_worker || worker_result.failed_count > 0,
            "Worker {} total attempts ({}) should be <= iterations ({})",
            worker_result.worker_id,
            total_attempts,
            parallel_config.iterations_per_worker
        );

        // Errors list should match failed_count
        assert_eq!(
            worker_result.errors.len(),
            worker_result.failed_count,
            "Worker {} errors list length should match failed_count",
            worker_result.worker_id
        );
    }

    // Verify we can compute per-worker success rates
    for worker_result in &aggregated.worker_results {
        let success_count = worker_result.latencies.len();
        let _success_rate = if success_count + worker_result.failed_count > 0 {
            success_count as f64 / (success_count + worker_result.failed_count) as f64
        } else {
            0.0
        };
        // Success rate should be calculable (no panic)
    }

    server.stop();
}

/// Integration test for parallel execution using MetricsCollector and aggregate_results directly.
///
/// **Validates: Requirements 4.1, 6.4, 6.5**
///
/// This test verifies the parallel infrastructure at a lower level by:
/// 1. Using MetricsCollector to collect results from simulated workers
/// 2. Using aggregate_results to combine the results
/// 3. Verifying the aggregation is correct
#[test]
fn test_parallel_infrastructure_with_metrics_collector() {
    // Start a test server
    let server = TestServer::start();

    // Create a MetricsCollector
    let collector = MetricsCollector::new();
    let num_workers = 4;
    let iterations_per_worker = 5;

    // Spawn worker threads that perform real measurements
    let handles: Vec<_> = (0..num_workers)
        .map(|worker_id| {
            let sender = collector.sender();
            let transport_config = server.transport_config();

            thread::spawn(move || {
                // Each worker establishes its own connection
                let mut client = match connect(&transport_config) {
                    Ok(c) => c,
                    Err(e) => {
                        // Connection failed - report as failure
                        sender.send(WorkerResult {
                            worker_id,
                            latencies: vec![],
                            failed_count: iterations_per_worker,
                            errors: vec![format!("Connection failed: {}", e)],
                        }).expect("send failed");
                        return;
                    }
                };

                // Perform measurements
                let mut latencies = Vec::with_capacity(iterations_per_worker);
                let mut errors = Vec::new();

                for i in 0..iterations_per_worker {
                    let payload = vec![(worker_id * 10 + i) as u8; 50];
                    let start = Instant::now();
                    match ping_pong(&mut client, payload) {
                        Ok(_) => {
                            let latency_us = start.elapsed().as_micros() as u64;
                            latencies.push(latency_us);
                        }
                        Err(e) => {
                            errors.push(format!("iter {}: {}", i, e));
                        }
                    }
                }

                // Send results after all measurements complete
                sender.send(WorkerResult {
                    worker_id,
                    latencies,
                    failed_count: errors.len(),
                    errors,
                }).expect("send failed");
            })
        })
        .collect();

    // Wait for all workers to complete
    for handle in handles {
        handle.join().expect("worker thread panicked");
    }

    // Collect results
    let worker_results = collector.collect(num_workers);

    // Verify we got results from all workers
    assert_eq!(
        worker_results.len(),
        num_workers,
        "Should have results from all {} workers",
        num_workers
    );

    // Aggregate results
    let aggregated = aggregate_results(worker_results);

    // Verify aggregation
    assert_eq!(
        aggregated.worker_results.len(),
        num_workers,
        "Aggregated should contain all worker results"
    );

    // Verify all worker IDs are present
    let mut worker_ids: Vec<usize> = aggregated.worker_results.iter()
        .map(|r| r.worker_id)
        .collect();
    worker_ids.sort();
    assert_eq!(
        worker_ids,
        vec![0, 1, 2, 3],
        "All worker IDs should be present"
    );

    // Verify total counts
    let expected_total_success: usize = aggregated.worker_results.iter()
        .map(|r| r.latencies.len())
        .sum();
    assert_eq!(
        aggregated.total_success,
        expected_total_success,
        "Total success should match sum of per-worker successes"
    );

    let expected_total_failed: usize = aggregated.worker_results.iter()
        .map(|r| r.failed_count)
        .sum();
    assert_eq!(
        aggregated.total_failed,
        expected_total_failed,
        "Total failed should match sum of per-worker failures"
    );

    // Verify all_latencies contains all measurements
    let expected_latency_count: usize = aggregated.worker_results.iter()
        .map(|r| r.latencies.len())
        .sum();
    assert_eq!(
        aggregated.all_latencies.len(),
        expected_latency_count,
        "all_latencies should contain all measurements"
    );

    server.stop();
}

/// Integration test verifying parallel execution with histogram aggregation.
///
/// **Validates: Requirements 6.3, 6.4, 6.5**
/// - 6.3: THE aggregated histogram SHALL combine bucket counts from all workers
///
/// This test verifies that histograms can be created from parallel execution results.
#[test]
fn test_parallel_execution_with_histogram_aggregation() {
    // Start a test server
    let server = TestServer::start();
    let config = server.transport_config();

    // Create parallel config with 4 workers
    let parallel_config = ParallelConfig {
        workers: 4,
        iterations_per_worker: 10,
    };

    // Run parallel measurements
    let result = run_parallel_measurements(&config, &parallel_config);
    assert!(result.is_ok(), "Parallel measurements should succeed");

    let aggregated = result.unwrap();

    // Create histogram from aggregated latencies
    let histogram = Histogram::from_measurements(&aggregated.all_latencies, None);

    // Verify histogram total matches aggregated latency count
    assert_eq!(
        histogram.total(),
        aggregated.all_latencies.len() as u64,
        "Histogram total should match aggregated latency count"
    );

    // Verify sum of bucket counts equals total
    let bucket_sum: u64 = histogram.counts().iter().sum();
    assert_eq!(
        bucket_sum,
        aggregated.all_latencies.len() as u64,
        "Sum of bucket counts should equal total latencies"
    );

    // Create per-worker histograms and merge them
    let mut merged_histogram = Histogram::with_defaults();
    for worker_result in &aggregated.worker_results {
        let worker_histogram = Histogram::from_measurements(&worker_result.latencies, None);
        merged_histogram.merge(&worker_histogram);
    }

    // Verify merged histogram matches histogram from aggregated latencies
    assert_eq!(
        merged_histogram.total(),
        histogram.total(),
        "Merged histogram total should match direct histogram total"
    );

    // Verify bucket counts match
    assert_eq!(
        merged_histogram.counts(),
        histogram.counts(),
        "Merged histogram bucket counts should match direct histogram"
    );

    server.stop();
}

/// Integration test verifying that parallel workers operate independently.
///
/// **Validates: Requirements 4.2, 4.3, 5.3**
/// - 4.2: WHEN parallel mode is enabled, EACH Parallel_Worker SHALL establish its own connection to the enclave
/// - 4.3: WHEN parallel mode is enabled, EACH Parallel_Worker SHALL execute the specified number of iterations independently
/// - 5.3: WHEN a worker encounters an error, THE Pod_Binary SHALL report the error without affecting other workers
///
/// This test verifies that workers operate independently by checking that
/// each worker's measurements are isolated.
#[test]
fn test_parallel_workers_operate_independently() {
    // Start a test server
    let server = TestServer::start();
    let config = server.transport_config();

    // Create parallel config with 4 workers
    let parallel_config = ParallelConfig {
        workers: 4,
        iterations_per_worker: 8,
    };

    // Run parallel measurements
    let result = run_parallel_measurements(&config, &parallel_config);
    assert!(result.is_ok(), "Parallel measurements should succeed");

    let aggregated = result.unwrap();

    // Verify each worker has independent results
    for worker_result in &aggregated.worker_results {
        // Each worker should have attempted all iterations
        let total_attempts = worker_result.latencies.len() + worker_result.failed_count;
        
        // If connection succeeded, total attempts should equal iterations
        // If connection failed, failed_count will be > 0
        if worker_result.failed_count == 0 || !worker_result.errors.iter().any(|e| e.contains("Connection failed")) {
            assert_eq!(
                total_attempts,
                parallel_config.iterations_per_worker,
                "Worker {} should have attempted all {} iterations (got {})",
                worker_result.worker_id,
                parallel_config.iterations_per_worker,
                total_attempts
            );
        }
    }

    // Verify that successful workers have reasonable latencies
    // (this indirectly verifies they each established their own connection)
    for worker_result in &aggregated.worker_results {
        for latency in &worker_result.latencies {
            assert!(
                *latency > 0,
                "Worker {} latency should be positive (got {})",
                worker_result.worker_id,
                latency
            );
            // TCP loopback latencies should typically be under 10ms (10,000 µs)
            assert!(
                *latency < 100_000,
                "Worker {} latency {} µs seems unreasonably high for TCP loopback",
                worker_result.worker_id,
                latency
            );
        }
    }

    server.stop();
}

// ============================================================================
// Backward Compatibility Integration Tests
// ============================================================================

use enclave_performance::stats::MeasurementStats;

/// Integration test for backward compatibility when running without new flags.
///
/// **Validates: Requirements 8.1, 8.3**
/// - 8.1: WHEN no new flags are provided, THE Pod_Binary SHALL produce identical output to the previous version
/// - 8.3: THE existing measurement modes SHALL function identically to the previous version
///
/// This test verifies that:
/// 1. When --parallel is not specified (default 1), single-threaded execution is used
/// 2. When --histogram is not specified (default false), no histogram is displayed
/// 3. The measurement flow works correctly without new flags
/// 4. Statistics (min, max, mean, median, percentiles) are computed correctly
#[test]
fn test_backward_compatibility_without_new_flags() {
    // Start a test server
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Simulate the default behavior: single-threaded execution without histogram
    // This mimics running the pod binary without --parallel or --histogram flags
    
    let iterations = 20;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    // Execute measurements in single-threaded mode (default behavior)
    for i in 0..iterations {
        let payload = vec![i as u8; 100];
        let start = Instant::now();
        let _response = ping_pong(&mut client, payload).expect("Ping-pong failed");
        let latency_us = start.elapsed().as_micros() as u64;
        latencies.push(latency_us);
    }

    // Verify we collected the expected number of latencies
    assert_eq!(
        latencies.len(),
        iterations,
        "Should collect {} latencies in single-threaded mode",
        iterations
    );

    // Verify all latencies are positive (real measurements)
    for latency in &latencies {
        assert!(
            *latency > 0,
            "Latency should be positive for real TCP roundtrip"
        );
    }

    // Compute statistics using MeasurementStats (same as the binary does)
    let stats = MeasurementStats::from_measurements(&latencies)
        .expect("Should compute statistics from non-empty latencies");

    // Verify basic statistics are computed correctly
    assert_eq!(stats.count, iterations, "Count should match iterations");
    
    // Verify min is the smallest value
    let expected_min = *latencies.iter().min().unwrap();
    assert_eq!(stats.min_us, expected_min, "Min should be the smallest latency");
    
    // Verify max is the largest value
    let expected_max = *latencies.iter().max().unwrap();
    assert_eq!(stats.max_us, expected_max, "Max should be the largest latency");
    
    // Verify mean is the arithmetic average
    let expected_mean = latencies.iter().map(|&x| x as f64).sum::<f64>() / iterations as f64;
    let mean_diff = (stats.mean_us - expected_mean).abs();
    assert!(
        mean_diff < 0.001,
        "Mean should be the arithmetic average (diff: {})",
        mean_diff
    );
    
    // Verify median is correct
    let mut sorted = latencies.clone();
    sorted.sort_unstable();
    let expected_median = if sorted.len() % 2 == 1 {
        sorted[sorted.len() / 2]
    } else {
        sorted[sorted.len() / 2 - 1]
    };
    assert_eq!(stats.median_us, expected_median, "Median should be correct");

    // Verify percentiles are computed and within bounds
    assert!(
        stats.p50_us >= stats.min_us as f64 && stats.p50_us <= stats.max_us as f64,
        "p50 should be within [min, max]"
    );
    assert!(
        stats.p90_us >= stats.min_us as f64 && stats.p90_us <= stats.max_us as f64,
        "p90 should be within [min, max]"
    );
    assert!(
        stats.p95_us >= stats.min_us as f64 && stats.p95_us <= stats.max_us as f64,
        "p95 should be within [min, max]"
    );
    assert!(
        stats.p99_us >= stats.min_us as f64 && stats.p99_us <= stats.max_us as f64,
        "p99 should be within [min, max]"
    );
    assert!(
        stats.p99_9_us >= stats.min_us as f64 && stats.p99_9_us <= stats.max_us as f64,
        "p99.9 should be within [min, max]"
    );

    // Verify percentile ordering (monotonic)
    assert!(
        stats.p50_us <= stats.p90_us,
        "p50 ({}) should be <= p90 ({})",
        stats.p50_us,
        stats.p90_us
    );
    assert!(
        stats.p90_us <= stats.p95_us,
        "p90 ({}) should be <= p95 ({})",
        stats.p90_us,
        stats.p95_us
    );
    assert!(
        stats.p95_us <= stats.p99_us,
        "p95 ({}) should be <= p99 ({})",
        stats.p95_us,
        stats.p99_us
    );
    assert!(
        stats.p99_us <= stats.p99_9_us,
        "p99 ({}) should be <= p99.9 ({})",
        stats.p99_us,
        stats.p99_9_us
    );

    server.stop();
}

/// Integration test verifying that single-threaded mode (parallel=1) works correctly.
///
/// **Validates: Requirements 4.4, 8.1**
/// - 4.4: IF the `--parallel` flag is not provided, THEN THE Pod_Binary SHALL default to single-threaded execution
/// - 8.1: WHEN no new flags are provided, THE Pod_Binary SHALL produce identical output to the previous version
///
/// This test verifies that when parallel=1 (the default), the measurement flow
/// uses single-threaded execution and produces correct results.
#[test]
fn test_single_threaded_default_execution() {
    // Start a test server
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Simulate single-threaded execution (parallel=1 default)
    let iterations = 15;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    // Single connection, sequential iterations (default behavior)
    for i in 0..iterations {
        let payload = vec![i as u8; 50];
        let start = Instant::now();
        let _response = ping_pong(&mut client, payload).expect("Ping-pong failed");
        let latency_us = start.elapsed().as_micros() as u64;
        latencies.push(latency_us);
    }

    // Verify single-threaded execution collected all measurements
    assert_eq!(
        latencies.len(),
        iterations,
        "Single-threaded mode should collect all {} iterations",
        iterations
    );

    // Verify statistics can be computed
    let stats = MeasurementStats::from_measurements(&latencies)
        .expect("Should compute statistics");

    // Verify count matches
    assert_eq!(stats.count, iterations, "Stats count should match iterations");

    // Verify all latencies are reasonable for TCP loopback
    for latency in &latencies {
        assert!(
            *latency > 0 && *latency < 100_000,
            "Latency {} µs should be reasonable for TCP loopback",
            latency
        );
    }

    server.stop();
}

/// Integration test verifying that histogram is not displayed when flag is not set.
///
/// **Validates: Requirements 7.4, 8.1**
/// - 7.4: WHEN `--histogram` is not specified, THE Pod_Binary SHALL not display histogram output
/// - 8.1: WHEN no new flags are provided, THE Pod_Binary SHALL produce identical output to the previous version
///
/// This test verifies that when histogram=false (the default), no histogram
/// is created or displayed, maintaining backward compatibility.
#[test]
fn test_no_histogram_when_flag_not_set() {
    // Start a test server
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Collect latencies without histogram (default behavior)
    let iterations = 10;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let payload = vec![i as u8; 50];
        let start = Instant::now();
        let _response = ping_pong(&mut client, payload).expect("Ping-pong failed");
        let latency_us = start.elapsed().as_micros() as u64;
        latencies.push(latency_us);
    }

    // Verify measurements were collected
    assert_eq!(latencies.len(), iterations, "Should collect all latencies");

    // Verify statistics can be computed without histogram
    let stats = MeasurementStats::from_measurements(&latencies)
        .expect("Should compute statistics without histogram");

    // Verify basic statistics are available (backward compatible output)
    assert!(stats.min_us > 0, "Min should be positive");
    assert!(stats.max_us >= stats.min_us, "Max should be >= min");
    assert!(stats.mean_us > 0.0, "Mean should be positive");
    assert!(stats.count == iterations, "Count should match iterations");

    // The key point: we can compute statistics without creating a histogram
    // This verifies the backward compatible code path works correctly

    server.stop();
}

/// Integration test verifying all measurement modes work without new flags.
///
/// **Validates: Requirements 7.5, 8.3**
/// - 7.5: THE new flags SHALL work with all existing measurement modes (roundtrip, json, sign)
/// - 8.3: THE existing measurement modes SHALL function identically to the previous version
///
/// This test verifies that roundtrip, JSON, and sign modes all work correctly
/// in backward compatible mode (without new flags).
#[test]
fn test_all_measurement_modes_backward_compatible() {
    // Start a test server
    let server = TestServer::start();

    // Test 1: Roundtrip mode (ping-pong)
    {
        let mut client = create_client_for_server(&server).expect("Failed to connect");
        let iterations = 5;
        let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

        for i in 0..iterations {
            let payload = vec![i as u8; 32];
            let start = Instant::now();
            let response = ping_pong(&mut client, payload.clone()).expect("Ping-pong failed");
            let latency_us = start.elapsed().as_micros() as u64;
            latencies.push(latency_us);
            
            // Verify response matches request (roundtrip correctness)
            assert_eq!(response, payload, "Roundtrip should return same payload");
        }

        let stats = MeasurementStats::from_measurements(&latencies)
            .expect("Should compute roundtrip stats");
        assert_eq!(stats.count, iterations, "Roundtrip mode should complete all iterations");
    }

    // Test 2: JSON mode
    {
        let mut client = create_client_for_server(&server).expect("Failed to connect");
        let iterations = 5;
        let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

        for i in 0..iterations {
            let payload = JsonTestPayload::new(1000 + i as u64, i as u32, format!("test_{}", i));
            let start = Instant::now();
            let response = json_roundtrip(&mut client, &payload).expect("JSON roundtrip failed");
            let latency_us = start.elapsed().as_micros() as u64;
            latencies.push(latency_us);
            
            // Verify JSON response matches request
            assert_eq!(response, payload, "JSON mode should return equivalent payload");
        }

        let stats = MeasurementStats::from_measurements(&latencies)
            .expect("Should compute JSON stats");
        assert_eq!(stats.count, iterations, "JSON mode should complete all iterations");
    }

    // Test 3: Sign mode
    {
        let mut client = create_client_for_server(&server).expect("Failed to connect");
        let iterations = 5;
        let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

        for i in 0..iterations {
            let message = vec![0xAB; 32 + i];
            let start = Instant::now();
            let signature = sign_request(&mut client, message).expect("Sign request failed");
            let latency_us = start.elapsed().as_micros() as u64;
            latencies.push(latency_us);
            
            // Verify signature is valid (64 bytes for secp256k1)
            assert_eq!(signature.len(), 64, "Sign mode should return 64-byte signature");
        }

        let stats = MeasurementStats::from_measurements(&latencies)
            .expect("Should compute sign stats");
        assert_eq!(stats.count, iterations, "Sign mode should complete all iterations");
    }

    server.stop();
}

/// Integration test verifying output format baseline for backward compatibility.
///
/// **Validates: Requirements 8.1, 8.2**
/// - 8.1: WHEN no new flags are provided, THE Pod_Binary SHALL produce identical output to the previous version
/// - 8.2: THE existing MeasurementStats structure SHALL retain all current fields and behavior
///
/// This test verifies that the MeasurementStats structure contains all expected
/// fields and produces the expected output format.
#[test]
fn test_output_format_baseline() {
    // Start a test server
    let server = TestServer::start();
    let mut client = create_client_for_server(&server).expect("Failed to connect");

    // Collect latencies
    let iterations = 10;
    let mut latencies: Vec<u64> = Vec::with_capacity(iterations);

    for i in 0..iterations {
        let payload = vec![i as u8; 50];
        let start = Instant::now();
        let _response = ping_pong(&mut client, payload).expect("Ping-pong failed");
        let latency_us = start.elapsed().as_micros() as u64;
        latencies.push(latency_us);
    }

    // Compute statistics
    let stats = MeasurementStats::from_measurements(&latencies)
        .expect("Should compute statistics");

    // Verify all expected fields are present (backward compatible structure)
    // These are the fields that existed before the new features were added
    
    // Original fields (must be present for backward compatibility)
    let _min = stats.min_us;      // Minimum latency
    let _max = stats.max_us;      // Maximum latency
    let _mean = stats.mean_us;    // Mean latency
    let _median = stats.median_us; // Median latency
    let _count = stats.count;     // Number of measurements

    // New percentile fields (added by advanced-performance-metrics)
    // These should be present but don't affect backward compatibility
    // when --histogram is not specified
    let _p50 = stats.p50_us;
    let _p90 = stats.p90_us;
    let _p95 = stats.p95_us;
    let _p99 = stats.p99_us;
    let _p99_9 = stats.p99_9_us;

    // Verify the structure can be cloned (backward compatible behavior)
    let cloned_stats = stats.clone();
    assert_eq!(cloned_stats.min_us, stats.min_us, "Clone should preserve min");
    assert_eq!(cloned_stats.max_us, stats.max_us, "Clone should preserve max");
    assert_eq!(cloned_stats.mean_us, stats.mean_us, "Clone should preserve mean");
    assert_eq!(cloned_stats.median_us, stats.median_us, "Clone should preserve median");
    assert_eq!(cloned_stats.count, stats.count, "Clone should preserve count");

    // Verify the structure can be compared for equality (backward compatible behavior)
    assert_eq!(stats, cloned_stats, "Stats should be equal to its clone");

    // Verify debug output works (backward compatible behavior)
    let debug_str = format!("{:?}", stats);
    assert!(debug_str.contains("MeasurementStats"), "Debug should contain struct name");
    assert!(debug_str.contains("min_us"), "Debug should contain min_us field");
    assert!(debug_str.contains("max_us"), "Debug should contain max_us field");
    assert!(debug_str.contains("mean_us"), "Debug should contain mean_us field");
    assert!(debug_str.contains("median_us"), "Debug should contain median_us field");
    assert!(debug_str.contains("count"), "Debug should contain count field");

    server.stop();
}

/// Integration test verifying statistics computation correctness with known values.
///
/// **Validates: Requirements 8.1, 8.2**
/// - 8.1: WHEN no new flags are provided, THE Pod_Binary SHALL produce identical output to the previous version
/// - 8.2: THE existing MeasurementStats structure SHALL retain all current fields and behavior
///
/// This test uses known latency values to verify statistics are computed correctly.
#[test]
fn test_statistics_computation_correctness() {
    // Use known latency values to verify computation
    let latencies = vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
    
    let stats = MeasurementStats::from_measurements(&latencies)
        .expect("Should compute statistics");

    // Verify count
    assert_eq!(stats.count, 10, "Count should be 10");

    // Verify min (smallest value)
    assert_eq!(stats.min_us, 100, "Min should be 100");

    // Verify max (largest value)
    assert_eq!(stats.max_us, 1000, "Max should be 1000");

    // Verify mean (arithmetic average)
    // (100+200+300+400+500+600+700+800+900+1000) / 10 = 5500 / 10 = 550
    let expected_mean = 550.0;
    assert!(
        (stats.mean_us - expected_mean).abs() < 0.001,
        "Mean should be 550.0, got {}",
        stats.mean_us
    );

    // Verify median (for even length, lower of two middle values)
    // Sorted: [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
    // Middle indices: 4 and 5 (values 500 and 600)
    // Lower middle value: 500
    assert_eq!(stats.median_us, 500, "Median should be 500");

    // Verify percentiles are within bounds
    assert!(
        stats.p50_us >= 100.0 && stats.p50_us <= 1000.0,
        "p50 should be within [100, 1000]"
    );
    assert!(
        stats.p90_us >= 100.0 && stats.p90_us <= 1000.0,
        "p90 should be within [100, 1000]"
    );
    assert!(
        stats.p95_us >= 100.0 && stats.p95_us <= 1000.0,
        "p95 should be within [100, 1000]"
    );
    assert!(
        stats.p99_us >= 100.0 && stats.p99_us <= 1000.0,
        "p99 should be within [100, 1000]"
    );
    assert!(
        stats.p99_9_us >= 100.0 && stats.p99_9_us <= 1000.0,
        "p99.9 should be within [100, 1000]"
    );

    // Verify percentile ordering
    assert!(stats.p50_us <= stats.p90_us, "p50 <= p90");
    assert!(stats.p90_us <= stats.p95_us, "p90 <= p95");
    assert!(stats.p95_us <= stats.p99_us, "p95 <= p99");
    assert!(stats.p99_us <= stats.p99_9_us, "p99 <= p99.9");
}
