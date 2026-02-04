//! Transport abstraction for vsock and TCP communication
//!
//! This module provides a unified interface for network communication
//! that supports both vsock (Virtual Socket) and standard TCP sockets.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use vsock::{VsockListener, VsockStream, VMADDR_CID_ANY};

/// Transport mode selection
///
/// Determines which underlying transport mechanism to use for communication.
/// Defaults to `Vsock` for backward compatibility with existing deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// Virtual Socket transport for Nitro Enclave communication
    Vsock,
    /// Standard TCP socket transport for local development and testing
    Tcp,
}

impl Default for TransportMode {
    fn default() -> Self {
        TransportMode::Vsock
    }
}

/// Configuration for transport layer
///
/// Contains the necessary parameters for establishing connections
/// based on the selected transport mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportConfig {
    /// Vsock configuration with optional CID and port
    ///
    /// - `cid`: Context Identifier for the target (required for client connections)
    /// - `port`: Port number for the vsock connection
    Vsock {
        /// Context Identifier (required for client, ignored for server)
        cid: Option<u32>,
        /// Port number
        port: u32,
    },
    /// TCP configuration with address and port
    ///
    /// - `address`: IP address to bind to (server) or connect to (client)
    /// - `port`: Port number for the TCP connection
    Tcp {
        /// IP address (e.g., "127.0.0.1", "0.0.0.0")
        address: String,
        /// Port number
        port: u32,
    },
}

/// A transport stream that can be either vsock or TCP
///
/// This enum provides a unified interface for reading and writing bytes
/// over either vsock or TCP connections. It implements the standard
/// `Read` and `Write` traits, allowing the protocol layer to work
/// identically regardless of the underlying transport.
#[derive(Debug)]
pub enum TransportStream {
    /// Vsock stream for Nitro Enclave communication
    Vsock(VsockStream),
    /// TCP stream for local development and testing
    Tcp(TcpStream),
}

impl Read for TransportStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TransportStream::Vsock(s) => s.read(buf),
            TransportStream::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for TransportStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            TransportStream::Vsock(s) => s.write(buf),
            TransportStream::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            TransportStream::Vsock(s) => s.flush(),
            TransportStream::Tcp(s) => s.flush(),
        }
    }
}

/// A transport listener that can be either vsock or TCP
///
/// This enum provides a unified interface for accepting incoming connections
/// over either vsock or TCP. It abstracts the differences between the two
/// transport mechanisms, allowing the server code to work identically
/// regardless of the underlying transport.
#[derive(Debug)]
pub enum TransportListener {
    /// Vsock listener for Nitro Enclave communication
    Vsock(VsockListener),
    /// TCP listener for local development and testing
    Tcp(TcpListener),
}

impl TransportListener {
    /// Bind to the specified transport configuration
    ///
    /// Creates a new listener bound to the address specified in the configuration.
    /// For vsock, binds to `VMADDR_CID_ANY` with the specified port.
    /// For TCP, binds to the specified address and port.
    ///
    /// # Arguments
    ///
    /// * `config` - The transport configuration specifying the bind parameters
    ///
    /// # Returns
    ///
    /// * `Ok(TransportListener)` - A listener ready to accept connections
    /// * `Err(std::io::Error)` - If binding fails (e.g., address in use, invalid address)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use enclave_performance::transport::{TransportConfig, TransportListener};
    ///
    /// // Bind to TCP
    /// let config = TransportConfig::Tcp {
    ///     address: "127.0.0.1".to_string(),
    ///     port: 5000,
    /// };
    /// let listener = TransportListener::bind(&config).expect("Failed to bind");
    /// ```
    pub fn bind(config: &TransportConfig) -> std::io::Result<Self> {
        match config {
            TransportConfig::Vsock { port, .. } => {
                let listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, *port)?;
                Ok(TransportListener::Vsock(listener))
            }
            TransportConfig::Tcp { address, port } => {
                let addr: SocketAddr = format!("{}:{}", address, port)
                    .parse()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                let listener = TcpListener::bind(addr)?;
                Ok(TransportListener::Tcp(listener))
            }
        }
    }

    /// Accept an incoming connection
    ///
    /// Blocks until a new connection is received, then returns a `TransportStream`
    /// that can be used for bidirectional communication.
    ///
    /// # Returns
    ///
    /// * `Ok(TransportStream)` - A stream for the accepted connection
    /// * `Err(std::io::Error)` - If accepting the connection fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use enclave_performance::transport::{TransportConfig, TransportListener};
    ///
    /// let config = TransportConfig::Tcp {
    ///     address: "127.0.0.1".to_string(),
    ///     port: 5000,
    /// };
    /// let listener = TransportListener::bind(&config).expect("Failed to bind");
    /// let stream = listener.accept().expect("Failed to accept connection");
    /// ```
    pub fn accept(&self) -> std::io::Result<TransportStream> {
        match self {
            TransportListener::Vsock(l) => {
                let (stream, _) = l.accept()?;
                Ok(TransportStream::Vsock(stream))
            }
            TransportListener::Tcp(l) => {
                let (stream, _) = l.accept()?;
                // Disable Nagle's algorithm for low-latency
                stream.set_nodelay(true)?;
                Ok(TransportStream::Tcp(stream))
            }
        }
    }

    /// Get the local address description for logging
    ///
    /// Returns a human-readable string describing the local address
    /// that the listener is bound to. Useful for logging and debugging.
    ///
    /// # Returns
    ///
    /// A string describing the local address:
    /// - For vsock: "vsock CID: <cid>"
    /// - For TCP: "TCP <address>:<port>"
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use enclave_performance::transport::{TransportConfig, TransportListener};
    ///
    /// let config = TransportConfig::Tcp {
    ///     address: "127.0.0.1".to_string(),
    ///     port: 5000,
    /// };
    /// let listener = TransportListener::bind(&config).expect("Failed to bind");
    /// println!("Listening on {}", listener.local_addr_string());
    /// // Output: "Listening on TCP 127.0.0.1:5000"
    /// ```
    pub fn local_addr_string(&self) -> String {
        match self {
            TransportListener::Vsock(_) => {
                let cid = vsock::get_local_cid().unwrap_or(0);
                format!("vsock CID: {}", cid)
            }
            TransportListener::Tcp(l) => {
                format!(
                    "TCP {}",
                    l.local_addr().map(|a| a.to_string()).unwrap_or_default()
                )
            }
        }
    }
}

/// Connect to a remote endpoint
///
/// Establishes a connection to a remote server using the specified transport
/// configuration. For vsock, connects using the CID and port. For TCP,
/// connects using the address and port.
///
/// # Arguments
///
/// * `config` - The transport configuration specifying the connection parameters
///
/// # Returns
///
/// * `Ok(TransportStream)` - A stream for bidirectional communication
/// * `Err(std::io::Error)` - If the connection fails
///
/// # Errors
///
/// Returns an error if:
/// - For vsock: CID is not provided (required for client connections)
/// - For vsock: The vsock connection fails (e.g., CID not reachable)
/// - For TCP: The address format is invalid
/// - For TCP: The connection is refused or times out
///
/// # Examples
///
/// ```no_run
/// use enclave_performance::transport::{TransportConfig, connect};
///
/// // Connect via TCP
/// let config = TransportConfig::Tcp {
///     address: "127.0.0.1".to_string(),
///     port: 5000,
/// };
/// let stream = connect(&config).expect("Failed to connect");
///
/// // Connect via vsock
/// let config = TransportConfig::Vsock {
///     cid: Some(16),
///     port: 5000,
/// };
/// let stream = connect(&config).expect("Failed to connect");
/// ```
pub fn connect(config: &TransportConfig) -> std::io::Result<TransportStream> {
    match config {
        TransportConfig::Vsock { cid, port } => {
            let cid = cid.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "CID required for vsock")
            })?;
            let stream = VsockStream::connect_with_cid_port(cid, *port)?;
            Ok(TransportStream::Vsock(stream))
        }
        TransportConfig::Tcp { address, port } => {
            let addr: SocketAddr = format!("{}:{}", address, port)
                .parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let stream = TcpStream::connect(addr)?;
            // Disable Nagle's algorithm for low-latency
            stream.set_nodelay(true)?;
            Ok(TransportStream::Tcp(stream))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Property-based test configuration
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        /// Feature: socket-transport-abstraction, Property 3: TransportStream Read/Write Equivalence
        ///
        /// **Property 3: TransportStream Read/Write Trait Equivalence**
        /// *For any* sequence of bytes written to a `TransportStream`, reading the same number
        /// of bytes SHALL return the identical byte sequence, regardless of whether the stream
        /// wraps a `VsockStream` or `TcpStream`.
        ///
        /// **Validates: Requirements 4.1, 4.2, 4.5, 4.6**
        #[test]
        fn prop_transport_stream_read_write_equivalence(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            use std::net::TcpListener;
            use std::io::{Read, Write};
            use std::thread;

            // Skip empty data case as there's nothing to verify
            if data.is_empty() {
                return Ok(());
            }

            // Create a TCP listener on a random available port
            let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind TCP listener");
            let addr = listener.local_addr().expect("Failed to get local address");
            let data_clone = data.clone();
            let data_len = data.len();

            // Spawn a thread to act as the writer (client)
            let writer_handle = thread::spawn(move || {
                let tcp_stream = std::net::TcpStream::connect(addr).expect("Failed to connect");
                let mut transport_stream = TransportStream::Tcp(tcp_stream);

                // Write the data to the TransportStream
                let bytes_written = transport_stream.write(&data_clone).expect("Failed to write");
                transport_stream.flush().expect("Failed to flush");

                bytes_written
            });

            // Accept the connection and read from it (server)
            let (server_tcp_stream, _) = listener.accept().expect("Failed to accept connection");
            let mut reader_stream = TransportStream::Tcp(server_tcp_stream);

            // Read the data back
            let mut read_buffer = vec![0u8; data_len];
            reader_stream.read_exact(&mut read_buffer).expect("Failed to read");

            // Wait for writer to complete
            let bytes_written = writer_handle.join().expect("Writer thread panicked");

            // Verify byte-for-byte equivalence
            prop_assert_eq!(bytes_written, data_len, "Bytes written should equal data length");
            prop_assert_eq!(read_buffer, data, "Read data should be identical to written data");
        }

        /// Feature: socket-transport-abstraction, Property 3: TransportStream Read/Write Equivalence
        ///
        /// Additional property test for chunked read/write operations.
        /// Verifies that data written in multiple chunks can be read back correctly.
        ///
        /// **Validates: Requirements 4.1, 4.2, 4.5, 4.6**
        #[test]
        fn prop_transport_stream_chunked_read_write(
            chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..256), 1..10)
        ) {
            use std::net::TcpListener;
            use std::io::{Read, Write};
            use std::thread;

            // Calculate total data size
            let total_size: usize = chunks.iter().map(|c| c.len()).sum();
            let expected_data: Vec<u8> = chunks.iter().flatten().copied().collect();

            // Create a TCP listener on a random available port
            let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind TCP listener");
            let addr = listener.local_addr().expect("Failed to get local address");
            let chunks_clone = chunks.clone();

            // Spawn a thread to act as the writer (client)
            let writer_handle = thread::spawn(move || {
                let tcp_stream = std::net::TcpStream::connect(addr).expect("Failed to connect");
                let mut transport_stream = TransportStream::Tcp(tcp_stream);

                // Write data in chunks
                let mut total_written = 0;
                for chunk in &chunks_clone {
                    let bytes_written = transport_stream.write(chunk).expect("Failed to write chunk");
                    total_written += bytes_written;
                }
                transport_stream.flush().expect("Failed to flush");

                total_written
            });

            // Accept the connection and read from it (server)
            let (server_tcp_stream, _) = listener.accept().expect("Failed to accept connection");
            let mut reader_stream = TransportStream::Tcp(server_tcp_stream);

            // Read all data back
            let mut read_buffer = vec![0u8; total_size];
            reader_stream.read_exact(&mut read_buffer).expect("Failed to read");

            // Wait for writer to complete
            let bytes_written = writer_handle.join().expect("Writer thread panicked");

            // Verify byte-for-byte equivalence
            prop_assert_eq!(bytes_written, total_size, "Total bytes written should equal total data size");
            prop_assert_eq!(read_buffer, expected_data, "Read data should be identical to written data");
        }
    }

    #[test]
    fn test_transport_mode_default_is_vsock() {
        let mode = TransportMode::default();
        assert_eq!(mode, TransportMode::Vsock);
    }

    #[test]
    fn test_transport_mode_equality() {
        assert_eq!(TransportMode::Vsock, TransportMode::Vsock);
        assert_eq!(TransportMode::Tcp, TransportMode::Tcp);
        assert_ne!(TransportMode::Vsock, TransportMode::Tcp);
    }

    #[test]
    fn test_transport_mode_clone() {
        let mode = TransportMode::Tcp;
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_transport_mode_copy() {
        let mode = TransportMode::Vsock;
        let copied: TransportMode = mode; // Copy trait
        assert_eq!(mode, copied);
    }

    #[test]
    fn test_transport_mode_debug() {
        assert_eq!(format!("{:?}", TransportMode::Vsock), "Vsock");
        assert_eq!(format!("{:?}", TransportMode::Tcp), "Tcp");
    }

    #[test]
    fn test_transport_config_vsock() {
        let config = TransportConfig::Vsock {
            cid: Some(16),
            port: 5000,
        };
        
        if let TransportConfig::Vsock { cid, port } = config {
            assert_eq!(cid, Some(16));
            assert_eq!(port, 5000);
        } else {
            panic!("Expected Vsock config");
        }
    }

    #[test]
    fn test_transport_config_vsock_no_cid() {
        let config = TransportConfig::Vsock {
            cid: None,
            port: 5000,
        };
        
        if let TransportConfig::Vsock { cid, port } = config {
            assert_eq!(cid, None);
            assert_eq!(port, 5000);
        } else {
            panic!("Expected Vsock config");
        }
    }

    #[test]
    fn test_transport_config_tcp() {
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: 8080,
        };
        
        if let TransportConfig::Tcp { address, port } = config {
            assert_eq!(address, "127.0.0.1");
            assert_eq!(port, 8080);
        } else {
            panic!("Expected Tcp config");
        }
    }

    #[test]
    fn test_transport_config_tcp_all_interfaces() {
        let config = TransportConfig::Tcp {
            address: "0.0.0.0".to_string(),
            port: 3000,
        };
        
        if let TransportConfig::Tcp { address, port } = config {
            assert_eq!(address, "0.0.0.0");
            assert_eq!(port, 3000);
        } else {
            panic!("Expected Tcp config");
        }
    }

    #[test]
    fn test_transport_config_clone() {
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: 5000,
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn test_transport_config_equality() {
        let config1 = TransportConfig::Vsock {
            cid: Some(16),
            port: 5000,
        };
        let config2 = TransportConfig::Vsock {
            cid: Some(16),
            port: 5000,
        };
        let config3 = TransportConfig::Vsock {
            cid: Some(17),
            port: 5000,
        };
        
        assert_eq!(config1, config2);
        assert_ne!(config1, config3);
    }

    #[test]
    fn test_transport_config_debug() {
        let vsock_config = TransportConfig::Vsock {
            cid: Some(16),
            port: 5000,
        };
        let debug_str = format!("{:?}", vsock_config);
        assert!(debug_str.contains("Vsock"));
        assert!(debug_str.contains("16"));
        assert!(debug_str.contains("5000"));

        let tcp_config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: 8080,
        };
        let debug_str = format!("{:?}", tcp_config);
        assert!(debug_str.contains("Tcp"));
        assert!(debug_str.contains("127.0.0.1"));
        assert!(debug_str.contains("8080"));
    }

    // TransportStream tests
    // Note: Full Read/Write trait testing requires actual network connections
    // or mock streams. These tests verify the enum structure and Debug trait.

    #[test]
    fn test_transport_stream_debug_tcp() {
        use std::net::TcpListener;
        
        // Create a TCP listener and connect to it to get a TcpStream
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Connect in a separate thread
        let handle = std::thread::spawn(move || {
            std::net::TcpStream::connect(addr).unwrap()
        });
        
        // Accept the connection
        let (_server_stream, _) = listener.accept().unwrap();
        let client_stream = handle.join().unwrap();
        
        let transport = TransportStream::Tcp(client_stream);
        let debug_str = format!("{:?}", transport);
        assert!(debug_str.contains("Tcp"));
    }

    #[test]
    fn test_transport_stream_tcp_read_write() {
        use std::net::TcpListener;
        use std::io::{Read, Write};
        
        // Create a TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Connect in a separate thread
        let handle = std::thread::spawn(move || {
            let stream = std::net::TcpStream::connect(addr).unwrap();
            TransportStream::Tcp(stream)
        });
        
        // Accept the connection
        let (server_tcp_stream, _) = listener.accept().unwrap();
        let mut server_stream = TransportStream::Tcp(server_tcp_stream);
        let mut client_stream = handle.join().unwrap();
        
        // Test write from client
        let test_data = b"Hello, Transport!";
        let bytes_written = client_stream.write(test_data).unwrap();
        assert_eq!(bytes_written, test_data.len());
        client_stream.flush().unwrap();
        
        // Test read on server
        let mut buf = [0u8; 17];
        let bytes_read = server_stream.read(&mut buf).unwrap();
        assert_eq!(bytes_read, test_data.len());
        assert_eq!(&buf[..bytes_read], test_data);
    }

    #[test]
    fn test_transport_stream_tcp_bidirectional() {
        use std::net::TcpListener;
        use std::io::{Read, Write};
        
        // Create a TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Connect in a separate thread
        let handle = std::thread::spawn(move || {
            let stream = std::net::TcpStream::connect(addr).unwrap();
            TransportStream::Tcp(stream)
        });
        
        // Accept the connection
        let (server_tcp_stream, _) = listener.accept().unwrap();
        let mut server_stream = TransportStream::Tcp(server_tcp_stream);
        let mut client_stream = handle.join().unwrap();
        
        // Client sends request
        let request = b"REQUEST";
        client_stream.write_all(request).unwrap();
        client_stream.flush().unwrap();
        
        // Server reads request
        let mut buf = [0u8; 7];
        server_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, request);
        
        // Server sends response
        let response = b"RESPONSE";
        server_stream.write_all(response).unwrap();
        server_stream.flush().unwrap();
        
        // Client reads response
        let mut buf = [0u8; 8];
        client_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, response);
    }

    // TransportListener tests

    #[test]
    fn test_transport_listener_bind_tcp() {
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: 0, // Use port 0 to let OS assign an available port
        };
        
        let listener = TransportListener::bind(&config);
        assert!(listener.is_ok(), "Should successfully bind to TCP");
        
        let listener = listener.unwrap();
        if let TransportListener::Tcp(_) = listener {
            // Expected
        } else {
            panic!("Expected TCP listener");
        }
    }

    #[test]
    fn test_transport_listener_bind_tcp_all_interfaces() {
        let config = TransportConfig::Tcp {
            address: "0.0.0.0".to_string(),
            port: 0,
        };
        
        let listener = TransportListener::bind(&config);
        assert!(listener.is_ok(), "Should successfully bind to all interfaces");
    }

    #[test]
    fn test_transport_listener_bind_tcp_invalid_address() {
        let config = TransportConfig::Tcp {
            address: "invalid-address".to_string(),
            port: 5000,
        };
        
        let listener = TransportListener::bind(&config);
        assert!(listener.is_err(), "Should fail with invalid address");
        
        let err = listener.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_transport_listener_local_addr_string_tcp() {
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: 0,
        };
        
        let listener = TransportListener::bind(&config).unwrap();
        let addr_str = listener.local_addr_string();
        
        assert!(addr_str.starts_with("TCP "), "Should start with 'TCP '");
        assert!(addr_str.contains("127.0.0.1"), "Should contain the IP address");
    }

    #[test]
    fn test_transport_listener_accept_tcp() {
        use std::io::{Read, Write};
        
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: 0,
        };
        
        let listener = TransportListener::bind(&config).unwrap();
        
        // Get the actual bound address
        let addr = if let TransportListener::Tcp(ref l) = listener {
            l.local_addr().unwrap()
        } else {
            panic!("Expected TCP listener");
        };
        
        // Connect in a separate thread
        let handle = std::thread::spawn(move || {
            std::net::TcpStream::connect(addr).unwrap()
        });
        
        // Accept the connection using TransportListener
        let stream = listener.accept();
        assert!(stream.is_ok(), "Should successfully accept connection");
        
        let mut server_stream = stream.unwrap();
        let client_stream = handle.join().unwrap();
        let mut client_stream = TransportStream::Tcp(client_stream);
        
        // Verify the stream works
        let test_data = b"Hello via TransportListener!";
        client_stream.write_all(test_data).unwrap();
        client_stream.flush().unwrap();
        
        let mut buf = vec![0u8; test_data.len()];
        server_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, test_data);
    }

    #[test]
    fn test_transport_listener_debug_tcp() {
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: 0,
        };
        
        let listener = TransportListener::bind(&config).unwrap();
        let debug_str = format!("{:?}", listener);
        assert!(debug_str.contains("Tcp"), "Debug output should contain 'Tcp'");
    }

    // connect() function tests

    #[test]
    fn test_connect_tcp_success() {
        use std::net::TcpListener;
        use std::io::{Read, Write};
        
        // Create a TCP listener on a random available port
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Spawn a thread to accept the connection
        let handle = std::thread::spawn(move || {
            listener.accept().unwrap()
        });
        
        // Connect using the connect function
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: addr.port() as u32,
        };
        
        let mut client_stream = connect(&config).expect("Should connect successfully");
        
        // Get the server stream
        let (server_tcp_stream, _) = handle.join().unwrap();
        let mut server_stream = TransportStream::Tcp(server_tcp_stream);
        
        // Verify the connection works
        let test_data = b"Hello via connect!";
        client_stream.write_all(test_data).unwrap();
        client_stream.flush().unwrap();
        
        let mut buf = vec![0u8; test_data.len()];
        server_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, test_data);
    }

    #[test]
    fn test_connect_tcp_bidirectional() {
        use std::net::TcpListener;
        use std::io::{Read, Write};
        
        // Create a TCP listener
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Spawn a thread to accept the connection
        let handle = std::thread::spawn(move || {
            listener.accept().unwrap()
        });
        
        // Connect using the connect function
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: addr.port() as u32,
        };
        
        let mut client_stream = connect(&config).expect("Should connect successfully");
        
        // Get the server stream
        let (server_tcp_stream, _) = handle.join().unwrap();
        let mut server_stream = TransportStream::Tcp(server_tcp_stream);
        
        // Client sends request
        let request = b"REQUEST";
        client_stream.write_all(request).unwrap();
        client_stream.flush().unwrap();
        
        // Server reads request
        let mut buf = [0u8; 7];
        server_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, request);
        
        // Server sends response
        let response = b"RESPONSE";
        server_stream.write_all(response).unwrap();
        server_stream.flush().unwrap();
        
        // Client reads response
        let mut buf = [0u8; 8];
        client_stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, response);
    }

    #[test]
    fn test_connect_tcp_invalid_address() {
        let config = TransportConfig::Tcp {
            address: "invalid-address".to_string(),
            port: 5000,
        };
        
        let result = connect(&config);
        assert!(result.is_err(), "Should fail with invalid address");
        
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_connect_tcp_connection_refused() {
        // Try to connect to a port that's not listening
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: 59999, // Unlikely to be in use
        };
        
        let result = connect(&config);
        assert!(result.is_err(), "Should fail when connection is refused");
        
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn test_connect_vsock_missing_cid() {
        let config = TransportConfig::Vsock {
            cid: None,
            port: 5000,
        };
        
        let result = connect(&config);
        assert!(result.is_err(), "Should fail when CID is missing for vsock");
        
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("CID required"), "Error message should mention CID requirement");
    }

    #[test]
    fn test_transport_listener_multiple_accepts_tcp() {
        use std::io::{Read, Write};
        
        let config = TransportConfig::Tcp {
            address: "127.0.0.1".to_string(),
            port: 0,
        };
        
        let listener = TransportListener::bind(&config).unwrap();
        
        // Get the actual bound address
        let addr = if let TransportListener::Tcp(ref l) = listener {
            l.local_addr().unwrap()
        } else {
            panic!("Expected TCP listener");
        };
        
        // Test accepting multiple connections
        for i in 0..3 {
            let addr_clone = addr;
            let handle = std::thread::spawn(move || {
                let stream = std::net::TcpStream::connect(addr_clone).unwrap();
                TransportStream::Tcp(stream)
            });
            
            let mut server_stream = listener.accept().unwrap();
            let mut client_stream = handle.join().unwrap();
            
            // Verify each connection works independently
            let test_data = format!("Connection {}", i);
            client_stream.write_all(test_data.as_bytes()).unwrap();
            client_stream.flush().unwrap();
            
            let mut buf = vec![0u8; test_data.len()];
            server_stream.read_exact(&mut buf).unwrap();
            assert_eq!(String::from_utf8(buf).unwrap(), test_data);
        }
    }
}
