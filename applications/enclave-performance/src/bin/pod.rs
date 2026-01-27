//! Pod Binary
//!
//! Runs from the Kubernetes pod, executes performance tests against
//! the enclave, and reports statistics.

use clap::{Parser, ValueEnum};
use enclave_performance::json::JsonTestPayload;
use enclave_performance::protocol::{Message, MessageType, ProtocolError};
use enclave_performance::stats::MeasurementStats;
use std::time::Instant;
use thiserror::Error;
use vsock::VsockStream;

/// Measurement mode for performance tests
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MeasurementMode {
    /// Raw vsock roundtrip latency measurement
    Roundtrip,
    /// JSON serialization overhead measurement
    Json,
    /// Secp256k1 signing latency measurement
    Sign,
}

/// CLI arguments for the enclave performance measurement tool
#[derive(Parser, Debug)]
#[command(name = "enclave-perf")]
#[command(about = "Measure vsock communication performance with Nitro Enclave")]
pub struct PodArgs {
    /// Target enclave CID
    #[arg(short, long)]
    pub cid: u32,

    /// Vsock port number
    #[arg(short, long, default_value = "5000")]
    pub port: u32,

    /// Measurement mode
    #[arg(short, long, value_enum)]
    pub mode: MeasurementMode,

    /// Number of iterations
    #[arg(short = 'n', long, default_value = "100")]
    pub iterations: usize,
}

impl PodArgs {
    /// Validate the arguments and return an error message if invalid
    pub fn validate(&self) -> Result<(), String> {
        // CID 0 is reserved (VMADDR_CID_HYPERVISOR)
        // CID 1 is reserved (VMADDR_CID_LOCAL)
        // CID 2 is the host (VMADDR_CID_HOST)
        // Valid enclave CIDs start from 3
        if self.cid < 3 {
            return Err(format!(
                "Invalid CID: {}. CID must be 3 or greater (0-2 are reserved)",
                self.cid
            ));
        }

        // Iterations must be at least 1
        if self.iterations == 0 {
            return Err("Iterations must be at least 1".to_string());
        }

        Ok(())
    }
}

/// Pod binary errors
#[derive(Debug, Error)]
pub enum PodError {
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("Connection failed: {0}")]
    Connection(#[from] std::io::Error),

    #[error("Invalid CID: {0}")]
    InvalidCid(u32),

    #[error("Unexpected response type: expected {expected:?}, got {actual:?}")]
    UnexpectedResponse {
        expected: MessageType,
        actual: MessageType,
    },
}

/// Result of a measurement run
///
/// Contains the measurement mode, iteration count, and calculated statistics.
/// Provides a `print_report()` method to display results.
///
/// Requirements: 3.4, 4.4, 5.5
#[derive(Debug, Clone)]
pub struct MeasurementResult {
    /// The measurement mode used
    pub mode: MeasurementMode,
    /// Number of iterations performed
    pub iterations: usize,
    /// Calculated statistics from the measurements
    pub stats: MeasurementStats,
}

impl MeasurementResult {
    /// Create a new MeasurementResult from latency measurements
    ///
    /// Returns `None` if the latencies slice is empty.
    pub fn from_latencies(mode: MeasurementMode, latencies: &[u64]) -> Option<Self> {
        let stats = MeasurementStats::from_measurements(latencies)?;
        Some(MeasurementResult {
            mode,
            iterations: latencies.len(),
            stats,
        })
    }

    /// Print a formatted report of the measurement results
    ///
    /// Displays mode, iteration count, and all statistics (min, max, mean, median)
    /// in microseconds.
    ///
    /// Requirements: 3.4, 4.4, 5.5
    pub fn print_report(&self) {
        println!("Mode: {:?}", self.mode);
        println!("Iterations: {}", self.iterations);
        println!("Min: {} µs", self.stats.min_us);
        println!("Max: {} µs", self.stats.max_us);
        println!("Mean: {:.2} µs", self.stats.mean_us);
        println!("Median: {} µs", self.stats.median_us);
    }
}

/// Execute a single roundtrip measurement
///
/// Sends a ping message and waits for a pong response.
/// Returns the roundtrip time in microseconds.
///
/// Requirements: 3.1, 3.3
fn execute_roundtrip(stream: &mut VsockStream) -> Result<u64, PodError> {
    // Create a fixed-size ping payload (32 bytes)
    let ping_payload = vec![0u8; 32];
    let ping_msg = Message::ping(ping_payload)?;

    // Record start time
    let start = Instant::now();

    // Send ping
    ping_msg.write_to(stream)?;

    // Receive pong
    let response = Message::read_from(stream)?;

    // Record end time and calculate latency
    let latency_us = start.elapsed().as_micros() as u64;

    // Verify response type
    let response_type = response.message_type()?;
    if response_type != MessageType::Pong {
        return Err(PodError::UnexpectedResponse {
            expected: MessageType::Pong,
            actual: response_type,
        });
    }

    Ok(latency_us)
}

/// Execute a single JSON serialization measurement
///
/// Serializes a test payload to JSON, sends it, receives the response,
/// and deserializes it.
/// Returns the roundtrip time in microseconds.
///
/// Requirements: 4.1, 4.3
fn execute_json(stream: &mut VsockStream, sequence: u32) -> Result<u64, PodError> {
    // Create test payload
    let payload = JsonTestPayload::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64,
        sequence,
        "performance test data".to_string(),
    );

    // Serialize to JSON
    let json_bytes = serde_json::to_vec(&payload).map_err(ProtocolError::Serialization)?;

    // Create JSON request message
    let request_msg = Message::new(MessageType::JsonRequest, json_bytes)?;

    // Record start time
    let start = Instant::now();

    // Send request
    request_msg.write_to(stream)?;

    // Receive response
    let response = Message::read_from(stream)?;

    // Record end time and calculate latency
    let latency_us = start.elapsed().as_micros() as u64;

    // Verify response type
    let response_type = response.message_type()?;
    if response_type != MessageType::JsonResponse {
        return Err(PodError::UnexpectedResponse {
            expected: MessageType::JsonResponse,
            actual: response_type,
        });
    }

    // Deserialize response to verify it's valid JSON
    let _response_payload: JsonTestPayload =
        serde_json::from_slice(&response.payload).map_err(ProtocolError::Serialization)?;

    Ok(latency_us)
}

/// Execute a single signing measurement
///
/// Sends a message to be signed and receives the signature.
/// Returns the roundtrip time in microseconds.
///
/// Requirements: 5.2, 5.4
fn execute_sign(stream: &mut VsockStream) -> Result<u64, PodError> {
    // Create a message to be signed (32 bytes - typical hash size)
    let message_to_sign = vec![0xABu8; 32];

    // Create sign request message
    let request_msg = Message::new(MessageType::SignRequest, message_to_sign)?;

    // Record start time
    let start = Instant::now();

    // Send request
    request_msg.write_to(stream)?;

    // Receive response
    let response = Message::read_from(stream)?;

    // Record end time and calculate latency
    let latency_us = start.elapsed().as_micros() as u64;

    // Verify response type
    let response_type = response.message_type()?;
    if response_type != MessageType::SignResponse {
        return Err(PodError::UnexpectedResponse {
            expected: MessageType::SignResponse,
            actual: response_type,
        });
    }

    Ok(latency_us)
}

/// Result of running measurements, including any iteration errors
///
/// Contains successful latencies and a count of failed iterations.
pub struct MeasurementRunResult {
    /// Successful latency measurements in microseconds
    pub latencies: Vec<u64>,
    /// Number of iterations that failed
    pub failed_iterations: usize,
    /// Error messages for failed iterations (iteration number, error message)
    pub iteration_errors: Vec<(usize, String)>,
}

/// Run measurements for the specified mode
///
/// Performs a warmup iteration, then executes the measurement loop.
/// Returns successful latencies and reports errors for failed iterations.
/// Connection failures during initial connect will return an error.
/// Malformed responses during iterations are reported but don't stop the run.
///
/// Requirements: 3.1, 3.3, 4.1, 4.3, 5.2, 5.4, 6.4, 8.4
pub fn run_measurements(args: &PodArgs) -> Result<MeasurementRunResult, PodError> {
    // Connect to enclave via vsock
    // Connection failures are fatal and return an error with clear message
    let mut stream = VsockStream::connect_with_cid_port(args.cid, args.port).map_err(|e| {
        // Provide clear error message for connection failures
        PodError::Connection(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to connect to enclave at CID {} port {}: {}",
                args.cid, args.port, e
            ),
        ))
    })?;

    // Perform warmup iteration (Requirement 6.4)
    println!("Performing warmup iteration...");
    match args.mode {
        MeasurementMode::Roundtrip => {
            execute_roundtrip(&mut stream)?;
        }
        MeasurementMode::Json => {
            execute_json(&mut stream, 0)?;
        }
        MeasurementMode::Sign => {
            execute_sign(&mut stream)?;
        }
    }

    // Pre-allocate latencies vector for performance (Requirement 6.3)
    let mut latencies = Vec::with_capacity(args.iterations);
    let mut iteration_errors: Vec<(usize, String)> = Vec::new();

    // Execute measurement loop
    // Requirement 8.4: Report errors for individual iterations but continue
    println!("Running {} iterations...", args.iterations);
    for i in 0..args.iterations {
        let result = match args.mode {
            MeasurementMode::Roundtrip => execute_roundtrip(&mut stream),
            MeasurementMode::Json => execute_json(&mut stream, (i + 1) as u32),
            MeasurementMode::Sign => execute_sign(&mut stream),
        };

        match result {
            Ok(latency) => {
                latencies.push(latency);
            }
            Err(e) => {
                // Report error for this iteration (Requirement 8.4)
                let error_msg = format!("Iteration {} failed: {}", i + 1, e);
                eprintln!("Warning: {}", error_msg);
                iteration_errors.push((i + 1, error_msg));
            }
        }
    }

    Ok(MeasurementRunResult {
        latencies,
        failed_iterations: iteration_errors.len(),
        iteration_errors,
    })
}

fn main() {
    let args = PodArgs::parse();

    // Validate arguments
    if let Err(e) = args.validate() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // Print configuration
    println!("Enclave Performance Measurement Tool");
    println!("=====================================");
    println!("Target CID: {}", args.cid);
    println!("Port: {}", args.port);
    println!("Mode: {:?}", args.mode);
    println!("Iterations: {}", args.iterations);
    println!();

    // Run measurements
    match run_measurements(&args) {
        Ok(run_result) => {
            // Report any iteration failures
            if run_result.failed_iterations > 0 {
                println!();
                println!(
                    "Warning: {} of {} iterations failed",
                    run_result.failed_iterations, args.iterations
                );
            }

            // Check if we have any successful measurements
            if run_result.latencies.is_empty() {
                eprintln!("Error: All iterations failed. No measurements collected.");
                // Print summary of errors
                for (iter, error) in &run_result.iteration_errors {
                    eprintln!("  Iteration {}: {}", iter, error);
                }
                std::process::exit(1);
            }

            // Create MeasurementResult and print report
            match MeasurementResult::from_latencies(args.mode, &run_result.latencies) {
                Some(result) => {
                    println!();
                    println!("Results:");
                    println!("--------");
                    result.print_report();
                    println!(
                        "Successful iterations: {}/{}",
                        run_result.latencies.len(),
                        args.iterations
                    );
                }
                None => {
                    eprintln!("Error: No measurements collected");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            // Handle connection failures and other fatal errors with clear messages
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests for CLI argument parsing

    #[test]
    fn test_parse_valid_args() {
        let args = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--port",
            "5000",
            "--mode",
            "roundtrip",
            "--iterations",
            "50",
        ])
        .unwrap();

        assert_eq!(args.cid, 10);
        assert_eq!(args.port, 5000);
        assert_eq!(args.mode, MeasurementMode::Roundtrip);
        assert_eq!(args.iterations, 50);
    }

    #[test]
    fn test_parse_with_defaults() {
        let args = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "json",
        ])
        .unwrap();

        assert_eq!(args.cid, 10);
        assert_eq!(args.port, 5000); // default
        assert_eq!(args.mode, MeasurementMode::Json);
        assert_eq!(args.iterations, 100); // default
    }

    #[test]
    fn test_parse_sign_mode() {
        let args = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "5",
            "--mode",
            "sign",
        ])
        .unwrap();

        assert_eq!(args.mode, MeasurementMode::Sign);
    }

    #[test]
    fn test_parse_short_flags() {
        let args = PodArgs::try_parse_from([
            "enclave-perf",
            "-c",
            "10",
            "-p",
            "6000",
            "-m",
            "roundtrip",
            "-n",
            "200",
        ])
        .unwrap();

        assert_eq!(args.cid, 10);
        assert_eq!(args.port, 6000);
        assert_eq!(args.mode, MeasurementMode::Roundtrip);
        assert_eq!(args.iterations, 200);
    }

    #[test]
    fn test_missing_required_cid() {
        let result = PodArgs::try_parse_from([
            "enclave-perf",
            "--mode",
            "roundtrip",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_mode() {
        let result = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_mode() {
        let result = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "invalid",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_cid_zero() {
        let args = PodArgs {
            cid: 0,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
        };

        let result = args.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid CID"));
    }

    #[test]
    fn test_validate_invalid_cid_one() {
        let args = PodArgs {
            cid: 1,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
        };

        let result = args.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_cid_two() {
        let args = PodArgs {
            cid: 2,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
        };

        let result = args.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_valid_cid_three() {
        let args = PodArgs {
            cid: 3,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
        };

        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_zero_iterations() {
        let args = PodArgs {
            cid: 10,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 0,
        };

        let result = args.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Iterations"));
    }

    #[test]
    fn test_validate_valid_args() {
        let args = PodArgs {
            cid: 10,
            port: 5000,
            mode: MeasurementMode::Json,
            iterations: 100,
        };

        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_measurement_mode_clone() {
        let mode = MeasurementMode::Roundtrip;
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_measurement_mode_debug() {
        let mode = MeasurementMode::Json;
        let debug_str = format!("{:?}", mode);
        assert_eq!(debug_str, "Json");
    }

    // Unit tests for MeasurementResult

    #[test]
    fn test_measurement_result_from_latencies() {
        let latencies = vec![100, 200, 150, 300, 250];
        let result = MeasurementResult::from_latencies(MeasurementMode::Roundtrip, &latencies);
        
        assert!(result.is_some());
        let result = result.unwrap();
        
        assert_eq!(result.mode, MeasurementMode::Roundtrip);
        assert_eq!(result.iterations, 5);
        assert_eq!(result.stats.min_us, 100);
        assert_eq!(result.stats.max_us, 300);
        assert_eq!(result.stats.mean_us, 200.0);
        assert_eq!(result.stats.median_us, 200);
    }

    #[test]
    fn test_measurement_result_empty_latencies() {
        let latencies: Vec<u64> = vec![];
        let result = MeasurementResult::from_latencies(MeasurementMode::Json, &latencies);
        
        assert!(result.is_none());
    }

    #[test]
    fn test_measurement_result_single_latency() {
        let latencies = vec![42];
        let result = MeasurementResult::from_latencies(MeasurementMode::Sign, &latencies);
        
        assert!(result.is_some());
        let result = result.unwrap();
        
        assert_eq!(result.mode, MeasurementMode::Sign);
        assert_eq!(result.iterations, 1);
        assert_eq!(result.stats.min_us, 42);
        assert_eq!(result.stats.max_us, 42);
        assert_eq!(result.stats.mean_us, 42.0);
        assert_eq!(result.stats.median_us, 42);
    }

    #[test]
    fn test_measurement_result_json_mode() {
        let latencies = vec![500, 600, 550];
        let result = MeasurementResult::from_latencies(MeasurementMode::Json, &latencies);
        
        assert!(result.is_some());
        let result = result.unwrap();
        
        assert_eq!(result.mode, MeasurementMode::Json);
        assert_eq!(result.iterations, 3);
    }

    #[test]
    fn test_measurement_result_sign_mode() {
        let latencies = vec![1000, 1100, 1050, 1200];
        let result = MeasurementResult::from_latencies(MeasurementMode::Sign, &latencies);
        
        assert!(result.is_some());
        let result = result.unwrap();
        
        assert_eq!(result.mode, MeasurementMode::Sign);
        assert_eq!(result.iterations, 4);
    }

    #[test]
    fn test_measurement_result_clone() {
        let latencies = vec![100, 200, 300];
        let result = MeasurementResult::from_latencies(MeasurementMode::Roundtrip, &latencies).unwrap();
        let cloned = result.clone();
        
        assert_eq!(result.mode, cloned.mode);
        assert_eq!(result.iterations, cloned.iterations);
        assert_eq!(result.stats.min_us, cloned.stats.min_us);
        assert_eq!(result.stats.max_us, cloned.stats.max_us);
    }

    #[test]
    fn test_measurement_result_debug() {
        let latencies = vec![100, 200];
        let result = MeasurementResult::from_latencies(MeasurementMode::Roundtrip, &latencies).unwrap();
        let debug_str = format!("{:?}", result);
        
        assert!(debug_str.contains("MeasurementResult"));
        assert!(debug_str.contains("Roundtrip"));
    }

    // Unit tests for PodError (Task 8.1)

    #[test]
    fn test_pod_error_protocol_variant() {
        // Test that PodError::Protocol can be created from ProtocolError
        let protocol_error = ProtocolError::InvalidMessageType(99);
        let pod_error: PodError = protocol_error.into();
        
        // Verify the error message contains the expected text
        let error_msg = format!("{}", pod_error);
        assert!(error_msg.contains("Protocol error"));
        assert!(error_msg.contains("99"));
    }

    #[test]
    fn test_pod_error_connection_variant() {
        // Test that PodError::Connection can be created from std::io::Error
        let io_error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused");
        let pod_error: PodError = io_error.into();
        
        // Verify the error message contains the expected text
        let error_msg = format!("{}", pod_error);
        assert!(error_msg.contains("Connection failed"));
        assert!(error_msg.contains("connection refused"));
    }

    #[test]
    fn test_pod_error_invalid_cid_variant() {
        // Test the InvalidCid variant
        let pod_error = PodError::InvalidCid(0);
        
        // Verify the error message contains the expected text
        let error_msg = format!("{}", pod_error);
        assert!(error_msg.contains("Invalid CID"));
        assert!(error_msg.contains("0"));
    }

    #[test]
    fn test_pod_error_invalid_cid_various_values() {
        // Test InvalidCid with various CID values
        for cid in [0u32, 1, 2, 100, u32::MAX] {
            let pod_error = PodError::InvalidCid(cid);
            let error_msg = format!("{}", pod_error);
            assert!(error_msg.contains(&cid.to_string()));
        }
    }

    #[test]
    fn test_pod_error_unexpected_response_variant() {
        // Test the UnexpectedResponse variant
        let pod_error = PodError::UnexpectedResponse {
            expected: MessageType::Pong,
            actual: MessageType::JsonResponse,
        };
        
        // Verify the error message contains the expected text
        let error_msg = format!("{}", pod_error);
        assert!(error_msg.contains("Unexpected response"));
        assert!(error_msg.contains("Pong"));
        assert!(error_msg.contains("JsonResponse"));
    }

    #[test]
    fn test_pod_error_debug_format() {
        // Test that PodError implements Debug correctly
        let pod_error = PodError::InvalidCid(42);
        
        let debug_str = format!("{:?}", pod_error);
        assert!(debug_str.contains("InvalidCid"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_pod_error_from_protocol_error_conversion() {
        // Test the From<ProtocolError> implementation
        let protocol_error = ProtocolError::PayloadTooLarge(2000000);
        let pod_error = PodError::from(protocol_error);
        
        match pod_error {
            PodError::Protocol(_) => {} // Expected
            _ => panic!("Expected Protocol variant"),
        }
    }

    #[test]
    fn test_pod_error_from_io_error_conversion() {
        // Test the From<std::io::Error> implementation
        let io_error = std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out");
        let pod_error = PodError::from(io_error);
        
        match pod_error {
            PodError::Connection(_) => {} // Expected
            _ => panic!("Expected Connection variant"),
        }
    }

    // Unit tests for MeasurementRunResult (Task 8.3)
    // Tests for error handling during measurement iterations

    #[test]
    fn test_measurement_run_result_all_successful() {
        // Test MeasurementRunResult with all successful iterations
        let run_result = MeasurementRunResult {
            latencies: vec![100, 200, 150],
            failed_iterations: 0,
            iteration_errors: vec![],
        };

        assert_eq!(run_result.latencies.len(), 3);
        assert_eq!(run_result.failed_iterations, 0);
        assert!(run_result.iteration_errors.is_empty());
    }

    #[test]
    fn test_measurement_run_result_partial_failures() {
        // Test MeasurementRunResult with some failed iterations
        // Requirement 8.4: Report errors for individual iterations
        let run_result = MeasurementRunResult {
            latencies: vec![100, 200],
            failed_iterations: 2,
            iteration_errors: vec![
                (3, "Iteration 3 failed: Unexpected response".to_string()),
                (5, "Iteration 5 failed: Protocol error".to_string()),
            ],
        };

        assert_eq!(run_result.latencies.len(), 2);
        assert_eq!(run_result.failed_iterations, 2);
        assert_eq!(run_result.iteration_errors.len(), 2);
        assert!(run_result.iteration_errors[0].1.contains("Iteration 3"));
        assert!(run_result.iteration_errors[1].1.contains("Iteration 5"));
    }

    #[test]
    fn test_measurement_run_result_all_failed() {
        // Test MeasurementRunResult when all iterations fail
        let run_result = MeasurementRunResult {
            latencies: vec![],
            failed_iterations: 3,
            iteration_errors: vec![
                (1, "Iteration 1 failed: Connection error".to_string()),
                (2, "Iteration 2 failed: Malformed response".to_string()),
                (3, "Iteration 3 failed: Timeout".to_string()),
            ],
        };

        assert!(run_result.latencies.is_empty());
        assert_eq!(run_result.failed_iterations, 3);
        assert_eq!(run_result.iteration_errors.len(), 3);
    }

    #[test]
    fn test_measurement_run_result_error_message_format() {
        // Test that error messages contain iteration number and error details
        let run_result = MeasurementRunResult {
            latencies: vec![100],
            failed_iterations: 1,
            iteration_errors: vec![
                (2, "Iteration 2 failed: Unexpected response type: expected Pong, got JsonResponse".to_string()),
            ],
        };

        let error_msg = &run_result.iteration_errors[0].1;
        assert!(error_msg.contains("Iteration 2"));
        assert!(error_msg.contains("Unexpected response"));
    }

    #[test]
    fn test_connection_error_message_clarity() {
        // Test that connection errors have clear messages
        // Requirement 8.3: Handle connection failures with clear error messages
        let io_error = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Failed to connect to enclave at CID 10 port 5000: Connection refused",
        );
        let pod_error = PodError::Connection(io_error);
        
        let error_msg = format!("{}", pod_error);
        assert!(error_msg.contains("Connection failed"));
        assert!(error_msg.contains("CID 10"));
        assert!(error_msg.contains("port 5000"));
    }

    #[test]
    fn test_malformed_response_error_handling() {
        // Test that malformed responses (wrong message type) are properly reported
        // Requirement 8.4: Report error for malformed responses
        let pod_error = PodError::UnexpectedResponse {
            expected: MessageType::Pong,
            actual: MessageType::SignResponse,
        };
        
        let error_msg = format!("{}", pod_error);
        assert!(error_msg.contains("Unexpected response"));
        assert!(error_msg.contains("expected"));
        assert!(error_msg.contains("Pong"));
        assert!(error_msg.contains("SignResponse"));
    }

    #[test]
    fn test_protocol_error_as_malformed_response() {
        // Test that protocol errors (invalid payload) are properly reported
        // Requirement 8.4: Report error for malformed responses
        let protocol_error = ProtocolError::InvalidMessageType(255);
        let pod_error = PodError::Protocol(protocol_error);
        
        let error_msg = format!("{}", pod_error);
        assert!(error_msg.contains("Protocol error"));
        assert!(error_msg.contains("Invalid message type"));
        assert!(error_msg.contains("255"));
    }

    // Property-based tests
    use proptest::prelude::*;

    // Feature: enclave-perf-cli, Property 6: CLI Argument Parsing
    // **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_cli_argument_parsing(
            cid in 3u32..=u32::MAX,  // Valid CIDs start from 3
            port in any::<u32>(),
            mode_idx in 0u8..3u8,    // 0=roundtrip, 1=json, 2=sign
            iterations in 1usize..=10000usize,  // Positive iterations
        ) {
            // Map mode index to mode string
            let mode_str = match mode_idx {
                0 => "roundtrip",
                1 => "json",
                _ => "sign",
            };

            // Expected mode enum value
            let expected_mode = match mode_idx {
                0 => MeasurementMode::Roundtrip,
                1 => MeasurementMode::Json,
                _ => MeasurementMode::Sign,
            };

            // Build command line arguments
            let args = PodArgs::try_parse_from([
                "enclave-perf",
                "--cid",
                &cid.to_string(),
                "--port",
                &port.to_string(),
                "--mode",
                mode_str,
                "--iterations",
                &iterations.to_string(),
            ]);

            // Verify parsing succeeds
            prop_assert!(args.is_ok(), "Failed to parse valid arguments");

            let parsed = args.unwrap();

            // Verify all parsed values match the generated values
            prop_assert_eq!(parsed.cid, cid, "CID mismatch");
            prop_assert_eq!(parsed.port, port, "Port mismatch");
            prop_assert_eq!(parsed.mode, expected_mode, "Mode mismatch");
            prop_assert_eq!(parsed.iterations, iterations, "Iterations mismatch");
        }
    }
}
