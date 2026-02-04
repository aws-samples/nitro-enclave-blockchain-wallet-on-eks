//! Pod Binary
//!
//! Runs from the Kubernetes pod, executes performance tests against
//! the enclave, and reports statistics.

use clap::{Parser, ValueEnum};
use enclave_performance::histogram::Histogram;
use enclave_performance::json::JsonTestPayload;
use enclave_performance::parallel::{ParallelConfig, run_parallel_measurements};
use enclave_performance::protocol::{Message, MessageType, ProtocolError};
use enclave_performance::stats::MeasurementStats;
use enclave_performance::transport::{connect, TransportConfig, TransportStream};
use std::time::Instant;
use thiserror::Error;

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

/// Transport mode selection for CLI
///
/// Determines which underlying transport mechanism to use for communication.
/// Defaults to `Vsock` for backward compatibility with existing deployments.
///
/// # Requirements
/// - 1.4: WHEN the Pod_Binary is started with `--transport vsock`, THE Pod_Binary SHALL use vsock for connecting
/// - 1.5: WHEN the Pod_Binary is started with `--transport tcp`, THE Pod_Binary SHALL use TCP socket for connecting
/// - 1.6: WHEN the Pod_Binary is started without `--transport` flag, THE Pod_Binary SHALL default to vsock transport
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum TransportMode {
    /// Virtual Socket transport for Nitro Enclave communication (default)
    #[default]
    Vsock,
    /// Standard TCP socket transport for local development and testing
    Tcp,
}

/// CLI arguments for the enclave performance measurement tool
///
/// # Requirements
/// - 1.4, 1.5, 1.6: Transport mode selection with vsock default
/// - 2.4, 2.5: TCP address configuration
/// - 3.1, 3.2, 3.3, 3.4: Vsock CID parameter validation
#[derive(Parser, Debug)]
#[command(name = "enclave-perf")]
#[command(about = "Measure communication performance with enclave")]
pub struct PodArgs {
    /// Transport mode (vsock or tcp)
    ///
    /// Use 'vsock' for Nitro Enclave deployments (default).
    /// Use 'tcp' for local development and testing.
    #[arg(long, value_enum, default_value = "vsock")]
    pub transport: TransportMode,

    /// Target enclave CID (required for vsock mode)
    ///
    /// The Context Identifier of the target enclave.
    /// Valid CIDs start from 3 (0-2 are reserved).
    #[arg(short, long, required_if_eq("transport", "vsock"))]
    pub cid: Option<u32>,

    /// Target address for TCP mode (e.g., 127.0.0.1)
    ///
    /// Required when using TCP transport mode.
    /// Use 127.0.0.1 for loopback connections.
    #[arg(long, required_if_eq("transport", "tcp"))]
    pub address: Option<String>,

    /// Port number (used for both vsock and TCP)
    #[arg(short, long, default_value = "5000")]
    pub port: u32,

    /// Measurement mode
    #[arg(short, long, value_enum)]
    pub mode: MeasurementMode,

    /// Number of iterations
    #[arg(short = 'n', long, default_value = "100")]
    pub iterations: usize,

    /// Number of parallel connections (1-256)
    ///
    /// Specifies the number of concurrent worker threads to spawn.
    /// Each worker establishes its own connection and runs iterations independently.
    /// Default is 1 (single-threaded execution).
    ///
    /// Requirements: 4.5, 7.1
    #[arg(long, default_value = "1", value_parser = clap::value_parser!(u16).range(1..=256))]
    pub parallel: u16,

    /// Enable histogram output
    ///
    /// When enabled, displays an ASCII histogram visualization of the latency
    /// distribution alongside the standard statistics output.
    ///
    /// Requirements: 7.2, 7.4
    #[arg(long, default_value = "false")]
    pub histogram: bool,

    /// Custom histogram bucket boundaries (comma-separated, in microseconds)
    ///
    /// Specifies custom bucket boundaries for the histogram visualization.
    /// Values should be positive integers representing microseconds.
    /// Example: --buckets 50,100,250,500,1000
    ///
    /// Requirements: 7.3
    #[arg(long, value_delimiter = ',')]
    pub buckets: Option<Vec<u64>>,
}

impl PodArgs {
    /// Validate the arguments and return an error message if invalid
    ///
    /// # Requirements
    /// - 3.1: WHEN the Pod_Binary is started with `--transport vsock`, THE Pod_Binary SHALL require the `--cid` parameter
    /// - 3.2: WHEN the Pod_Binary is started with `--transport tcp`, THE Pod_Binary SHALL NOT require the `--cid` parameter
    /// - 3.3: IF the Pod_Binary is started with `--transport tcp` and `--cid` is provided, THEN THE Pod_Binary SHALL ignore the `--cid` parameter
    /// - 3.4: IF the Pod_Binary is started with `--transport vsock` without `--cid`, THEN THE Pod_Binary SHALL exit with an error message
    pub fn validate(&self) -> Result<(), String> {
        // Transport-specific validation
        match self.transport {
            TransportMode::Vsock => {
                // CID is required for vsock mode (Requirement 3.1, 3.4)
                let cid = self.cid.ok_or_else(|| {
                    "CID is required for vsock transport mode. Use --cid <value>".to_string()
                })?;

                // CID 0 is reserved (VMADDR_CID_HYPERVISOR)
                // CID 1 is reserved (VMADDR_CID_LOCAL)
                // CID 2 is the host (VMADDR_CID_HOST)
                // Valid enclave CIDs start from 3
                if cid < 3 {
                    return Err(format!(
                        "Invalid CID: {}. CID must be 3 or greater (0-2 are reserved)",
                        cid
                    ));
                }
            }
            TransportMode::Tcp => {
                // Address is required for TCP mode (Requirement 2.4)
                if self.address.is_none() {
                    return Err(
                        "Address is required for TCP transport mode. Use --address <value>"
                            .to_string(),
                    );
                }
                // CID is ignored for TCP mode (Requirement 3.2, 3.3)
            }
        }

        // Iterations must be at least 1
        if self.iterations == 0 {
            return Err("Iterations must be at least 1".to_string());
        }

        // Validate bucket values if provided (Requirement 4.5)
        if let Some(ref buckets) = self.buckets {
            // Check that all bucket values are positive (> 0)
            for (i, &value) in buckets.iter().enumerate() {
                if value == 0 {
                    return Err(format!(
                        "Invalid bucket value at position {}: bucket values must be positive (> 0)",
                        i
                    ));
                }
            }

            // Check that bucket values are sorted in ascending order
            for i in 1..buckets.len() {
                if buckets[i] <= buckets[i - 1] {
                    return Err(format!(
                        "Bucket values must be sorted in ascending order: {} is not greater than {}",
                        buckets[i], buckets[i - 1]
                    ));
                }
            }
        }

        Ok(())
    }

    /// Convert CLI arguments to a TransportConfig
    ///
    /// Creates the appropriate transport configuration based on the
    /// selected transport mode and provided parameters.
    ///
    /// # Requirements
    /// - 2.4: WHEN the Pod_Binary is started with `--transport tcp`, THE Pod_Binary SHALL require an `--address` parameter
    /// - 2.5: WHEN the Pod_Binary is started with `--transport tcp` and `--address 127.0.0.1`, THE Pod_Binary SHALL connect to loopback
    /// - 2.6: THE existing `--port` parameter SHALL be used for both vsock and TCP transport modes
    pub fn to_transport_config(&self) -> TransportConfig {
        match self.transport {
            TransportMode::Vsock => TransportConfig::Vsock {
                cid: self.cid,
                port: self.port,
            },
            TransportMode::Tcp => TransportConfig::Tcp {
                address: self.address.clone().unwrap_or_default(),
                port: self.port,
            },
        }
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
    /// in microseconds, followed by percentile values (p50, p90, p95, p99, p99.9).
    ///
    /// Requirements: 1.5, 3.4, 4.4, 5.5
    pub fn print_report(&self) {
        println!("Mode: {:?}", self.mode);
        println!("Iterations: {}", self.iterations);
        println!("Min: {} µs", self.stats.min_us);
        println!("Max: {} µs", self.stats.max_us);
        println!("Mean: {:.2} µs", self.stats.mean_us);
        println!("Median: {} µs", self.stats.median_us);
        // Percentile output (Requirement 1.5)
        println!("p50: {:.2} µs", self.stats.p50_us);
        println!("p90: {:.2} µs", self.stats.p90_us);
        println!("p95: {:.2} µs", self.stats.p95_us);
        println!("p99: {:.2} µs", self.stats.p99_us);
        println!("p99.9: {:.2} µs", self.stats.p99_9_us);
    }
}

/// Execute a single roundtrip measurement
///
/// Sends a ping message and waits for a pong response.
/// Returns the roundtrip time in microseconds.
///
/// Requirements: 3.1, 3.3
fn execute_roundtrip(stream: &mut TransportStream, ping_msg: &Message) -> Result<u64, PodError> {
    // Record start time
    let start = Instant::now();

    // Send ping (reuse pre-built message)
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
fn execute_json(stream: &mut TransportStream, sequence: u32) -> Result<u64, PodError> {
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
fn execute_sign(stream: &mut TransportStream, sign_msg: &Message) -> Result<u64, PodError> {
    // Record start time
    let start = Instant::now();

    // Send request (reuse pre-built message)
    sign_msg.write_to(stream)?;

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
    // Build transport configuration from CLI args
    let config = args.to_transport_config();

    // Connect to enclave using the transport abstraction
    // Connection failures are fatal and return an error with clear message
    let mut stream = connect(&config).map_err(|e| {
        // Provide clear error message for connection failures
        let target_desc = match &config {
            TransportConfig::Vsock { cid, port } => {
                format!("CID {} port {}", cid.unwrap_or(0), port)
            }
            TransportConfig::Tcp { address, port } => {
                format!("{}:{}", address, port)
            }
        };
        PodError::Connection(std::io::Error::new(
            e.kind(),
            format!("Failed to connect to enclave at {}: {}", target_desc, e),
        ))
    })?;

    // Pre-build messages once to avoid allocations in hot path (low-latency optimization)
    let ping_msg = Message::ping(vec![0u8; 32])?;
    let sign_msg = Message::new(MessageType::SignRequest, vec![0xABu8; 32])?;

    // Perform warmup iteration (Requirement 6.4)
    println!("Performing warmup iteration...");
    match args.mode {
        MeasurementMode::Roundtrip => {
            execute_roundtrip(&mut stream, &ping_msg)?;
        }
        MeasurementMode::Json => {
            execute_json(&mut stream, 0)?;
        }
        MeasurementMode::Sign => {
            execute_sign(&mut stream, &sign_msg)?;
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
            MeasurementMode::Roundtrip => execute_roundtrip(&mut stream, &ping_msg),
            MeasurementMode::Json => execute_json(&mut stream, (i + 1) as u32),
            MeasurementMode::Sign => execute_sign(&mut stream, &sign_msg),
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
    match args.transport {
        TransportMode::Vsock => {
            println!("Transport: vsock");
            println!("Target CID: {}", args.cid.unwrap_or(0));
        }
        TransportMode::Tcp => {
            println!("Transport: TCP");
            println!("Target Address: {}", args.address.as_deref().unwrap_or(""));
        }
    }
    println!("Port: {}", args.port);
    println!("Mode: {:?}", args.mode);
    println!("Iterations: {}", args.iterations);
    if args.parallel > 1 {
        println!("Parallel workers: {}", args.parallel);
    }
    println!();

    // Check if parallel mode is enabled (Requirements 4.4, 8.1)
    // If parallel > 1, use run_parallel_measurements
    // Otherwise, use existing run_measurements for backward compatibility
    if args.parallel > 1 {
        // Parallel execution mode
        let config = args.to_transport_config();
        let parallel_config = ParallelConfig {
            workers: args.parallel as usize,
            iterations_per_worker: args.iterations,
        };

        println!(
            "Running {} iterations across {} parallel workers...",
            args.iterations * args.parallel as usize,
            args.parallel
        );

        match run_parallel_measurements(&config, &parallel_config) {
            Ok(aggregated) => {
                // Report any failures
                if aggregated.total_failed > 0 {
                    println!();
                    println!(
                        "Warning: {} of {} total iterations failed",
                        aggregated.total_failed,
                        aggregated.total_success + aggregated.total_failed
                    );
                }

                // Check if we have any successful measurements
                if aggregated.all_latencies.is_empty() {
                    eprintln!("Error: All iterations failed. No measurements collected.");
                    for result in &aggregated.worker_results {
                        for error in &result.errors {
                            eprintln!("  Worker {}: {}", result.worker_id, error);
                        }
                    }
                    std::process::exit(1);
                }

                // Create MeasurementResult and print report
                match MeasurementResult::from_latencies(args.mode, &aggregated.all_latencies) {
                    Some(result) => {
                        println!();
                        println!("Results:");
                        println!("--------");
                        result.print_report();
                        
                        // Display worker count and total iterations (Requirement 6.4)
                        println!();
                        println!("Parallel execution summary:");
                        println!(
                            "  Workers: {}, Total iterations: {}",
                            args.parallel,
                            aggregated.total_success + aggregated.total_failed
                        );
                        println!(
                            "  Successful iterations: {}/{}",
                            aggregated.total_success,
                            aggregated.total_success + aggregated.total_failed
                        );
                        
                        // Display per-worker success/failure counts (Requirement 6.5)
                        println!();
                        println!("Per-worker results:");
                        // Sort worker results by worker_id for consistent display
                        let mut sorted_results: Vec<_> = aggregated.worker_results.iter().collect();
                        sorted_results.sort_by_key(|r| r.worker_id);
                        for worker_result in sorted_results {
                            println!(
                                "  Worker {}: {} successful, {} failed",
                                worker_result.worker_id,
                                worker_result.latencies.len(),
                                worker_result.failed_count
                            );
                        }

                        // Display histogram if --histogram flag is set (Requirements 7.2, 7.4, 7.5)
                        if args.histogram {
                            let histogram = Histogram::from_measurements(
                                &aggregated.all_latencies,
                                args.buckets.clone(),
                            );
                            println!();
                            print!("{}", histogram.render_ascii(20));
                        }
                    }
                    None => {
                        eprintln!("Error: No measurements collected");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Single-threaded execution (backward compatible mode)
        // Run measurements using existing function
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

                        // Display histogram if --histogram flag is set (Requirements 7.2, 7.4, 7.5)
                        if args.histogram {
                            let histogram = Histogram::from_measurements(
                                &run_result.latencies,
                                args.buckets.clone(),
                            );
                            println!();
                            print!("{}", histogram.render_ascii(20));
                        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests for CLI argument parsing

    #[test]
    fn test_parse_valid_args_vsock() {
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

        assert_eq!(args.transport, TransportMode::Vsock);
        assert_eq!(args.cid, Some(10));
        assert_eq!(args.port, 5000);
        assert_eq!(args.mode, MeasurementMode::Roundtrip);
        assert_eq!(args.iterations, 50);
    }

    #[test]
    fn test_parse_valid_args_tcp() {
        let args = PodArgs::try_parse_from([
            "enclave-perf",
            "--transport",
            "tcp",
            "--address",
            "127.0.0.1",
            "--port",
            "5000",
            "--mode",
            "roundtrip",
            "--iterations",
            "50",
        ])
        .unwrap();

        assert_eq!(args.transport, TransportMode::Tcp);
        assert_eq!(args.address, Some("127.0.0.1".to_string()));
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

        assert_eq!(args.transport, TransportMode::Vsock); // default
        assert_eq!(args.cid, Some(10));
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
    fn test_parse_buckets_flag() {
        // Test parsing --buckets flag with comma-separated values
        // Requirements: 7.3
        let args = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "roundtrip",
            "--buckets",
            "50,100,250,500,1000",
        ])
        .unwrap();

        assert_eq!(args.buckets, Some(vec![50, 100, 250, 500, 1000]));
    }

    #[test]
    fn test_parse_buckets_flag_single_value() {
        // Test parsing --buckets flag with a single value
        let args = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "roundtrip",
            "--buckets",
            "100",
        ])
        .unwrap();

        assert_eq!(args.buckets, Some(vec![100]));
    }

    #[test]
    fn test_parse_buckets_flag_not_provided() {
        // Test that buckets is None when not provided
        let args = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "roundtrip",
        ])
        .unwrap();

        assert_eq!(args.buckets, None);
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

        assert_eq!(args.cid, Some(10));
        assert_eq!(args.port, 6000);
        assert_eq!(args.mode, MeasurementMode::Roundtrip);
        assert_eq!(args.iterations, 200);
    }

    #[test]
    fn test_missing_required_cid_for_vsock_explicit() {
        // CID is required for vsock mode when explicitly specified
        let result = PodArgs::try_parse_from([
            "enclave-perf",
            "--transport",
            "vsock",
            "--mode",
            "roundtrip",
        ]);

        // Clap enforces required_if_eq when transport is explicitly set to vsock
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_cid_for_default_vsock_validated() {
        // When transport defaults to vsock and CID is missing,
        // parsing succeeds but validation fails
        let result = PodArgs::try_parse_from([
            "enclave-perf",
            "--mode",
            "roundtrip",
        ]);

        // Parsing succeeds (clap doesn't enforce required_if_eq for default values)
        assert!(result.is_ok());
        
        // But validation should fail
        let args = result.unwrap();
        let validation = args.validate();
        assert!(validation.is_err());
        assert!(validation.unwrap_err().contains("CID is required"));
    }

    #[test]
    fn test_missing_required_address_for_tcp() {
        // Address is required for TCP mode
        let result = PodArgs::try_parse_from([
            "enclave-perf",
            "--transport",
            "tcp",
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
    fn test_invalid_transport() {
        let result = PodArgs::try_parse_from([
            "enclave-perf",
            "--transport",
            "invalid",
            "--mode",
            "roundtrip",
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_cid_zero() {
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(0),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid CID"));
    }

    #[test]
    fn test_validate_invalid_cid_one() {
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(1),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_invalid_cid_two() {
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(2),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_valid_cid_three() {
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(3),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_vsock_missing_cid() {
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: None,
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("CID is required"));
    }

    #[test]
    fn test_validate_tcp_missing_address() {
        let args = PodArgs {
            transport: TransportMode::Tcp,
            cid: None,
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Address is required"));
    }

    #[test]
    fn test_validate_tcp_valid() {
        let args = PodArgs {
            transport: TransportMode::Tcp,
            cid: None,
            address: Some("127.0.0.1".to_string()),
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_tcp_ignores_cid() {
        // CID should be ignored for TCP mode (Requirement 3.3)
        let args = PodArgs {
            transport: TransportMode::Tcp,
            cid: Some(10), // This should be ignored
            address: Some("127.0.0.1".to_string()),
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_zero_iterations() {
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 0,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Iterations"));
    }

    #[test]
    fn test_validate_valid_args() {
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Json,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_ok());
    }

    // Unit tests for bucket validation (Task 9.4)
    // Requirements: 4.5

    #[test]
    fn test_validate_buckets_valid() {
        // Valid bucket values: positive and sorted in ascending order
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: true,
            buckets: Some(vec![50, 100, 250, 500, 1000]),
        };

        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_buckets_single_value() {
        // Single bucket value is valid
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: true,
            buckets: Some(vec![100]),
        };

        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_buckets_none() {
        // No buckets provided is valid (will use defaults)
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: true,
            buckets: None,
        };

        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_buckets_zero_value() {
        // Zero bucket value is invalid (must be positive)
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: true,
            buckets: Some(vec![0, 100, 200]),
        };

        let result = args.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("bucket values must be positive"));
        assert!(err.contains("position 0"));
    }

    #[test]
    fn test_validate_buckets_zero_in_middle() {
        // Zero bucket value in the middle is invalid
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: true,
            buckets: Some(vec![50, 0, 200]),
        };

        let result = args.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("bucket values must be positive"));
        assert!(err.contains("position 1"));
    }

    #[test]
    fn test_validate_buckets_not_sorted() {
        // Bucket values not in ascending order is invalid
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: true,
            buckets: Some(vec![100, 50, 200]),
        };

        let result = args.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("sorted in ascending order"));
        assert!(err.contains("50"));
        assert!(err.contains("100"));
    }

    #[test]
    fn test_validate_buckets_duplicate_values() {
        // Duplicate bucket values are invalid (not strictly ascending)
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: true,
            buckets: Some(vec![100, 100, 200]),
        };

        let result = args.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("sorted in ascending order"));
    }

    #[test]
    fn test_validate_buckets_descending_at_end() {
        // Descending values at the end is invalid
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(10),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: true,
            buckets: Some(vec![50, 100, 200, 150]),
        };

        let result = args.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("sorted in ascending order"));
        assert!(err.contains("150"));
        assert!(err.contains("200"));
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

    // Feature: socket-transport-abstraction, Property 1: Transport Mode CLI Parsing
    // **Validates: Requirements 1.1, 1.2, 1.4, 1.5**
    //
    // *For any* valid transport mode string ("vsock" or "tcp"), parsing the CLI arguments
    // with that transport mode SHALL produce the corresponding `TransportMode` enum value
    // (`TransportMode::Vsock` or `TransportMode::Tcp`).
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        fn prop_transport_mode_cli_parsing(
            transport_mode_str in "(vsock|tcp)",
        ) {
            // Determine expected TransportMode based on the generated string
            let expected_mode = match transport_mode_str.as_str() {
                "vsock" => TransportMode::Vsock,
                "tcp" => TransportMode::Tcp,
                _ => unreachable!("Generator only produces 'vsock' or 'tcp'"),
            };

            // Build CLI arguments based on transport mode
            // For vsock: requires --cid
            // For tcp: requires --address
            let args_result = match transport_mode_str.as_str() {
                "vsock" => PodArgs::try_parse_from([
                    "enclave-perf",
                    "--transport",
                    &transport_mode_str,
                    "--cid",
                    "10",
                    "--mode",
                    "roundtrip",
                ]),
                "tcp" => PodArgs::try_parse_from([
                    "enclave-perf",
                    "--transport",
                    &transport_mode_str,
                    "--address",
                    "127.0.0.1",
                    "--mode",
                    "roundtrip",
                ]),
                _ => unreachable!("Generator only produces 'vsock' or 'tcp'"),
            };

            // Verify parsing succeeds
            prop_assert!(
                args_result.is_ok(),
                "Failed to parse valid transport mode '{}': {:?}",
                transport_mode_str,
                args_result.err()
            );

            let parsed_args = args_result.unwrap();

            // Verify the parsed TransportMode matches the expected value
            // This validates Requirements 1.1, 1.2, 1.4, 1.5
            prop_assert_eq!(
                parsed_args.transport,
                expected_mode,
                "Transport mode mismatch: parsed '{}' but got {:?}, expected {:?}",
                transport_mode_str,
                parsed_args.transport,
                expected_mode
            );
        }
    }

    // Feature: enclave-perf-cli, Property 6: CLI Argument Parsing
    // **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        fn prop_cli_argument_parsing_vsock(
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

            // Build command line arguments for vsock mode
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
            prop_assert_eq!(parsed.transport, TransportMode::Vsock, "Transport should default to Vsock");
            prop_assert_eq!(parsed.cid, Some(cid), "CID mismatch");
            prop_assert_eq!(parsed.port, port, "Port mismatch");
            prop_assert_eq!(parsed.mode, expected_mode, "Mode mismatch");
            prop_assert_eq!(parsed.iterations, iterations, "Iterations mismatch");
        }

        #[test]
        fn prop_cli_argument_parsing_tcp(
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

            // Build command line arguments for TCP mode
            let args = PodArgs::try_parse_from([
                "enclave-perf",
                "--transport",
                "tcp",
                "--address",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--mode",
                mode_str,
                "--iterations",
                &iterations.to_string(),
            ]);

            // Verify parsing succeeds
            prop_assert!(args.is_ok(), "Failed to parse valid TCP arguments");

            let parsed = args.unwrap();

            // Verify all parsed values match the generated values
            prop_assert_eq!(parsed.transport, TransportMode::Tcp, "Transport should be Tcp");
            prop_assert_eq!(parsed.address, Some("127.0.0.1".to_string()), "Address mismatch");
            prop_assert_eq!(parsed.port, port, "Port mismatch");
            prop_assert_eq!(parsed.mode, expected_mode, "Mode mismatch");
            prop_assert_eq!(parsed.iterations, iterations, "Iterations mismatch");
        }
    }

    // Feature: socket-transport-abstraction, Property 4: Port Parameter Consistency
    // **Validates: Requirements 2.6**
    //
    // *For any* valid port number and any transport mode, the port parameter SHALL be
    // correctly included in the resulting `TransportConfig` and used for binding (server)
    // or connecting (client).
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        fn prop_port_parameter_consistency(
            port in any::<u32>(),
            transport_mode_idx in 0u8..2u8,  // 0=vsock, 1=tcp
        ) {
            // Determine transport mode based on index
            let (transport_mode, transport_str) = match transport_mode_idx {
                0 => (TransportMode::Vsock, "vsock"),
                _ => (TransportMode::Tcp, "tcp"),
            };

            // Build CLI arguments based on transport mode
            // For vsock: requires --cid
            // For tcp: requires --address
            let args_result = match transport_mode {
                TransportMode::Vsock => PodArgs::try_parse_from([
                    "enclave-perf",
                    "--transport",
                    transport_str,
                    "--cid",
                    "10",
                    "--port",
                    &port.to_string(),
                    "--mode",
                    "roundtrip",
                ]),
                TransportMode::Tcp => PodArgs::try_parse_from([
                    "enclave-perf",
                    "--transport",
                    transport_str,
                    "--address",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                    "--mode",
                    "roundtrip",
                ]),
            };

            // Verify parsing succeeds
            prop_assert!(
                args_result.is_ok(),
                "Failed to parse valid arguments with port {}: {:?}",
                port,
                args_result.err()
            );

            let parsed_args = args_result.unwrap();

            // Verify the parsed port matches the generated port
            prop_assert_eq!(
                parsed_args.port,
                port,
                "Parsed port {} does not match generated port {}",
                parsed_args.port,
                port
            );

            // Convert to TransportConfig and verify port is correctly included
            let config = parsed_args.to_transport_config();

            // Verify the port in TransportConfig matches the generated port
            // This validates Requirement 2.6: THE existing `--port` parameter SHALL be
            // used for both vsock and TCP transport modes
            match config {
                TransportConfig::Vsock { port: config_port, .. } => {
                    prop_assert_eq!(
                        config_port,
                        port,
                        "Vsock TransportConfig port {} does not match generated port {}",
                        config_port,
                        port
                    );
                }
                TransportConfig::Tcp { port: config_port, .. } => {
                    prop_assert_eq!(
                        config_port,
                        port,
                        "Tcp TransportConfig port {} does not match generated port {}",
                        config_port,
                        port
                    );
                }
            }

            // Also verify the transport mode is correct
            prop_assert_eq!(
                parsed_args.transport,
                transport_mode,
                "Transport mode mismatch"
            );
        }
    }

    // Unit tests for to_transport_config method

    #[test]
    fn test_to_transport_config_vsock() {
        let args = PodArgs {
            transport: TransportMode::Vsock,
            cid: Some(16),
            address: None,
            port: 5000,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let config = args.to_transport_config();
        match config {
            TransportConfig::Vsock { cid, port } => {
                assert_eq!(cid, Some(16));
                assert_eq!(port, 5000);
            }
            _ => panic!("Expected Vsock config"),
        }
    }

    #[test]
    fn test_to_transport_config_tcp() {
        let args = PodArgs {
            transport: TransportMode::Tcp,
            cid: None,
            address: Some("127.0.0.1".to_string()),
            port: 8080,
            mode: MeasurementMode::Roundtrip,
            iterations: 100,
            parallel: 1,
            histogram: false,
            buckets: None,
        };

        let config = args.to_transport_config();
        match config {
            TransportConfig::Tcp { address, port } => {
                assert_eq!(address, "127.0.0.1");
                assert_eq!(port, 8080);
            }
            _ => panic!("Expected Tcp config"),
        }
    }

    // Unit tests for TransportMode

    // Feature: advanced-performance-metrics, Property 5: Parallel Connection Validation
    // **Validates: Requirements 4.5**
    //
    // *For any* parallel connection count value:
    // - Values in range [1, 256] are accepted
    // - Values < 1 or > 256 are rejected with an error
    // - Default value when unspecified is 1
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_parallel_connection_validation_valid_range(
            parallel_value in 1u16..=256u16,
        ) {
            // Test that values in the valid range [1, 256] are accepted by clap's value_parser
            let args_result = PodArgs::try_parse_from([
                "enclave-perf",
                "--cid",
                "10",
                "--mode",
                "roundtrip",
                "--parallel",
                &parallel_value.to_string(),
            ]);

            // Verify parsing succeeds for valid parallel values
            prop_assert!(
                args_result.is_ok(),
                "Failed to parse valid parallel value {}: {:?}",
                parallel_value,
                args_result.err()
            );

            let parsed_args = args_result.unwrap();

            // Verify the parsed parallel value matches the generated value
            prop_assert_eq!(
                parsed_args.parallel,
                parallel_value,
                "Parsed parallel value {} does not match generated value {}",
                parsed_args.parallel,
                parallel_value
            );
        }

        #[test]
        fn prop_parallel_connection_validation_invalid_zero(
            // Test that value 0 (below minimum) is rejected
            _dummy in Just(()),
        ) {
            // Test that parallel value of 0 is rejected by clap's value_parser
            let args_result = PodArgs::try_parse_from([
                "enclave-perf",
                "--cid",
                "10",
                "--mode",
                "roundtrip",
                "--parallel",
                "0",
            ]);

            // Verify parsing fails for parallel value 0 (below minimum of 1)
            prop_assert!(
                args_result.is_err(),
                "Parallel value 0 should be rejected but was accepted"
            );
        }

        #[test]
        fn prop_parallel_connection_validation_invalid_above_max(
            // Test values above 256 (the maximum allowed)
            parallel_value in 257u32..=65535u32,
        ) {
            // Test that values above 256 are rejected by clap's value_parser
            let args_result = PodArgs::try_parse_from([
                "enclave-perf",
                "--cid",
                "10",
                "--mode",
                "roundtrip",
                "--parallel",
                &parallel_value.to_string(),
            ]);

            // Verify parsing fails for parallel values above 256
            prop_assert!(
                args_result.is_err(),
                "Parallel value {} (above 256) should be rejected but was accepted",
                parallel_value
            );
        }
    }

    #[test]
    fn test_parallel_default_value() {
        // Test that the default value for --parallel is 1 when not specified
        // Validates: Requirements 4.5
        let args_result = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "roundtrip",
        ]);

        assert!(args_result.is_ok(), "Failed to parse args without --parallel flag");
        let parsed_args = args_result.unwrap();

        // Verify default parallel value is 1
        assert_eq!(
            parsed_args.parallel, 1,
            "Default parallel value should be 1, got {}",
            parsed_args.parallel
        );
    }

    #[test]
    fn test_parallel_boundary_values() {
        // Test boundary values: 1 (minimum) and 256 (maximum)
        // Validates: Requirements 4.5

        // Test minimum value (1)
        let args_min = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "roundtrip",
            "--parallel",
            "1",
        ]);
        assert!(args_min.is_ok(), "Parallel value 1 should be accepted");
        assert_eq!(args_min.unwrap().parallel, 1);

        // Test maximum value (256)
        let args_max = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "roundtrip",
            "--parallel",
            "256",
        ]);
        assert!(args_max.is_ok(), "Parallel value 256 should be accepted");
        assert_eq!(args_max.unwrap().parallel, 256);

        // Test just below minimum (0) - should fail
        let args_below_min = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "roundtrip",
            "--parallel",
            "0",
        ]);
        assert!(args_below_min.is_err(), "Parallel value 0 should be rejected");

        // Test just above maximum (257) - should fail
        let args_above_max = PodArgs::try_parse_from([
            "enclave-perf",
            "--cid",
            "10",
            "--mode",
            "roundtrip",
            "--parallel",
            "257",
        ]);
        assert!(args_above_max.is_err(), "Parallel value 257 should be rejected");
    }

    #[test]
    fn test_transport_mode_default() {
        let mode = TransportMode::default();
        assert_eq!(mode, TransportMode::Vsock);
    }

    #[test]
    fn test_transport_mode_clone() {
        let mode = TransportMode::Tcp;
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_transport_mode_debug() {
        assert_eq!(format!("{:?}", TransportMode::Vsock), "Vsock");
        assert_eq!(format!("{:?}", TransportMode::Tcp), "Tcp");
    }
}
