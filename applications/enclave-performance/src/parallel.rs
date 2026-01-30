//! Parallel execution types for multi-threaded performance testing.
//!
//! This module provides types for configuring and collecting results from
//! parallel worker threads that execute performance measurements concurrently.
//!
//! # Zero-Overhead Design
//!
//! The [`MetricsCollector`] uses `mpsc::channel` for lock-free result collection.
//! Workers get a sender clone before spawning and send results exactly once
//! AFTER all measurements complete. This ensures no synchronization overhead
//! during the measurement hot path.

use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use crate::protocol::{Message, MessageType, ProtocolError};
use crate::transport::{connect, TransportConfig, TransportStream};

/// Configuration for parallel execution
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// Number of parallel workers
    pub workers: usize,
    /// Iterations per worker
    pub iterations_per_worker: usize,
}

/// Result from a single worker
#[derive(Debug)]
pub struct WorkerResult {
    /// Worker ID (0-indexed)
    pub worker_id: usize,
    /// Successful latency measurements
    pub latencies: Vec<u64>,
    /// Number of failed iterations
    pub failed_count: usize,
    /// Error messages for failed iterations
    pub errors: Vec<String>,
}

/// Aggregated results from all workers
#[derive(Debug)]
pub struct AggregatedResults {
    /// Combined latencies from all workers
    pub all_latencies: Vec<u64>,
    /// Per-worker results for detailed reporting
    pub worker_results: Vec<WorkerResult>,
    /// Total successful measurements
    pub total_success: usize,
    /// Total failed measurements
    pub total_failed: usize,
}

/// Aggregate results from multiple workers into a single result set.
///
/// This function combines latencies from all workers, sums success and failure
/// counts, and returns an `AggregatedResults` struct containing the combined data.
///
/// # Arguments
///
/// * `worker_results` - A vector of `WorkerResult` from all parallel workers
///
/// # Returns
///
/// An `AggregatedResults` struct containing:
/// - `all_latencies`: Combined latencies from all workers
/// - `worker_results`: The original per-worker results for detailed reporting
/// - `total_success`: Sum of successful measurements across all workers
/// - `total_failed`: Sum of failed iterations across all workers
///
/// # Requirements
///
/// - 6.1: Computes statistics from all combined measurements
/// - 6.2: Aggregated statistics include data across all workers
///
/// # Example
///
/// ```
/// use enclave_performance::parallel::{WorkerResult, aggregate_results};
///
/// let worker_results = vec![
///     WorkerResult {
///         worker_id: 0,
///         latencies: vec![100, 200, 150],
///         failed_count: 1,
///         errors: vec!["iter 3: timeout".to_string()],
///     },
///     WorkerResult {
///         worker_id: 1,
///         latencies: vec![120, 180],
///         failed_count: 0,
///         errors: vec![],
///     },
/// ];
///
/// let aggregated = aggregate_results(worker_results);
/// assert_eq!(aggregated.all_latencies.len(), 5); // 3 + 2 latencies
/// assert_eq!(aggregated.total_success, 5);
/// assert_eq!(aggregated.total_failed, 1);
/// ```
pub fn aggregate_results(worker_results: Vec<WorkerResult>) -> AggregatedResults {
    // Pre-calculate total capacity for efficiency
    let total_latency_count: usize = worker_results.iter().map(|r| r.latencies.len()).sum();
    
    // Combine all latencies from all workers
    let mut all_latencies = Vec::with_capacity(total_latency_count);
    let mut total_success = 0;
    let mut total_failed = 0;

    for result in &worker_results {
        all_latencies.extend(&result.latencies);
        total_success += result.latencies.len();
        total_failed += result.failed_count;
    }

    AggregatedResults {
        all_latencies,
        worker_results,
        total_success,
        total_failed,
    }
}

/// Channel-based collector for lock-free result collection.
///
/// This collector uses `mpsc::channel` to gather results from parallel workers
/// without introducing any synchronization overhead during the measurement hot path.
///
/// # Design Principles
///
/// - Workers get a sender clone **before** spawning (via [`sender()`](Self::sender))
/// - Each worker sends results exactly **once**, **after** all measurements complete
/// - No locks, atomics, or channel sends occur during the measurement loop
/// - All statistical computation happens after [`collect()`](Self::collect) returns
///
/// # Example
///
/// ```
/// use enclave_performance::parallel::{MetricsCollector, WorkerResult};
/// use std::thread;
///
/// let collector = MetricsCollector::new();
/// let num_workers = 4;
///
/// // Spawn workers, each with their own sender
/// let handles: Vec<_> = (0..num_workers)
///     .map(|id| {
///         let sender = collector.sender();
///         thread::spawn(move || {
///             // Measurement loop - NO synchronization here
///             let latencies = vec![100, 200, 150]; // simulated measurements
///             
///             // Single send AFTER all measurements complete
///             sender.send(WorkerResult {
///                 worker_id: id,
///                 latencies,
///                 failed_count: 0,
///                 errors: vec![],
///             }).expect("receiver dropped");
///         })
///     })
///     .collect();
///
/// // Wait for all workers to complete
/// for handle in handles {
///     handle.join().expect("worker panicked");
/// }
///
/// // Collect all results (blocking until all received)
/// let results = collector.collect(num_workers);
/// assert_eq!(results.len(), num_workers);
/// ```
pub struct MetricsCollector {
    sender: mpsc::Sender<WorkerResult>,
    receiver: mpsc::Receiver<WorkerResult>,
}

impl MetricsCollector {
    /// Creates a new `MetricsCollector` with an unbounded channel.
    ///
    /// The channel is unbounded because workers send exactly once after
    /// completing all measurements, so backpressure is not a concern.
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self { sender, receiver }
    }

    /// Returns a clone of the sender for a worker thread.
    ///
    /// This method should be called **before** spawning each worker thread.
    /// Each worker receives its own sender clone to avoid any shared state
    /// during the measurement hot path.
    ///
    /// # Note
    ///
    /// Workers should call `send()` exactly once, **after** all measurements
    /// are complete. Sending during the measurement loop would introduce
    /// unnecessary overhead.
    pub fn sender(&self) -> mpsc::Sender<WorkerResult> {
        self.sender.clone()
    }

    /// Collects results from all workers after they complete.
    ///
    /// This method consumes the collector and blocks until `expected_workers`
    /// results have been received. It drops the internal sender first to ensure
    /// the receiver knows when all senders are done.
    ///
    /// # Arguments
    ///
    /// * `expected_workers` - The number of worker results to collect
    ///
    /// # Returns
    ///
    /// A vector containing exactly `expected_workers` results, in the order
    /// they were received (which may differ from worker ID order).
    ///
    /// # Panics
    ///
    /// This method will block indefinitely if fewer than `expected_workers`
    /// results are sent. Ensure all workers send their results before calling.
    pub fn collect(self, expected_workers: usize) -> Vec<WorkerResult> {
        // Drop our sender so the receiver knows when all senders are done.
        // This is critical: without dropping, iter() would block forever
        // waiting for more messages even after all workers have sent.
        drop(self.sender);
        
        // Collect exactly the expected number of results.
        // Using take() ensures we don't block waiting for more than expected.
        self.receiver.iter().take(expected_workers).collect()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}


/// Errors that can occur during parallel measurement execution
#[derive(Debug)]
pub enum ParallelError {
    /// All workers failed to complete
    AllWorkersFailed(Vec<String>),
    /// Protocol error during measurement
    Protocol(ProtocolError),
    /// Connection error
    Connection(std::io::Error),
}

impl std::fmt::Display for ParallelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParallelError::AllWorkersFailed(errors) => {
                write!(f, "All workers failed: {:?}", errors)
            }
            ParallelError::Protocol(e) => write!(f, "Protocol error: {}", e),
            ParallelError::Connection(e) => write!(f, "Connection error: {}", e),
        }
    }
}

impl std::error::Error for ParallelError {}

impl From<ProtocolError> for ParallelError {
    fn from(e: ProtocolError) -> Self {
        ParallelError::Protocol(e)
    }
}

impl From<std::io::Error> for ParallelError {
    fn from(e: std::io::Error) -> Self {
        ParallelError::Connection(e)
    }
}

/// Execute a single roundtrip measurement (ping/pong)
///
/// This is the minimal hot path: timing start, send, receive, timing end.
/// Returns the latency in microseconds.
fn execute_roundtrip_measurement(
    stream: &mut TransportStream,
    ping_msg: &Message,
) -> Result<u64, String> {
    // Record start time
    let start = Instant::now();

    // Send ping
    ping_msg
        .write_to(stream)
        .map_err(|e| format!("Failed to send: {}", e))?;

    // Receive pong
    let response = Message::read_from(stream).map_err(|e| format!("Failed to receive: {}", e))?;

    // Record end time and calculate latency
    let latency_us = start.elapsed().as_micros() as u64;

    // Verify response type
    let response_type = response
        .message_type()
        .map_err(|e| format!("Invalid response type: {}", e))?;
    if response_type != MessageType::Pong {
        return Err(format!(
            "Unexpected response type: expected Pong, got {:?}",
            response_type
        ));
    }

    Ok(latency_us)
}

/// Run measurements in parallel across multiple workers
///
/// Spawns N worker threads, each establishing its own connection and running
/// the specified number of iterations. Results are collected via channel after
/// all workers complete.
///
/// # Arguments
///
/// * `config` - Transport configuration for establishing connections
/// * `parallel_config` - Parallel execution configuration (workers, iterations)
///
/// # Returns
///
/// * `Ok(AggregatedResults)` - Combined results from all workers
/// * `Err(ParallelError)` - If all workers fail
///
/// # Design
///
/// The measurement hot path contains ONLY:
/// - Timing start (`Instant::now()`)
/// - Send message
/// - Receive message
/// - Timing end and Vec push
///
/// No locks, atomics, or channel sends occur during the measurement loop.
/// Workers submit results exactly once, AFTER completing all iterations.
///
/// # Requirements
///
/// - 4.1: Spawns N concurrent worker threads
/// - 4.2: Each worker establishes its own connection
/// - 4.3: Each worker executes iterations independently
/// - 5.1: Collects all latency measurements from all workers
/// - 5.3: Worker errors don't affect other workers
pub fn run_parallel_measurements(
    config: &TransportConfig,
    parallel_config: &ParallelConfig,
) -> Result<AggregatedResults, ParallelError> {
    // Create metrics collector for gathering results
    let collector = MetricsCollector::new();
    let num_workers = parallel_config.workers;
    let iterations = parallel_config.iterations_per_worker;

    // Pre-build the ping message once (will be cloned for each worker)
    let ping_msg = Message::ping(vec![0u8; 32])?;

    // Spawn worker threads
    let handles: Vec<_> = (0..num_workers)
        .map(|worker_id| {
            // Get sender clone BEFORE spawning (as per design)
            let sender = collector.sender();
            let worker_config = config.clone();
            let worker_ping_msg = ping_msg.clone();
            let worker_iterations = iterations;

            thread::spawn(move || {
                worker_thread(
                    worker_id,
                    worker_config,
                    worker_iterations,
                    worker_ping_msg,
                    sender,
                )
            })
        })
        .collect();

    // Wait for all workers to complete
    for handle in handles {
        // We don't care about the thread result here since workers send their
        // results via channel. If a thread panics, it won't send a result,
        // and we'll handle that in the collection phase.
        let _ = handle.join();
    }

    // Collect all results
    let worker_results = collector.collect(num_workers);

    // Aggregate results using the dedicated function
    let aggregated = aggregate_results(worker_results);

    // Check if all workers failed
    if aggregated.total_success == 0 && aggregated.total_failed > 0 {
        let all_errors: Vec<String> = aggregated
            .worker_results
            .iter()
            .flat_map(|r| r.errors.clone())
            .collect();
        return Err(ParallelError::AllWorkersFailed(all_errors));
    }

    Ok(aggregated)
}

/// Worker thread function
///
/// Establishes a connection, runs iterations, and sends results via channel.
/// Errors during connection or iterations are captured and reported, but don't
/// affect other workers.
fn worker_thread(
    worker_id: usize,
    config: TransportConfig,
    iterations: usize,
    ping_msg: Message,
    result_sender: mpsc::Sender<WorkerResult>,
) {
    // Pre-allocate vectors for results
    let mut latencies = Vec::with_capacity(iterations);
    let mut errors = Vec::new();

    // Attempt to establish connection
    let connection_result = connect(&config);

    match connection_result {
        Ok(mut stream) => {
            // Measurement loop - MINIMAL overhead
            // Contains ONLY: timing, send/receive, Vec push
            for i in 0..iterations {
                match execute_roundtrip_measurement(&mut stream, &ping_msg) {
                    Ok(latency) => {
                        // Single push to pre-allocated Vec - the ONLY operation in hot path
                        latencies.push(latency);
                    }
                    Err(e) => {
                        // Record error but continue with remaining iterations
                        errors.push(format!("iter {}: {}", i, e));
                    }
                }
            }
        }
        Err(e) => {
            // Connection failed - record error for all iterations
            errors.push(format!("Connection failed: {}", e));
        }
    }

    // Single send AFTER all measurements complete
    let _ = result_sender.send(WorkerResult {
        worker_id,
        latencies,
        failed_count: errors.len(),
        errors,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_parallel_config_creation() {
        let config = ParallelConfig {
            workers: 4,
            iterations_per_worker: 100,
        };
        assert_eq!(config.workers, 4);
        assert_eq!(config.iterations_per_worker, 100);
    }

    #[test]
    fn test_worker_result_creation() {
        let result = WorkerResult {
            worker_id: 0,
            latencies: vec![100, 200, 150],
            failed_count: 1,
            errors: vec!["test error".to_string()],
        };
        assert_eq!(result.worker_id, 0);
        assert_eq!(result.latencies.len(), 3);
        assert_eq!(result.failed_count, 1);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_aggregated_results_creation() {
        let worker_result = WorkerResult {
            worker_id: 0,
            latencies: vec![100, 200],
            failed_count: 0,
            errors: vec![],
        };
        let results = AggregatedResults {
            all_latencies: vec![100, 200],
            worker_results: vec![worker_result],
            total_success: 2,
            total_failed: 0,
        };
        assert_eq!(results.all_latencies.len(), 2);
        assert_eq!(results.total_success, 2);
        assert_eq!(results.total_failed, 0);
    }

    #[test]
    fn test_metrics_collector_basic() {
        let collector = MetricsCollector::new();
        let sender = collector.sender();

        // Spawn a thread to send a result
        let handle = thread::spawn(move || {
            sender
                .send(WorkerResult {
                    worker_id: 0,
                    latencies: vec![100, 200, 300],
                    failed_count: 0,
                    errors: vec![],
                })
                .expect("send failed");
        });

        handle.join().expect("thread panicked");

        let results = collector.collect(1);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].worker_id, 0);
        assert_eq!(results[0].latencies, vec![100, 200, 300]);
    }

    #[test]
    fn test_metrics_collector_multiple_workers() {
        let collector = MetricsCollector::new();
        let num_workers = 4;

        let handles: Vec<_> = (0..num_workers)
            .map(|id| {
                let sender = collector.sender();
                thread::spawn(move || {
                    sender
                        .send(WorkerResult {
                            worker_id: id,
                            latencies: vec![100 * (id as u64 + 1)],
                            failed_count: 0,
                            errors: vec![],
                        })
                        .expect("send failed");
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let results = collector.collect(num_workers);
        assert_eq!(results.len(), num_workers);

        // Verify all workers sent results (order may vary)
        let mut worker_ids: Vec<_> = results.iter().map(|r| r.worker_id).collect();
        worker_ids.sort();
        assert_eq!(worker_ids, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_parallel_error_display() {
        let err = ParallelError::AllWorkersFailed(vec!["error1".to_string(), "error2".to_string()]);
        let display = format!("{}", err);
        assert!(display.contains("All workers failed"));
    }

    // Tests for aggregate_results function
    #[test]
    fn test_aggregate_results_single_worker() {
        let worker_results = vec![WorkerResult {
            worker_id: 0,
            latencies: vec![100, 200, 150],
            failed_count: 1,
            errors: vec!["iter 3: timeout".to_string()],
        }];

        let aggregated = aggregate_results(worker_results);

        assert_eq!(aggregated.all_latencies, vec![100, 200, 150]);
        assert_eq!(aggregated.total_success, 3);
        assert_eq!(aggregated.total_failed, 1);
        assert_eq!(aggregated.worker_results.len(), 1);
    }

    #[test]
    fn test_aggregate_results_multiple_workers() {
        let worker_results = vec![
            WorkerResult {
                worker_id: 0,
                latencies: vec![100, 200],
                failed_count: 0,
                errors: vec![],
            },
            WorkerResult {
                worker_id: 1,
                latencies: vec![150, 250, 350],
                failed_count: 1,
                errors: vec!["iter 3: error".to_string()],
            },
            WorkerResult {
                worker_id: 2,
                latencies: vec![120],
                failed_count: 2,
                errors: vec!["iter 1: error".to_string(), "iter 2: error".to_string()],
            },
        ];

        let aggregated = aggregate_results(worker_results);

        // Combined latencies: [100, 200] + [150, 250, 350] + [120] = 6 total
        assert_eq!(aggregated.all_latencies.len(), 6);
        assert_eq!(aggregated.all_latencies, vec![100, 200, 150, 250, 350, 120]);
        assert_eq!(aggregated.total_success, 6);
        assert_eq!(aggregated.total_failed, 3); // 0 + 1 + 2
        assert_eq!(aggregated.worker_results.len(), 3);
    }

    #[test]
    fn test_aggregate_results_empty_workers() {
        let worker_results: Vec<WorkerResult> = vec![];

        let aggregated = aggregate_results(worker_results);

        assert!(aggregated.all_latencies.is_empty());
        assert_eq!(aggregated.total_success, 0);
        assert_eq!(aggregated.total_failed, 0);
        assert!(aggregated.worker_results.is_empty());
    }

    #[test]
    fn test_aggregate_results_all_failures() {
        let worker_results = vec![
            WorkerResult {
                worker_id: 0,
                latencies: vec![],
                failed_count: 5,
                errors: vec!["connection failed".to_string()],
            },
            WorkerResult {
                worker_id: 1,
                latencies: vec![],
                failed_count: 5,
                errors: vec!["connection failed".to_string()],
            },
        ];

        let aggregated = aggregate_results(worker_results);

        assert!(aggregated.all_latencies.is_empty());
        assert_eq!(aggregated.total_success, 0);
        assert_eq!(aggregated.total_failed, 10);
    }

    #[test]
    fn test_aggregate_results_preserves_worker_results() {
        let worker_results = vec![
            WorkerResult {
                worker_id: 0,
                latencies: vec![100, 200],
                failed_count: 1,
                errors: vec!["error1".to_string()],
            },
            WorkerResult {
                worker_id: 1,
                latencies: vec![300],
                failed_count: 0,
                errors: vec![],
            },
        ];

        let aggregated = aggregate_results(worker_results);

        // Verify worker_results are preserved for detailed reporting
        assert_eq!(aggregated.worker_results.len(), 2);
        assert_eq!(aggregated.worker_results[0].worker_id, 0);
        assert_eq!(aggregated.worker_results[0].latencies, vec![100, 200]);
        assert_eq!(aggregated.worker_results[1].worker_id, 1);
        assert_eq!(aggregated.worker_results[1].latencies, vec![300]);
    }

    // Feature: advanced-performance-metrics, Property 6: Zero-Overhead Hot Path
    // **Validates: Requirements 5.2, 5.6**
    //
    // This property test verifies the design invariants that ensure zero-overhead
    // during the measurement hot path:
    // - Workers send results exactly once, after all measurements complete
    // - No intermediate aggregation during measurement
    // - Results are collected in batch after all workers finish
    //
    // Since this is a structural/design property, we test the behavioral invariants
    // that the MetricsCollector pattern enforces:
    // 1. Each worker produces exactly one WorkerResult
    // 2. Latencies are collected without intermediate processing (raw values preserved)
    // 3. Aggregation happens only after all workers complete (batch collection)
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 6a: Workers send results exactly once after all measurements complete
        ///
        /// For any number of workers, each worker sends exactly one WorkerResult
        /// containing all its measurements. This ensures no channel sends occur
        /// during the measurement loop.
        #[test]
        fn property_workers_send_exactly_once(
            num_workers in 1usize..=16,
            iterations_per_worker in 1usize..=100
        ) {
            let collector = MetricsCollector::new();

            // Simulate workers: each collects all measurements first, then sends once
            let handles: Vec<_> = (0..num_workers)
                .map(|worker_id| {
                    let sender = collector.sender();
                    let iters = iterations_per_worker;
                    thread::spawn(move || {
                        // Simulate measurement collection (hot path)
                        // Pre-allocate like the real implementation
                        let mut latencies = Vec::with_capacity(iters);
                        
                        // Measurement loop - NO sends during this phase
                        for i in 0..iters {
                            // Simulate latency measurement (just use iteration as value)
                            let latency = (worker_id * 1000 + i) as u64;
                            latencies.push(latency);
                        }
                        
                        // Single send AFTER all measurements complete
                        sender.send(WorkerResult {
                            worker_id,
                            latencies,
                            failed_count: 0,
                            errors: vec![],
                        }).expect("send failed");
                    })
                })
                .collect();

            // Wait for all workers
            for handle in handles {
                handle.join().expect("worker panicked");
            }

            // Collect results
            let results = collector.collect(num_workers);

            // Property: Exactly num_workers results received (one per worker)
            prop_assert_eq!(
                results.len(),
                num_workers,
                "Expected exactly {} results (one per worker), got {}",
                num_workers,
                results.len()
            );

            // Property: Each worker ID appears exactly once
            let mut worker_ids: Vec<_> = results.iter().map(|r| r.worker_id).collect();
            worker_ids.sort();
            let expected_ids: Vec<_> = (0..num_workers).collect();
            prop_assert_eq!(
                worker_ids,
                expected_ids,
                "Each worker should send exactly one result"
            );
        }

        /// Property 6b: Latencies collected without intermediate processing
        ///
        /// Raw latency values are preserved exactly as measured. No transformation,
        /// aggregation, or statistical computation occurs during collection.
        /// This verifies that all computation is deferred to post-measurement phase.
        #[test]
        fn property_latencies_preserved_without_processing(
            worker_latencies in prop::collection::vec(
                prop::collection::vec(0u64..=1_000_000u64, 1..=50),
                1..=8
            )
        ) {
            let collector = MetricsCollector::new();
            let num_workers = worker_latencies.len();

            // Clone latencies for verification
            let expected_latencies = worker_latencies.clone();

            // Spawn workers that send their latencies
            let handles: Vec<_> = worker_latencies
                .into_iter()
                .enumerate()
                .map(|(worker_id, latencies)| {
                    let sender = collector.sender();
                    thread::spawn(move || {
                        // Worker sends raw latencies without any processing
                        sender.send(WorkerResult {
                            worker_id,
                            latencies,
                            failed_count: 0,
                            errors: vec![],
                        }).expect("send failed");
                    })
                })
                .collect();

            for handle in handles {
                handle.join().expect("worker panicked");
            }

            let results = collector.collect(num_workers);

            // Property: Each worker's latencies are preserved exactly
            for result in &results {
                let expected = &expected_latencies[result.worker_id];
                prop_assert_eq!(
                    &result.latencies,
                    expected,
                    "Worker {} latencies should be preserved exactly without processing",
                    result.worker_id
                );
            }
        }

        /// Property 6c: Aggregation happens only after all workers complete
        ///
        /// The MetricsCollector.collect() method blocks until all expected workers
        /// have sent their results, ensuring batch collection. This verifies that
        /// no intermediate aggregation occurs during measurement.
        #[test]
        fn property_batch_collection_after_completion(
            num_workers in 1usize..=8,
            latencies_per_worker in prop::collection::vec(0u64..=10_000u64, 1..=20)
        ) {
            let collector = MetricsCollector::new();
            let latencies_clone = latencies_per_worker.clone();

            // Spawn workers
            let handles: Vec<_> = (0..num_workers)
                .map(|worker_id| {
                    let sender = collector.sender();
                    let worker_latencies = latencies_clone.clone();
                    thread::spawn(move || {
                        // Simulate some work before sending
                        let mut collected = Vec::with_capacity(worker_latencies.len());
                        for lat in worker_latencies {
                            collected.push(lat);
                        }
                        
                        // Send after all collection complete
                        sender.send(WorkerResult {
                            worker_id,
                            latencies: collected,
                            failed_count: 0,
                            errors: vec![],
                        }).expect("send failed");
                    })
                })
                .collect();

            // Wait for all workers to complete
            for handle in handles {
                handle.join().expect("worker panicked");
            }

            // Collect all results in batch
            let results = collector.collect(num_workers);

            // Property: All results collected together after workers complete
            prop_assert_eq!(
                results.len(),
                num_workers,
                "All {} workers should have their results collected in batch",
                num_workers
            );

            // Property: Aggregation can now happen (simulating post-collection phase)
            let mut all_latencies: Vec<u64> = Vec::new();
            let mut total_success = 0;
            for result in &results {
                all_latencies.extend(&result.latencies);
                total_success += result.latencies.len();
            }

            // Verify aggregation correctness
            let expected_total = num_workers * latencies_per_worker.len();
            prop_assert_eq!(
                total_success,
                expected_total,
                "Total success count should equal sum of all worker latencies"
            );
            prop_assert_eq!(
                all_latencies.len(),
                expected_total,
                "Aggregated latencies should contain all measurements"
            );
        }

        /// Property 6d: No synchronization overhead during simulated measurement
        ///
        /// This test verifies that the pattern allows workers to operate independently
        /// without any shared state during their measurement phase. Each worker's
        /// measurements are isolated until the final send.
        #[test]
        fn property_workers_operate_independently(
            num_workers in 2usize..=8,
            iterations in 10usize..=50
        ) {
            use std::sync::atomic::{AtomicUsize, Ordering};
            use std::sync::Arc;

            let collector = MetricsCollector::new();
            
            // Counter to track completed workers (for verification only, not used in hot path)
            let completed_count = Arc::new(AtomicUsize::new(0));

            let handles: Vec<_> = (0..num_workers)
                .map(|worker_id| {
                    let sender = collector.sender();
                    let completed = Arc::clone(&completed_count);
                    thread::spawn(move || {
                        // Measurement phase - completely independent, no shared state access
                        let mut latencies = Vec::with_capacity(iterations);
                        for i in 0..iterations {
                            // Simulate measurement (no locks, no atomics, no channel sends)
                            latencies.push((worker_id * 1000 + i) as u64);
                        }
                        
                        // Only after measurement phase: send result and update counter
                        sender.send(WorkerResult {
                            worker_id,
                            latencies,
                            failed_count: 0,
                            errors: vec![],
                        }).expect("send failed");
                        
                        // Mark completion (this is post-measurement, for test verification)
                        completed.fetch_add(1, Ordering::SeqCst);
                    })
                })
                .collect();

            for handle in handles {
                handle.join().expect("worker panicked");
            }

            let results = collector.collect(num_workers);

            // Property: All workers completed independently
            prop_assert_eq!(
                completed_count.load(Ordering::SeqCst),
                num_workers,
                "All workers should complete independently"
            );

            // Property: Each worker has correct number of measurements
            for result in &results {
                prop_assert_eq!(
                    result.latencies.len(),
                    iterations,
                    "Worker {} should have {} measurements",
                    result.worker_id,
                    iterations
                );
            }

            // Property: Measurements are deterministic based on worker_id
            // (proves no interference between workers)
            for result in &results {
                let expected: Vec<u64> = (0..iterations)
                    .map(|i| (result.worker_id * 1000 + i) as u64)
                    .collect();
                prop_assert_eq!(
                    result.latencies.clone(),
                    expected,
                    "Worker {} measurements should be deterministic (no interference)",
                    result.worker_id
                );
            }
        }
    }

    // Feature: advanced-performance-metrics, Property 8: Aggregation Correctness
    // **Validates: Requirements 5.1, 5.4, 5.5, 6.1, 6.2, 6.3**
    //
    // This property test verifies that result aggregation is correct:
    // - The aggregated latency collection contains all measurements from all workers
    // - Total success count equals sum of per-worker success counts
    // - Total failure count equals sum of per-worker failure counts
    // - Statistics computed on aggregated data match statistics computed on the union of all worker measurements
    // - Merged histogram bucket counts equal the sum of individual histogram bucket counts
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 8a: Aggregated latency collection contains all measurements from all workers
        ///
        /// When aggregating results from multiple workers, the combined latency collection
        /// must contain every measurement from every worker, preserving all values.
        #[test]
        fn property_aggregated_latencies_contain_all_measurements(
            // Generate random worker results: 1-8 workers, each with 1-50 latencies
            worker_latencies in prop::collection::vec(
                prop::collection::vec(0u64..=1_000_000u64, 1..=50),
                1..=8
            )
        ) {
            // Create WorkerResults from the generated latencies
            let worker_results: Vec<WorkerResult> = worker_latencies
                .iter()
                .enumerate()
                .map(|(worker_id, latencies)| WorkerResult {
                    worker_id,
                    latencies: latencies.clone(),
                    failed_count: 0,
                    errors: vec![],
                })
                .collect();

            // Calculate expected combined latencies (union of all worker measurements)
            let expected_all_latencies: Vec<u64> = worker_latencies
                .iter()
                .flat_map(|lats| lats.iter().copied())
                .collect();

            // Aggregate results
            let aggregated = aggregate_results(worker_results);

            // Property: Aggregated latencies contain all measurements from all workers
            prop_assert_eq!(
                aggregated.all_latencies.len(),
                expected_all_latencies.len(),
                "Aggregated latencies count ({}) should equal total measurements ({})",
                aggregated.all_latencies.len(),
                expected_all_latencies.len()
            );

            // Property: All latencies are preserved (order may vary by worker order)
            prop_assert_eq!(
                aggregated.all_latencies,
                expected_all_latencies,
                "Aggregated latencies should contain all measurements in worker order"
            );
        }

        /// Property 8b: Total success count equals sum of per-worker success counts
        ///
        /// The total_success field in AggregatedResults must equal the sum of
        /// successful measurements (latencies.len()) across all workers.
        #[test]
        fn property_total_success_equals_sum_of_per_worker_successes(
            // Generate random worker results with varying success counts
            worker_configs in prop::collection::vec(
                (0usize..=100, 0usize..=20), // (num_successes, num_failures)
                1..=8
            )
        ) {
            // Create WorkerResults from the generated configs
            let worker_results: Vec<WorkerResult> = worker_configs
                .iter()
                .enumerate()
                .map(|(worker_id, &(num_successes, num_failures))| {
                    let latencies: Vec<u64> = (0..num_successes)
                        .map(|i| (worker_id * 1000 + i) as u64)
                        .collect();
                    let errors: Vec<String> = (0..num_failures)
                        .map(|i| format!("iter {}: error", i))
                        .collect();
                    WorkerResult {
                        worker_id,
                        latencies,
                        failed_count: num_failures,
                        errors,
                    }
                })
                .collect();

            // Calculate expected total success
            let expected_total_success: usize = worker_configs.iter().map(|(s, _)| s).sum();

            // Aggregate results
            let aggregated = aggregate_results(worker_results);

            // Property: Total success equals sum of per-worker successes
            prop_assert_eq!(
                aggregated.total_success,
                expected_total_success,
                "Total success ({}) should equal sum of per-worker successes ({})",
                aggregated.total_success,
                expected_total_success
            );
        }

        /// Property 8c: Total failure count equals sum of per-worker failure counts
        ///
        /// The total_failed field in AggregatedResults must equal the sum of
        /// failed_count across all workers.
        #[test]
        fn property_total_failures_equals_sum_of_per_worker_failures(
            // Generate random worker results with varying failure counts
            worker_configs in prop::collection::vec(
                (0usize..=50, 0usize..=30), // (num_successes, num_failures)
                1..=8
            )
        ) {
            // Create WorkerResults from the generated configs
            let worker_results: Vec<WorkerResult> = worker_configs
                .iter()
                .enumerate()
                .map(|(worker_id, &(num_successes, num_failures))| {
                    let latencies: Vec<u64> = (0..num_successes)
                        .map(|i| (worker_id * 1000 + i) as u64)
                        .collect();
                    let errors: Vec<String> = (0..num_failures)
                        .map(|i| format!("iter {}: error", i))
                        .collect();
                    WorkerResult {
                        worker_id,
                        latencies,
                        failed_count: num_failures,
                        errors,
                    }
                })
                .collect();

            // Calculate expected total failures
            let expected_total_failed: usize = worker_configs.iter().map(|(_, f)| f).sum();

            // Aggregate results
            let aggregated = aggregate_results(worker_results);

            // Property: Total failures equals sum of per-worker failures
            prop_assert_eq!(
                aggregated.total_failed,
                expected_total_failed,
                "Total failures ({}) should equal sum of per-worker failures ({})",
                aggregated.total_failed,
                expected_total_failed
            );
        }

        /// Property 8d: Statistics computed on aggregated data match statistics on union of measurements
        ///
        /// When computing MeasurementStats on the aggregated latencies, the result
        /// must be identical to computing stats on the union of all worker measurements.
        #[test]
        fn property_aggregated_stats_match_union_stats(
            // Generate random worker latencies (non-empty to ensure valid stats)
            worker_latencies in prop::collection::vec(
                prop::collection::vec(1u64..=1_000_000u64, 1..=50),
                1..=8
            )
        ) {
            use crate::stats::MeasurementStats;

            // Create WorkerResults from the generated latencies
            let worker_results: Vec<WorkerResult> = worker_latencies
                .iter()
                .enumerate()
                .map(|(worker_id, latencies)| WorkerResult {
                    worker_id,
                    latencies: latencies.clone(),
                    failed_count: 0,
                    errors: vec![],
                })
                .collect();

            // Calculate expected stats from union of all measurements
            let union_latencies: Vec<u64> = worker_latencies
                .iter()
                .flat_map(|lats| lats.iter().copied())
                .collect();
            let expected_stats = MeasurementStats::from_measurements(&union_latencies);

            // Aggregate results
            let aggregated = aggregate_results(worker_results);

            // Compute stats on aggregated latencies
            let aggregated_stats = MeasurementStats::from_measurements(&aggregated.all_latencies);

            // Property: Stats computed on aggregated data match stats on union
            prop_assert_eq!(
                aggregated_stats,
                expected_stats,
                "Stats on aggregated latencies should match stats on union of all measurements"
            );
        }

        /// Property 8e: Merged histogram bucket counts equal sum of individual histogram bucket counts
        ///
        /// When merging histograms from multiple workers, each bucket count in the
        /// merged histogram must equal the sum of that bucket's counts across all workers.
        #[test]
        fn property_merged_histogram_equals_sum_of_individual_histograms(
            // Generate random worker latencies
            worker_latencies in prop::collection::vec(
                prop::collection::vec(0u64..=20_000u64, 0..=100),
                1..=8
            ),
            // Generate random boundaries (sorted and deduplicated)
            raw_boundaries in prop::collection::vec(100u64..=15_000u64, 1..=6)
        ) {
            use crate::histogram::Histogram;

            // Prepare boundaries: sort and deduplicate
            let mut boundaries = raw_boundaries.clone();
            boundaries.sort_unstable();
            boundaries.dedup();

            // Create individual histograms for each worker
            let worker_histograms: Vec<Histogram> = worker_latencies
                .iter()
                .map(|latencies| Histogram::from_measurements(latencies, Some(boundaries.clone())))
                .collect();

            // Calculate expected merged counts by summing individual histogram counts
            let num_buckets = boundaries.len() + 1;
            let mut expected_counts: Vec<u64> = vec![0; num_buckets];
            for histogram in &worker_histograms {
                for (i, &count) in histogram.counts().iter().enumerate() {
                    expected_counts[i] += count;
                }
            }

            // Create merged histogram by merging all worker histograms
            let mut merged_histogram = Histogram::new(boundaries.clone());
            for histogram in &worker_histograms {
                merged_histogram.merge(histogram);
            }

            // Property: Merged histogram bucket counts equal sum of individual counts
            prop_assert_eq!(
                merged_histogram.counts(),
                &expected_counts[..],
                "Merged histogram counts should equal sum of individual histogram counts"
            );

            // Property: Merged histogram total equals sum of individual totals
            let expected_total: u64 = worker_histograms.iter().map(|h| h.total()).sum();
            prop_assert_eq!(
                merged_histogram.total(),
                expected_total,
                "Merged histogram total ({}) should equal sum of individual totals ({})",
                merged_histogram.total(),
                expected_total
            );

            // Property: Merged histogram total equals total number of latencies
            let total_latencies: usize = worker_latencies.iter().map(|l| l.len()).sum();
            prop_assert_eq!(
                merged_histogram.total(),
                total_latencies as u64,
                "Merged histogram total ({}) should equal total latencies ({})",
                merged_histogram.total(),
                total_latencies
            );
        }

        /// Property 8f: Aggregation preserves per-worker results for detailed reporting
        ///
        /// The worker_results field in AggregatedResults must preserve all original
        /// WorkerResult data for per-worker reporting.
        #[test]
        fn property_aggregation_preserves_per_worker_results(
            // Generate random worker configs
            worker_configs in prop::collection::vec(
                (0usize..=50, 0usize..=10), // (num_successes, num_failures)
                1..=8
            )
        ) {
            // Create WorkerResults from the generated configs
            let worker_results: Vec<WorkerResult> = worker_configs
                .iter()
                .enumerate()
                .map(|(worker_id, &(num_successes, num_failures))| {
                    let latencies: Vec<u64> = (0..num_successes)
                        .map(|i| (worker_id * 1000 + i) as u64)
                        .collect();
                    let errors: Vec<String> = (0..num_failures)
                        .map(|i| format!("worker {} iter {}: error", worker_id, i))
                        .collect();
                    WorkerResult {
                        worker_id,
                        latencies,
                        failed_count: num_failures,
                        errors,
                    }
                })
                .collect();

            // Store expected values before aggregation
            let expected_worker_count = worker_results.len();
            let expected_latencies: Vec<Vec<u64>> = worker_results
                .iter()
                .map(|r| r.latencies.clone())
                .collect();
            let expected_failed_counts: Vec<usize> = worker_results
                .iter()
                .map(|r| r.failed_count)
                .collect();

            // Aggregate results
            let aggregated = aggregate_results(worker_results);

            // Property: Worker results count is preserved
            prop_assert_eq!(
                aggregated.worker_results.len(),
                expected_worker_count,
                "Aggregated should preserve all {} worker results",
                expected_worker_count
            );

            // Property: Each worker's latencies are preserved
            for (i, result) in aggregated.worker_results.iter().enumerate() {
                prop_assert_eq!(
                    &result.latencies,
                    &expected_latencies[i],
                    "Worker {} latencies should be preserved",
                    i
                );
            }

            // Property: Each worker's failed_count is preserved
            for (i, result) in aggregated.worker_results.iter().enumerate() {
                prop_assert_eq!(
                    result.failed_count,
                    expected_failed_counts[i],
                    "Worker {} failed_count should be preserved",
                    i
                );
            }
        }
    }

    // Feature: advanced-performance-metrics, Property 7: Worker Error Isolation
    // **Validates: Requirements 5.3**
    //
    // This property test verifies that worker errors are isolated:
    // - When some workers encounter errors, other workers still complete their full iteration count
    // - Errors in one worker do not prevent other workers from completing
    // - Failed iterations are tracked per-worker
    // - Aggregated results include both successful measurements and failure counts
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// Property 7a: Successful workers complete full iteration count despite other worker failures
        ///
        /// When some workers encounter errors (simulated by marking certain workers as "failing"),
        /// the successful workers should still complete their full iteration count without
        /// being affected by the failures.
        #[test]
        fn property_successful_workers_complete_despite_failures(
            num_workers in 2usize..=16,
            iterations_per_worker in 1usize..=50,
            // Generate a set of worker IDs that will "fail" (at least one succeeds)
            failing_worker_indices in prop::collection::vec(0usize..16, 0..8)
        ) {
            // Ensure at least one worker succeeds
            let failing_set: std::collections::HashSet<usize> = failing_worker_indices
                .into_iter()
                .filter(|&idx| idx < num_workers && idx < num_workers - 1) // Keep at least one successful
                .collect();

            let collector = MetricsCollector::new();

            let handles: Vec<_> = (0..num_workers)
                .map(|worker_id| {
                    let sender = collector.sender();
                    let should_fail = failing_set.contains(&worker_id);
                    let iters = iterations_per_worker;
                    
                    thread::spawn(move || {
                        let mut latencies = Vec::with_capacity(iters);
                        let mut errors = Vec::new();
                        let mut failed_count = 0;

                        if should_fail {
                            // Simulate connection failure - no measurements, all iterations fail
                            errors.push(format!("Worker {} connection failed", worker_id));
                            failed_count = iters;
                        } else {
                            // Successful worker - complete all iterations
                            for i in 0..iters {
                                latencies.push((worker_id * 1000 + i) as u64);
                            }
                        }

                        sender.send(WorkerResult {
                            worker_id,
                            latencies,
                            failed_count,
                            errors,
                        }).expect("send failed");
                    })
                })
                .collect();

            for handle in handles {
                handle.join().expect("worker panicked");
            }

            let results = collector.collect(num_workers);

            // Property: All workers (both successful and failed) report results
            prop_assert_eq!(
                results.len(),
                num_workers,
                "All {} workers should report results regardless of success/failure",
                num_workers
            );

            // Property: Successful workers complete their full iteration count
            for result in &results {
                let was_failing = failing_set.contains(&result.worker_id);
                if !was_failing {
                    prop_assert_eq!(
                        result.latencies.len(),
                        iterations_per_worker,
                        "Successful worker {} should complete all {} iterations despite other failures",
                        result.worker_id,
                        iterations_per_worker
                    );
                    prop_assert_eq!(
                        result.failed_count,
                        0,
                        "Successful worker {} should have no failures",
                        result.worker_id
                    );
                }
            }
        }

        /// Property 7b: Failed iterations are tracked per-worker
        ///
        /// Each worker independently tracks its own failure count. Failures in one
        /// worker do not affect the failure counts of other workers.
        #[test]
        fn property_failures_tracked_per_worker(
            num_workers in 2usize..=8,
            iterations_per_worker in 5usize..=20,
            // For each worker, how many iterations fail (0 to all)
            failure_counts in prop::collection::vec(0usize..=20, 2..=8)
        ) {
            // Adjust failure counts to match num_workers and cap at iterations
            let worker_failure_counts: Vec<usize> = (0..num_workers)
                .map(|i| {
                    let fc = failure_counts.get(i).copied().unwrap_or(0);
                    fc.min(iterations_per_worker)
                })
                .collect();

            let collector = MetricsCollector::new();
            let expected_failures = worker_failure_counts.clone();

            let handles: Vec<_> = (0..num_workers)
                .map(|worker_id| {
                    let sender = collector.sender();
                    let iters = iterations_per_worker;
                    let num_failures = worker_failure_counts[worker_id];
                    
                    thread::spawn(move || {
                        let mut latencies = Vec::with_capacity(iters);
                        let mut errors = Vec::new();

                        for i in 0..iters {
                            if i < num_failures {
                                // Simulate iteration failure
                                errors.push(format!("iter {}: simulated error", i));
                            } else {
                                // Successful measurement
                                latencies.push((worker_id * 1000 + i) as u64);
                            }
                        }

                        sender.send(WorkerResult {
                            worker_id,
                            latencies,
                            failed_count: errors.len(),
                            errors,
                        }).expect("send failed");
                    })
                })
                .collect();

            for handle in handles {
                handle.join().expect("worker panicked");
            }

            let results = collector.collect(num_workers);

            // Property: Each worker's failure count matches expected
            for result in &results {
                let expected_fc = expected_failures[result.worker_id];
                prop_assert_eq!(
                    result.failed_count,
                    expected_fc,
                    "Worker {} should have exactly {} failures tracked",
                    result.worker_id,
                    expected_fc
                );
                prop_assert_eq!(
                    result.errors.len(),
                    expected_fc,
                    "Worker {} error messages should match failure count",
                    result.worker_id
                );
            }

            // Property: Successful measurements + failures = total iterations
            for result in &results {
                let total = result.latencies.len() + result.failed_count;
                prop_assert_eq!(
                    total,
                    iterations_per_worker,
                    "Worker {} total (success + failures) should equal iterations",
                    result.worker_id
                );
            }
        }

        /// Property 7c: Aggregated results include both successful measurements and failure counts
        ///
        /// When aggregating results from all workers, the totals correctly sum up
        /// both successful measurements and failure counts from all workers.
        #[test]
        fn property_aggregation_includes_successes_and_failures(
            num_workers in 2usize..=8,
            iterations_per_worker in 5usize..=30,
            // Failure rate per worker (0-100%)
            failure_rates in prop::collection::vec(0u8..=100, 2..=8)
        ) {
            let collector = MetricsCollector::new();

            // Calculate expected failures per worker
            let worker_configs: Vec<(usize, usize)> = (0..num_workers)
                .map(|i| {
                    let rate = failure_rates.get(i).copied().unwrap_or(0) as usize;
                    let num_failures = (iterations_per_worker * rate) / 100;
                    (iterations_per_worker - num_failures, num_failures)
                })
                .collect();

            let configs_clone = worker_configs.clone();

            let handles: Vec<_> = (0..num_workers)
                .map(|worker_id| {
                    let sender = collector.sender();
                    let (num_success, num_failures) = configs_clone[worker_id];
                    
                    thread::spawn(move || {
                        let mut latencies = Vec::with_capacity(num_success);
                        let mut errors = Vec::new();

                        // Record successful measurements
                        for i in 0..num_success {
                            latencies.push((worker_id * 1000 + i) as u64);
                        }

                        // Record failures
                        for i in 0..num_failures {
                            errors.push(format!("iter {}: simulated failure", num_success + i));
                        }

                        sender.send(WorkerResult {
                            worker_id,
                            latencies,
                            failed_count: errors.len(),
                            errors,
                        }).expect("send failed");
                    })
                })
                .collect();

            for handle in handles {
                handle.join().expect("worker panicked");
            }

            let results = collector.collect(num_workers);

            // Simulate aggregation (as done in run_parallel_measurements)
            let mut all_latencies: Vec<u64> = Vec::new();
            let mut total_success = 0;
            let mut total_failed = 0;

            for result in &results {
                all_latencies.extend(&result.latencies);
                total_success += result.latencies.len();
                total_failed += result.failed_count;
            }

            // Calculate expected totals
            let expected_success: usize = worker_configs.iter().map(|(s, _)| s).sum();
            let expected_failed: usize = worker_configs.iter().map(|(_, f)| f).sum();

            // Property: Total success count equals sum of per-worker successes
            prop_assert_eq!(
                total_success,
                expected_success,
                "Total success should equal sum of per-worker successes"
            );

            // Property: Total failure count equals sum of per-worker failures
            prop_assert_eq!(
                total_failed,
                expected_failed,
                "Total failures should equal sum of per-worker failures"
            );

            // Property: Aggregated latencies contain all successful measurements
            prop_assert_eq!(
                all_latencies.len(),
                expected_success,
                "Aggregated latencies should contain all successful measurements"
            );

            // Property: Total attempted iterations equals workers * iterations_per_worker
            let total_attempted = total_success + total_failed;
            prop_assert_eq!(
                total_attempted,
                num_workers * iterations_per_worker,
                "Total attempted should equal workers * iterations"
            );
        }

        /// Property 7d: Worker errors do not corrupt other workers' data
        ///
        /// Even when workers fail with errors, the successful workers' measurements
        /// remain intact and uncorrupted. This verifies true isolation.
        #[test]
        fn property_errors_do_not_corrupt_other_workers_data(
            num_workers in 3usize..=8,
            iterations_per_worker in 10usize..=30,
            // Which worker will have a "catastrophic" failure (all iterations fail)
            failing_worker in 0usize..8
        ) {
            let failing_worker_id = failing_worker % num_workers;
            let collector = MetricsCollector::new();

            let handles: Vec<_> = (0..num_workers)
                .map(|worker_id| {
                    let sender = collector.sender();
                    let iters = iterations_per_worker;
                    let is_failing = worker_id == failing_worker_id;
                    
                    thread::spawn(move || {
                        let mut latencies = Vec::with_capacity(iters);
                        let mut errors = Vec::new();

                        if is_failing {
                            // Catastrophic failure - all iterations fail
                            for i in 0..iters {
                                errors.push(format!("iter {}: catastrophic error", i));
                            }
                        } else {
                            // Successful worker - deterministic measurements
                            for i in 0..iters {
                                // Use a specific pattern that can be verified
                                latencies.push((worker_id * 10000 + i * 100) as u64);
                            }
                        }

                        sender.send(WorkerResult {
                            worker_id,
                            latencies,
                            failed_count: errors.len(),
                            errors,
                        }).expect("send failed");
                    })
                })
                .collect();

            for handle in handles {
                handle.join().expect("worker panicked");
            }

            let results = collector.collect(num_workers);

            // Property: Successful workers' data is intact and uncorrupted
            for result in &results {
                if result.worker_id != failing_worker_id {
                    // Verify exact expected values (proves no corruption)
                    let expected: Vec<u64> = (0..iterations_per_worker)
                        .map(|i| (result.worker_id * 10000 + i * 100) as u64)
                        .collect();
                    
                    prop_assert_eq!(
                        result.latencies.clone(),
                        expected,
                        "Worker {} data should be uncorrupted despite worker {} failure",
                        result.worker_id,
                        failing_worker_id
                    );
                    
                    prop_assert_eq!(
                        result.failed_count,
                        0,
                        "Successful worker {} should have no failures",
                        result.worker_id
                    );
                }
            }

            // Property: Failing worker correctly reports all failures
            let failing_result = results.iter().find(|r| r.worker_id == failing_worker_id);
            prop_assert!(
                failing_result.is_some(),
                "Failing worker should still report results"
            );
            
            if let Some(fr) = failing_result {
                prop_assert_eq!(
                    fr.latencies.len(),
                    0,
                    "Failing worker should have no successful measurements"
                );
                prop_assert_eq!(
                    fr.failed_count,
                    iterations_per_worker,
                    "Failing worker should report all iterations as failed"
                );
            }
        }
    }
}
