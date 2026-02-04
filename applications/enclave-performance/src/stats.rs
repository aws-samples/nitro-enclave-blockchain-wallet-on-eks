//! Statistics module for performance measurements
//!
//! Provides calculation of min, max, mean, and median latency statistics
//! from measurement data.

/// Statistics result for a measurement run
#[derive(Debug, Clone, PartialEq)]
pub struct MeasurementStats {
    /// Minimum latency in microseconds
    pub min_us: u64,
    /// Maximum latency in microseconds
    pub max_us: u64,
    /// Mean (average) latency in microseconds
    pub mean_us: f64,
    /// Median latency in microseconds
    pub median_us: u64,
    /// Number of measurements
    pub count: usize,

    // Percentile fields (new)
    /// 50th percentile (median) latency in microseconds
    pub p50_us: f64,
    /// 90th percentile latency in microseconds
    pub p90_us: f64,
    /// 95th percentile latency in microseconds
    pub p95_us: f64,
    /// 99th percentile latency in microseconds
    pub p99_us: f64,
    /// 99.9th percentile latency in microseconds
    pub p99_9_us: f64,
}

impl MeasurementStats {
    /// Calculate a specific percentile using linear interpolation.
    ///
    /// # Arguments
    /// * `sorted` - A sorted slice of latency measurements (must be non-empty)
    /// * `percentile` - The percentile to calculate (0.0 to 100.0)
    ///
    /// # Algorithm
    /// - Calculate the rank: `rank = (percentile / 100.0) * (n - 1)`
    /// - If rank is an integer, return that element
    /// - Otherwise, linearly interpolate between floor(rank) and ceil(rank)
    ///
    /// # Edge Cases
    /// - Single element: returns that element for any percentile
    /// - Small arrays: interpolation works correctly for any size >= 1
    fn calculate_percentile(sorted: &[u64], percentile: f64) -> f64 {
        let n = sorted.len();
        
        // Handle single element case
        if n == 1 {
            return sorted[0] as f64;
        }
        
        // Clamp percentile to valid range [0, 100]
        let p = percentile.clamp(0.0, 100.0);
        
        // Calculate the rank using the formula: rank = (p/100) * (n-1)
        let rank = (p / 100.0) * (n - 1) as f64;
        
        // Get floor and ceil indices
        let lower_idx = rank.floor() as usize;
        let upper_idx = rank.ceil() as usize;
        
        // If rank is exactly an integer (or indices are the same), return that element
        if lower_idx == upper_idx {
            return sorted[lower_idx] as f64;
        }
        
        // Linear interpolation between floor and ceil values
        let lower_value = sorted[lower_idx] as f64;
        let upper_value = sorted[upper_idx] as f64;
        let fraction = rank - lower_idx as f64;
        
        lower_value + fraction * (upper_value - lower_value)
    }

    /// Calculate statistics from a slice of latency measurements (in microseconds)
    ///
    /// Returns `None` if the slice is empty.
    ///
    /// For median calculation with even-length slices, uses the lower of the two
    /// middle values (simpler than averaging).
    ///
    /// # Examples
    ///
    /// ```
    /// use enclave_performance::stats::MeasurementStats;
    ///
    /// let latencies = vec![100, 200, 150, 300, 250];
    /// let stats = MeasurementStats::from_measurements(&latencies).unwrap();
    /// assert_eq!(stats.min_us, 100);
    /// assert_eq!(stats.max_us, 300);
    /// assert_eq!(stats.count, 5);
    /// ```
    pub fn from_measurements(latencies: &[u64]) -> Option<Self> {
        // Handle empty slice
        if latencies.is_empty() {
            return None;
        }

        // Calculate min and max
        let min_us = *latencies.iter().min().unwrap();
        let max_us = *latencies.iter().max().unwrap();

        // Calculate mean using f64 to avoid overflow with large values
        let mean_us = latencies.iter().map(|&x| x as f64).sum::<f64>() / latencies.len() as f64;

        // Calculate median (requires sorting a copy)
        let mut sorted = latencies.to_vec();
        sorted.sort_unstable();
        
        let median_us = if sorted.len() % 2 == 1 {
            // Odd length: take the middle element
            sorted[sorted.len() / 2]
        } else {
            // Even length: take the lower of the two middle values
            sorted[sorted.len() / 2 - 1]
        };

        // Compute all percentiles using linear interpolation on the sorted array
        let p50_us = Self::calculate_percentile(&sorted, 50.0);
        let p90_us = Self::calculate_percentile(&sorted, 90.0);
        let p95_us = Self::calculate_percentile(&sorted, 95.0);
        let p99_us = Self::calculate_percentile(&sorted, 99.0);
        let p99_9_us = Self::calculate_percentile(&sorted, 99.9);

        Some(MeasurementStats {
            min_us,
            max_us,
            mean_us,
            median_us,
            count: latencies.len(),
            p50_us,
            p90_us,
            p95_us,
            p99_us,
            p99_9_us,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Feature: advanced-performance-metrics, Property 1: Percentile Calculation Correctness
    // **Validates: Requirements 1.2, 1.4**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_percentile_calculation_correctness(
            latencies in prop::collection::vec(0u64..=1_000_000u64, 1..=1000)
        ) {
            let stats = MeasurementStats::from_measurements(&latencies).unwrap();

            // Property 1a: Monotonic ordering - p50 ≤ p90 ≤ p95 ≤ p99 ≤ p99.9
            prop_assert!(
                stats.p50_us <= stats.p90_us,
                "p50 ({}) should be <= p90 ({})",
                stats.p50_us, stats.p90_us
            );
            prop_assert!(
                stats.p90_us <= stats.p95_us,
                "p90 ({}) should be <= p95 ({})",
                stats.p90_us, stats.p95_us
            );
            prop_assert!(
                stats.p95_us <= stats.p99_us,
                "p95 ({}) should be <= p99 ({})",
                stats.p95_us, stats.p99_us
            );
            prop_assert!(
                stats.p99_us <= stats.p99_9_us,
                "p99 ({}) should be <= p99.9 ({})",
                stats.p99_us, stats.p99_9_us
            );

            // Property 1b: All percentiles are within [min_us, max_us] bounds
            let min_f64 = stats.min_us as f64;
            let max_f64 = stats.max_us as f64;

            prop_assert!(
                stats.p50_us >= min_f64 && stats.p50_us <= max_f64,
                "p50 ({}) should be within [{}, {}]",
                stats.p50_us, min_f64, max_f64
            );
            prop_assert!(
                stats.p90_us >= min_f64 && stats.p90_us <= max_f64,
                "p90 ({}) should be within [{}, {}]",
                stats.p90_us, min_f64, max_f64
            );
            prop_assert!(
                stats.p95_us >= min_f64 && stats.p95_us <= max_f64,
                "p95 ({}) should be within [{}, {}]",
                stats.p95_us, min_f64, max_f64
            );
            prop_assert!(
                stats.p99_us >= min_f64 && stats.p99_us <= max_f64,
                "p99 ({}) should be within [{}, {}]",
                stats.p99_us, min_f64, max_f64
            );
            prop_assert!(
                stats.p99_9_us >= min_f64 && stats.p99_9_us <= max_f64,
                "p99.9 ({}) should be within [{}, {}]",
                stats.p99_9_us, min_f64, max_f64
            );

            // Property 1c: Linear interpolation correctness verification
            // For each percentile p, verify: rank = (p/100) * (n-1)
            // and result interpolates between sorted[floor(rank)] and sorted[ceil(rank)]
            let mut sorted = latencies.clone();
            sorted.sort_unstable();
            let n = sorted.len();

            // Helper to verify linear interpolation for a given percentile
            let verify_interpolation = |percentile: f64, actual: f64| -> Result<(), TestCaseError> {
                let rank = (percentile / 100.0) * (n - 1) as f64;
                let lower_idx = rank.floor() as usize;
                let upper_idx = rank.ceil() as usize;
                
                let lower_value = sorted[lower_idx] as f64;
                let upper_value = sorted[upper_idx] as f64;
                
                // The actual value should be between lower and upper (inclusive)
                prop_assert!(
                    actual >= lower_value && actual <= upper_value,
                    "Percentile {} value {} should be between {} and {}",
                    percentile, actual, lower_value, upper_value
                );
                
                // If lower != upper, verify exact interpolation
                if lower_idx != upper_idx {
                    let fraction = rank - lower_idx as f64;
                    let expected = lower_value + fraction * (upper_value - lower_value);
                    let epsilon = 1e-10;
                    prop_assert!(
                        (actual - expected).abs() < epsilon,
                        "Percentile {} interpolation: actual {} != expected {} (diff: {})",
                        percentile, actual, expected, (actual - expected).abs()
                    );
                }
                
                Ok(())
            };

            verify_interpolation(50.0, stats.p50_us)?;
            verify_interpolation(90.0, stats.p90_us)?;
            verify_interpolation(95.0, stats.p95_us)?;
            verify_interpolation(99.0, stats.p99_us)?;
            verify_interpolation(99.9, stats.p99_9_us)?;
        }
    }

    // Feature: enclave-perf-cli, Property 2: Statistics Calculation Correctness
    // **Validates: Requirements 3.4, 4.4, 5.5**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        #[test]
        fn property_statistics_calculation_correctness(
            latencies in prop::collection::vec(0u64..=1_000_000u64, 1..=100)
        ) {
            let stats = MeasurementStats::from_measurements(&latencies).unwrap();

            // Verify count equals the slice length
            prop_assert_eq!(stats.count, latencies.len());

            // Verify min_us equals the smallest value in the slice
            let expected_min = *latencies.iter().min().unwrap();
            prop_assert_eq!(stats.min_us, expected_min);

            // Verify max_us equals the largest value in the slice
            let expected_max = *latencies.iter().max().unwrap();
            prop_assert_eq!(stats.max_us, expected_max);

            // Verify mean_us equals the arithmetic mean of all values
            let expected_mean = latencies.iter().map(|&x| x as f64).sum::<f64>() / latencies.len() as f64;
            // Use epsilon for f64 comparison due to floating point precision
            let epsilon = 1e-10;
            prop_assert!(
                (stats.mean_us - expected_mean).abs() < epsilon,
                "mean_us {} != expected_mean {} (diff: {})",
                stats.mean_us,
                expected_mean,
                (stats.mean_us - expected_mean).abs()
            );

            // Verify median_us equals the correct middle value
            let mut sorted = latencies.clone();
            sorted.sort_unstable();
            let expected_median = if sorted.len() % 2 == 1 {
                // Odd length: take the middle element
                sorted[sorted.len() / 2]
            } else {
                // Even length: take the lower of the two middle values
                sorted[sorted.len() / 2 - 1]
            };
            prop_assert_eq!(stats.median_us, expected_median);
        }
    }

    #[test]
    fn test_empty_slice_returns_none() {
        let latencies: Vec<u64> = vec![];
        assert!(MeasurementStats::from_measurements(&latencies).is_none());
    }

    #[test]
    fn test_single_element() {
        let latencies = vec![42];
        let stats = MeasurementStats::from_measurements(&latencies).unwrap();
        
        assert_eq!(stats.min_us, 42);
        assert_eq!(stats.max_us, 42);
        assert_eq!(stats.mean_us, 42.0);
        assert_eq!(stats.median_us, 42);
        assert_eq!(stats.count, 1);
    }

    #[test]
    fn test_two_elements() {
        let latencies = vec![10, 20];
        let stats = MeasurementStats::from_measurements(&latencies).unwrap();
        
        assert_eq!(stats.min_us, 10);
        assert_eq!(stats.max_us, 20);
        assert_eq!(stats.mean_us, 15.0);
        // Even length: lower of two middle values
        assert_eq!(stats.median_us, 10);
        assert_eq!(stats.count, 2);
    }

    #[test]
    fn test_odd_length_median() {
        // Sorted: [100, 150, 200, 250, 300]
        // Median is the middle element (index 2): 200
        let latencies = vec![100, 200, 150, 300, 250];
        let stats = MeasurementStats::from_measurements(&latencies).unwrap();
        
        assert_eq!(stats.min_us, 100);
        assert_eq!(stats.max_us, 300);
        assert_eq!(stats.mean_us, 200.0);
        assert_eq!(stats.median_us, 200);
        assert_eq!(stats.count, 5);
    }

    #[test]
    fn test_even_length_median() {
        // Sorted: [100, 150, 200, 250]
        // Even length: lower of two middle values (index 1): 150
        let latencies = vec![100, 200, 150, 250];
        let stats = MeasurementStats::from_measurements(&latencies).unwrap();
        
        assert_eq!(stats.min_us, 100);
        assert_eq!(stats.max_us, 250);
        assert_eq!(stats.mean_us, 175.0);
        assert_eq!(stats.median_us, 150);
        assert_eq!(stats.count, 4);
    }

    #[test]
    fn test_duplicate_values() {
        let latencies = vec![100, 100, 100, 100];
        let stats = MeasurementStats::from_measurements(&latencies).unwrap();
        
        assert_eq!(stats.min_us, 100);
        assert_eq!(stats.max_us, 100);
        assert_eq!(stats.mean_us, 100.0);
        assert_eq!(stats.median_us, 100);
        assert_eq!(stats.count, 4);
    }

    #[test]
    fn test_large_values() {
        let latencies = vec![u64::MAX - 1, u64::MAX];
        let stats = MeasurementStats::from_measurements(&latencies).unwrap();
        
        assert_eq!(stats.min_us, u64::MAX - 1);
        assert_eq!(stats.max_us, u64::MAX);
        assert_eq!(stats.count, 2);
    }

    #[test]
    fn test_unsorted_input() {
        // Verify that unsorted input is handled correctly
        let latencies = vec![500, 100, 300, 200, 400];
        let stats = MeasurementStats::from_measurements(&latencies).unwrap();
        
        assert_eq!(stats.min_us, 100);
        assert_eq!(stats.max_us, 500);
        assert_eq!(stats.mean_us, 300.0);
        // Sorted: [100, 200, 300, 400, 500], median is 300
        assert_eq!(stats.median_us, 300);
        assert_eq!(stats.count, 5);
    }

    // Tests for calculate_percentile method
    mod percentile_tests {
        use super::*;

        #[test]
        fn test_percentile_single_element() {
            // Single element: all percentiles should return that element
            let sorted = vec![100];
            
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 0.0), 100.0);
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 50.0), 100.0);
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 99.9), 100.0);
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 100.0), 100.0);
        }

        #[test]
        fn test_percentile_two_elements() {
            // Two elements: [10, 20]
            // p0 = 10, p50 = 15 (interpolated), p100 = 20
            let sorted = vec![10, 20];
            
            // p0: rank = 0 * 1 = 0, returns sorted[0] = 10
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 0.0), 10.0);
            
            // p50: rank = 0.5 * 1 = 0.5, interpolate between 10 and 20
            // result = 10 + 0.5 * (20 - 10) = 15
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 50.0), 15.0);
            
            // p100: rank = 1.0 * 1 = 1, returns sorted[1] = 20
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 100.0), 20.0);
        }

        #[test]
        fn test_percentile_exact_boundaries() {
            // 5 elements: [100, 200, 300, 400, 500]
            // n = 5, so n-1 = 4
            let sorted = vec![100, 200, 300, 400, 500];
            
            // p0: rank = 0 * 4 = 0, returns sorted[0] = 100
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 0.0), 100.0);
            
            // p25: rank = 0.25 * 4 = 1, returns sorted[1] = 200
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 25.0), 200.0);
            
            // p50: rank = 0.5 * 4 = 2, returns sorted[2] = 300
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 50.0), 300.0);
            
            // p75: rank = 0.75 * 4 = 3, returns sorted[3] = 400
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 75.0), 400.0);
            
            // p100: rank = 1.0 * 4 = 4, returns sorted[4] = 500
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 100.0), 500.0);
        }

        #[test]
        fn test_percentile_linear_interpolation() {
            // 5 elements: [100, 200, 300, 400, 500]
            // n = 5, so n-1 = 4
            let sorted = vec![100, 200, 300, 400, 500];
            
            // p10: rank = 0.1 * 4 = 0.4
            // interpolate between sorted[0]=100 and sorted[1]=200
            // result = 100 + 0.4 * (200 - 100) = 140
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 10.0), 140.0);
            
            // p90: rank = 0.9 * 4 = 3.6
            // interpolate between sorted[3]=400 and sorted[4]=500
            // result = 400 + 0.6 * (500 - 400) = 460
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 90.0), 460.0);
        }

        #[test]
        fn test_percentile_small_array_three_elements() {
            // 3 elements: [10, 20, 30]
            // n = 3, so n-1 = 2
            let sorted = vec![10, 20, 30];
            
            // p50: rank = 0.5 * 2 = 1, returns sorted[1] = 20
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 50.0), 20.0);
            
            // p99: rank = 0.99 * 2 = 1.98
            // interpolate between sorted[1]=20 and sorted[2]=30
            // result = 20 + 0.98 * (30 - 20) = 29.8
            let p99 = MeasurementStats::calculate_percentile(&sorted, 99.0);
            assert!((p99 - 29.8).abs() < 0.001);
        }

        #[test]
        fn test_percentile_clamps_out_of_range() {
            let sorted = vec![100, 200, 300];
            
            // Negative percentile should be clamped to 0
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, -10.0), 100.0);
            
            // Percentile > 100 should be clamped to 100
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 150.0), 300.0);
        }

        #[test]
        fn test_percentile_duplicate_values() {
            // All same values: any percentile should return that value
            let sorted = vec![50, 50, 50, 50, 50];
            
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 0.0), 50.0);
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 50.0), 50.0);
            assert_eq!(MeasurementStats::calculate_percentile(&sorted, 99.9), 50.0);
        }

        #[test]
        fn test_percentile_p99_9() {
            // 10 elements: [0, 100, 200, 300, 400, 500, 600, 700, 800, 900]
            // n = 10, so n-1 = 9
            let sorted: Vec<u64> = (0..10).map(|i| i * 100).collect();
            
            // p99.9: rank = 0.999 * 9 = 8.991
            // interpolate between sorted[8]=800 and sorted[9]=900
            // result = 800 + 0.991 * (900 - 800) = 899.1
            let p99_9 = MeasurementStats::calculate_percentile(&sorted, 99.9);
            assert!((p99_9 - 899.1).abs() < 0.001);
        }
    }
}
