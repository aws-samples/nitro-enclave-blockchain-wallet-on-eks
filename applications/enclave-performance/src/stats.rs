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
}

impl MeasurementStats {
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

        Some(MeasurementStats {
            min_us,
            max_us,
            mean_us,
            median_us,
            count: latencies.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Feature: enclave-perf-cli, Property 2: Statistics Calculation Correctness
    // **Validates: Requirements 3.4, 4.4, 5.5**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

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
}
