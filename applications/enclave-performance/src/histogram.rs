//! Histogram module for latency distribution visualization.
//!
//! This module provides a histogram data structure for bucketing latency
//! measurements and visualizing their distribution.

/// Default bucket boundaries in microseconds.
///
/// These boundaries define the upper bounds (exclusive) for each bucket:
/// - Bucket 0: [0, 100) µs
/// - Bucket 1: [100, 200) µs
/// - Bucket 2: [200, 500) µs
/// - Bucket 3: [500, 1000) µs
/// - Bucket 4: [1000, 2000) µs
/// - Bucket 5: [2000, 5000) µs
/// - Bucket 6: [5000, 10000) µs
/// - Overflow: [10000, ∞) µs
pub const DEFAULT_BOUNDARIES: &[u64] = &[100, 200, 500, 1000, 2000, 5000, 10000];

/// Histogram for latency distribution visualization.
///
/// A histogram groups latency measurements into configurable buckets,
/// allowing visualization of the distribution of response times.
///
/// # Bucket Structure
///
/// Given boundaries `[b0, b1, ..., bn]`, the buckets are:
/// - Bucket 0: `[0, b0)`
/// - Bucket 1: `[b0, b1)`
/// - ...
/// - Bucket n: `[b(n-1), bn)`
/// - Overflow: `[bn, ∞)`
///
/// The `counts` vector has length `boundaries.len() + 1` to include the overflow bucket.
#[derive(Debug, Clone)]
pub struct Histogram {
    /// Bucket boundaries in microseconds (upper bounds, exclusive).
    boundaries: Vec<u64>,
    /// Count of values in each bucket (including overflow bucket at the end).
    counts: Vec<u64>,
    /// Total number of values added to the histogram.
    total: u64,
}

impl Histogram {
    /// Create a new histogram with specified boundaries.
    ///
    /// The boundaries define the upper bounds (exclusive) for each bucket.
    /// The counts vector will have length `boundaries.len() + 1` to include
    /// the overflow bucket.
    ///
    /// # Arguments
    ///
    /// * `boundaries` - A vector of bucket boundaries in microseconds.
    ///
    /// # Example
    ///
    /// ```
    /// use enclave_performance::histogram::Histogram;
    ///
    /// let histogram = Histogram::new(vec![100, 500, 1000]);
    /// // Creates buckets: [0, 100), [100, 500), [500, 1000), [1000, ∞)
    /// ```
    pub fn new(boundaries: Vec<u64>) -> Self {
        // counts has one more element than boundaries for the overflow bucket
        let counts = vec![0u64; boundaries.len() + 1];
        Self {
            boundaries,
            counts,
            total: 0,
        }
    }

    /// Create a histogram with default boundaries.
    ///
    /// Uses `DEFAULT_BOUNDARIES`: [100, 200, 500, 1000, 2000, 5000, 10000] µs
    ///
    /// # Example
    ///
    /// ```
    /// use enclave_performance::histogram::Histogram;
    ///
    /// let histogram = Histogram::with_defaults();
    /// ```
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_BOUNDARIES.to_vec())
    }

    /// Add a single latency value to the histogram.
    ///
    /// The value is placed in the appropriate bucket based on the boundaries:
    /// - Bucket 0: `[0, boundaries[0])`
    /// - Bucket i: `[boundaries[i-1], boundaries[i])`
    /// - Overflow: `[boundaries[N], ∞)`
    ///
    /// # Arguments
    ///
    /// * `value` - The latency value in microseconds to record.
    ///
    /// # Example
    ///
    /// ```
    /// use enclave_performance::histogram::Histogram;
    ///
    /// let mut histogram = Histogram::new(vec![100, 500, 1000]);
    /// histogram.record(50);   // Goes to bucket 0: [0, 100)
    /// histogram.record(250);  // Goes to bucket 1: [100, 500)
    /// histogram.record(5000); // Goes to overflow bucket: [1000, ∞)
    /// ```
    pub fn record(&mut self, value: u64) {
        // Find the bucket index for this value
        // Binary search returns Ok(index) if found, Err(index) if not found
        // where index is the position where the value would be inserted
        let bucket_index = match self.boundaries.binary_search(&value) {
            // Value equals a boundary - it goes in the next bucket
            // (boundaries are exclusive upper bounds)
            Ok(idx) => idx + 1,
            // Value is between boundaries - Err gives us the insertion point
            // which is exactly the bucket index we want
            Err(idx) => idx,
        };

        self.counts[bucket_index] += 1;
        self.total += 1;
    }

    /// Get bucket boundaries.
    ///
    /// Returns a slice of the bucket boundaries in microseconds.
    /// These are the upper bounds (exclusive) for each bucket.
    ///
    /// # Example
    ///
    /// ```
    /// use enclave_performance::histogram::Histogram;
    ///
    /// let histogram = Histogram::new(vec![100, 500, 1000]);
    /// assert_eq!(histogram.boundaries(), &[100, 500, 1000]);
    /// ```
    pub fn boundaries(&self) -> &[u64] {
        &self.boundaries
    }

    /// Get bucket counts.
    ///
    /// Returns a slice of the counts for each bucket.
    /// The length is `boundaries.len() + 1` to include the overflow bucket.
    ///
    /// # Example
    ///
    /// ```
    /// use enclave_performance::histogram::Histogram;
    ///
    /// let mut histogram = Histogram::new(vec![100, 500]);
    /// histogram.record(50);   // bucket 0
    /// histogram.record(200);  // bucket 1
    /// histogram.record(1000); // overflow bucket
    /// assert_eq!(histogram.counts(), &[1, 1, 1]);
    /// ```
    pub fn counts(&self) -> &[u64] {
        &self.counts
    }

    /// Get total count of all recorded values.
    ///
    /// # Example
    ///
    /// ```
    /// use enclave_performance::histogram::Histogram;
    ///
    /// let mut histogram = Histogram::with_defaults();
    /// histogram.record(100);
    /// histogram.record(200);
    /// assert_eq!(histogram.total(), 2);
    /// ```
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Create a histogram from a slice of latency measurements.
    ///
    /// This constructor creates a histogram and records all provided latency
    /// values into it. If custom boundaries are provided, they are used;
    /// otherwise, the default boundaries are used.
    ///
    /// # Arguments
    ///
    /// * `latencies` - A slice of latency values in microseconds to record.
    /// * `boundaries` - Optional custom bucket boundaries. If `None`, uses `DEFAULT_BOUNDARIES`.
    ///
    /// # Example
    ///
    /// ```
    /// use enclave_performance::histogram::Histogram;
    ///
    /// // Create histogram with default boundaries
    /// let latencies = vec![50, 150, 250, 1500, 8000];
    /// let histogram = Histogram::from_measurements(&latencies, None);
    /// assert_eq!(histogram.total(), 5);
    ///
    /// // Create histogram with custom boundaries
    /// let custom_boundaries = vec![100, 500, 1000];
    /// let histogram = Histogram::from_measurements(&latencies, Some(custom_boundaries));
    /// assert_eq!(histogram.total(), 5);
    /// ```
    pub fn from_measurements(latencies: &[u64], boundaries: Option<Vec<u64>>) -> Self {
        let mut histogram = match boundaries {
            Some(b) => Self::new(b),
            None => Self::with_defaults(),
        };

        for &latency in latencies {
            histogram.record(latency);
        }

        histogram
    }

    /// Merge another histogram into this one (for aggregation).
    ///
    /// This method combines the bucket counts from another histogram into this one,
    /// which is useful for aggregating results from parallel workers.
    ///
    /// # Arguments
    ///
    /// * `other` - The histogram to merge into this one.
    ///
    /// # Panics
    ///
    /// Panics if the boundaries of the two histograms do not match exactly.
    /// This is a programming error - histograms being merged must have been
    /// created with the same bucket configuration.
    ///
    /// # Example
    ///
    /// ```
    /// use enclave_performance::histogram::Histogram;
    ///
    /// let mut histogram1 = Histogram::new(vec![100, 500, 1000]);
    /// histogram1.record(50);   // bucket 0
    /// histogram1.record(200);  // bucket 1
    ///
    /// let mut histogram2 = Histogram::new(vec![100, 500, 1000]);
    /// histogram2.record(75);   // bucket 0
    /// histogram2.record(750);  // bucket 2
    ///
    /// histogram1.merge(&histogram2);
    ///
    /// assert_eq!(histogram1.total(), 4);
    /// assert_eq!(histogram1.counts(), &[2, 1, 1, 0]);
    /// ```
    pub fn merge(&mut self, other: &Histogram) {
        // Validate that boundaries match before merging
        assert_eq!(
            self.boundaries, other.boundaries,
            "Cannot merge histograms with different boundaries: self has {:?}, other has {:?}",
            self.boundaries, other.boundaries
        );

        // Sum bucket counts from both histograms
        for (self_count, other_count) in self.counts.iter_mut().zip(other.counts.iter()) {
            *self_count += other_count;
        }

        // Update total count
        self.total += other.total;
    }

    /// Render the histogram as ASCII art.
    ///
    /// Generates an ASCII bar chart showing the distribution of latency values
    /// across buckets. Bar lengths are proportional to bucket counts.
    ///
    /// # Arguments
    ///
    /// * `max_width` - The maximum width for the bar portion of the visualization.
    ///
    /// # Returns
    ///
    /// A string containing the ASCII visualization with one line per bucket.
    ///
    /// # Example Output
    ///
    /// ```text
    /// Latency Distribution:
    ///     0-100µs  [████████████████████] 45 (45.0%)
    ///   100-200µs  [██████████          ] 25 (25.0%)
    ///   200-500µs  [████                ]  8 (8.0%)
    ///  500-1000µs  [██                  ]  5 (5.0%)
    /// 1000-2000µs  [█                   ]  2 (2.0%)
    /// 2000-5000µs  [                    ]  0 (0.0%)
    ///     >5000µs  [███████████████     ] 15 (15.0%)
    /// ```
    pub fn render_ascii(&self, max_width: usize) -> String {
        use std::fmt::Write;

        let mut output = String::new();
        writeln!(output, "Latency Distribution:").unwrap();

        // Calculate max count for scaling
        let max_count = self.counts.iter().copied().max().unwrap_or(0);

        // Generate bucket range labels and find the maximum label width for alignment
        let mut labels: Vec<String> = Vec::with_capacity(self.counts.len());

        for i in 0..self.counts.len() {
            let label = if i == 0 {
                // First bucket: [0, boundaries[0])
                if self.boundaries.is_empty() {
                    "all".to_string()
                } else {
                    format!("0-{}µs", self.boundaries[0])
                }
            } else if i < self.boundaries.len() {
                // Middle buckets: [boundaries[i-1], boundaries[i])
                format!("{}-{}µs", self.boundaries[i - 1], self.boundaries[i])
            } else {
                // Overflow bucket: [boundaries[N], ∞)
                if self.boundaries.is_empty() {
                    "all".to_string()
                } else {
                    format!(">{}µs", self.boundaries[self.boundaries.len() - 1])
                }
            };
            labels.push(label);
        }

        // Find max label width for alignment
        let max_label_width = labels.iter().map(|l| l.len()).max().unwrap_or(0);

        // Calculate percentage for each bucket
        let total = self.total as f64;

        // Render each bucket
        for (i, &count) in self.counts.iter().enumerate() {
            // Calculate bar length proportional to count
            let bar_length = if max_count > 0 {
                ((count as f64 / max_count as f64) * max_width as f64).round() as usize
            } else {
                0
            };

            // Generate the bar using █ character
            let bar: String = "█".repeat(bar_length);
            let padding: String = " ".repeat(max_width.saturating_sub(bar_length));

            // Calculate percentage
            let percentage = if total > 0.0 {
                (count as f64 / total) * 100.0
            } else {
                0.0
            };

            // Format the line with proper alignment
            // Right-align the label, then the bar in brackets, then count and percentage
            let label = &labels[i];
            let line = format!(
                "{:>width$}  [{}{}] {} ({:.1}%)",
                label,
                bar,
                padding,
                count,
                percentage,
                width = max_label_width
            );

            // Ensure line doesn't exceed 80 characters (character count, not byte length)
            // If it does, we truncate the bar portion
            let line_char_count = line.chars().count();
            if line_char_count > 80 {
                // Recalculate with reduced bar width
                // The overhead is the non-bar portion of the line
                let overhead = line_char_count - max_width;
                let available_bar_width = if overhead < 80 {
                    80 - overhead
                } else {
                    1 // Minimum bar width
                };

                let adjusted_bar_length = if max_count > 0 {
                    ((count as f64 / max_count as f64) * available_bar_width as f64).round() as usize
                } else {
                    0
                };

                let adjusted_bar: String = "█".repeat(adjusted_bar_length);
                let adjusted_padding: String =
                    " ".repeat(available_bar_width.saturating_sub(adjusted_bar_length));

                writeln!(
                    output,
                    "{:>width$}  [{}{}] {} ({:.1}%)",
                    label,
                    adjusted_bar,
                    adjusted_padding,
                    count,
                    percentage,
                    width = max_label_width
                )
                .unwrap();
            } else {
                writeln!(output, "{}", line).unwrap();
            }
        }

        output
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Feature: advanced-performance-metrics, Property 3: ASCII Rendering Correctness
    // **Validates: Requirements 3.2, 3.3, 3.4**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_ascii_rendering_correctness(
            // Generate random latencies (0 to 50,000 µs range)
            latencies in prop::collection::vec(0u64..=50_000u64, 1..=200),
            // Generate random boundaries (1 to 8 boundaries, values 100 to 20,000 µs)
            raw_boundaries in prop::collection::vec(100u64..=20_000u64, 1..=8),
            // Generate random max_width for bar rendering (10 to 40)
            max_width in 10usize..=40usize
        ) {
            // Prepare boundaries: sort and deduplicate to ensure valid configuration
            let mut boundaries = raw_boundaries.clone();
            boundaries.sort_unstable();
            boundaries.dedup();

            // Create histogram from measurements
            let histogram = Histogram::from_measurements(&latencies, Some(boundaries.clone()));

            // Render ASCII visualization
            let output = histogram.render_ascii(max_width);

            // Property 3a: The rendered string contains all bucket range labels
            // First bucket: "0-{boundaries[0]}µs"
            if !boundaries.is_empty() {
                let first_label = format!("0-{}µs", boundaries[0]);
                prop_assert!(
                    output.contains(&first_label),
                    "Output should contain first bucket label '{}'\nOutput:\n{}",
                    first_label,
                    output
                );

                // Middle buckets: "{boundaries[i-1]}-{boundaries[i]}µs"
                for i in 1..boundaries.len() {
                    let label = format!("{}-{}µs", boundaries[i - 1], boundaries[i]);
                    prop_assert!(
                        output.contains(&label),
                        "Output should contain bucket label '{}'\nOutput:\n{}",
                        label,
                        output
                    );
                }

                // Overflow bucket: ">{boundaries[N]}µs"
                let overflow_label = format!(">{}µs", boundaries[boundaries.len() - 1]);
                prop_assert!(
                    output.contains(&overflow_label),
                    "Output should contain overflow bucket label '{}'\nOutput:\n{}",
                    overflow_label,
                    output
                );
            }

            // Property 3b: The rendered string contains all bucket counts
            for &count in histogram.counts() {
                // Each count should appear in the output followed by a space and opening paren
                // Format is: "count (percentage%)"
                let count_pattern = format!(" {} (", count);
                prop_assert!(
                    output.contains(&count_pattern),
                    "Output should contain count '{}' in format ' {} ('\nOutput:\n{}",
                    count,
                    count,
                    output
                );
            }

            // Property 3c: No rendered line exceeds 80 characters total width
            for line in output.lines() {
                let char_count = line.chars().count();
                prop_assert!(
                    char_count <= 80,
                    "Line exceeds 80 characters (has {}): '{}'\nFull output:\n{}",
                    char_count,
                    line,
                    output
                );
            }

            // Property 3d: Zero-count buckets display with count "0"
            for (i, &count) in histogram.counts().iter().enumerate() {
                if count == 0 {
                    // Zero-count buckets should show " 0 (" in their line
                    prop_assert!(
                        output.contains(" 0 ("),
                        "Zero-count bucket {} should display with count '0'\nOutput:\n{}",
                        i,
                        output
                    );
                }
            }

            // Property 3e: Bar lengths are proportional to bucket counts
            // bar_length = count / max_count * max_width (rounded)
            let max_count = histogram.counts().iter().copied().max().unwrap_or(0);
            
            if max_count > 0 {
                // Parse the output to extract bar lengths for each bucket
                let lines: Vec<&str> = output.lines().skip(1).collect(); // Skip header
                
                for (i, &count) in histogram.counts().iter().enumerate() {
                    // Calculate expected bar length
                    let expected_bar_length = ((count as f64 / max_count as f64) * max_width as f64).round() as usize;
                    
                    // Find the line for this bucket by looking for its label
                    let label = if i == 0 {
                        if boundaries.is_empty() {
                            "all".to_string()
                        } else {
                            format!("0-{}µs", boundaries[0])
                        }
                    } else if i < boundaries.len() {
                        format!("{}-{}µs", boundaries[i - 1], boundaries[i])
                    } else {
                        if boundaries.is_empty() {
                            "all".to_string()
                        } else {
                            format!(">{}µs", boundaries[boundaries.len() - 1])
                        }
                    };
                    
                    if let Some(line) = lines.iter().find(|l| l.contains(&label)) {
                        // Count the █ characters in the line
                        let actual_bar_length = line.matches('█').count();
                        
                        // The bar length should match expected (may be adjusted for width constraint)
                        // Allow for width adjustment when line would exceed 80 chars
                        let line_char_count = line.chars().count();
                        if line_char_count <= 80 {
                            prop_assert_eq!(
                                actual_bar_length,
                                expected_bar_length,
                                "Bar length for bucket '{}' should be {} (count={}, max_count={}, max_width={}), got {}\nLine: '{}'",
                                label,
                                expected_bar_length,
                                count,
                                max_count,
                                max_width,
                                actual_bar_length,
                                line
                            );
                        }
                        // If line was adjusted for width constraint, we just verify it doesn't exceed 80
                    }
                }
            }
        }

        #[test]
        fn property_ascii_rendering_all_zero_counts(
            // Generate random boundaries
            raw_boundaries in prop::collection::vec(100u64..=10_000u64, 1..=6),
            max_width in 10usize..=30usize
        ) {
            // Prepare boundaries
            let mut boundaries = raw_boundaries.clone();
            boundaries.sort_unstable();
            boundaries.dedup();

            // Create empty histogram (all zero counts)
            let histogram = Histogram::new(boundaries.clone());

            let output = histogram.render_ascii(max_width);

            // Property: All buckets should display with count "0"
            let zero_count_occurrences = output.matches(" 0 (").count();
            prop_assert_eq!(
                zero_count_occurrences,
                boundaries.len() + 1, // +1 for overflow bucket
                "All {} buckets should show count '0', found {} occurrences\nOutput:\n{}",
                boundaries.len() + 1,
                zero_count_occurrences,
                output
            );

            // Property: No bars should be rendered (all counts are 0)
            let bar_count = output.matches('█').count();
            prop_assert_eq!(
                bar_count,
                0,
                "No bars should be rendered for empty histogram, found {} bars\nOutput:\n{}",
                bar_count,
                output
            );

            // Property: No line exceeds 80 characters
            for line in output.lines() {
                let char_count = line.chars().count();
                prop_assert!(
                    char_count <= 80,
                    "Line exceeds 80 characters (has {}): '{}'",
                    char_count,
                    line
                );
            }
        }

        #[test]
        fn property_ascii_rendering_single_bucket_max_bar(
            // Generate latencies all in one bucket
            count in 1u64..=1000u64,
            max_width in 10usize..=40usize
        ) {
            // Create histogram with single boundary, all values in first bucket
            let mut histogram = Histogram::new(vec![1000]);
            for _ in 0..count {
                histogram.record(500); // All values in [0, 1000) bucket
            }

            let output = histogram.render_ascii(max_width);

            // Property: The bucket with all values should have full bar (max_width)
            let lines: Vec<&str> = output.lines().skip(1).collect();
            if let Some(line) = lines.iter().find(|l| l.contains("0-1000µs")) {
                let bar_length = line.matches('█').count();
                
                // Check if line was adjusted for width constraint
                let line_char_count = line.chars().count();
                if line_char_count <= 80 {
                    prop_assert_eq!(
                        bar_length,
                        max_width,
                        "Bucket with max count should have full bar ({}), got {}\nLine: '{}'",
                        max_width,
                        bar_length,
                        line
                    );
                }
            }

            // Property: Overflow bucket should have 0 count and no bar
            if let Some(line) = lines.iter().find(|l| l.contains(">1000µs")) {
                prop_assert!(
                    line.contains(" 0 ("),
                    "Overflow bucket should have count 0\nLine: '{}'",
                    line
                );
                let bar_length = line.matches('█').count();
                prop_assert_eq!(
                    bar_length,
                    0,
                    "Overflow bucket should have no bar, got {}\nLine: '{}'",
                    bar_length,
                    line
                );
            }
        }
    }

    // Feature: advanced-performance-metrics, Property 2: Histogram Bucketing Correctness
    // **Validates: Requirements 2.1, 2.2, 2.3, 2.5, 2.6**
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn property_histogram_bucketing_correctness(
            // Generate random latencies (0 to 100,000 µs range)
            latencies in prop::collection::vec(0u64..=100_000u64, 0..=500),
            // Generate random boundaries (1 to 10 boundaries, values 1 to 50,000 µs)
            raw_boundaries in prop::collection::vec(1u64..=50_000u64, 1..=10)
        ) {
            // Prepare boundaries: sort and deduplicate to ensure valid configuration
            let mut boundaries = raw_boundaries.clone();
            boundaries.sort_unstable();
            boundaries.dedup();

            // Create histogram from measurements
            let histogram = Histogram::from_measurements(&latencies, Some(boundaries.clone()));

            // Property 2a: The sum of all bucket counts equals the input slice length
            let total_count: u64 = histogram.counts().iter().sum();
            prop_assert_eq!(
                total_count,
                latencies.len() as u64,
                "Sum of bucket counts ({}) should equal input length ({})",
                total_count,
                latencies.len()
            );

            // Property 2b: Total accessor matches sum of counts
            prop_assert_eq!(
                histogram.total(),
                latencies.len() as u64,
                "Histogram total ({}) should equal input length ({})",
                histogram.total(),
                latencies.len()
            );

            // Property 2c: Bucket boundaries are retrievable and match the input configuration
            prop_assert_eq!(
                histogram.boundaries(),
                &boundaries[..],
                "Histogram boundaries should match input configuration"
            );

            // Property 2d: Counts vector has correct length (boundaries + 1 for overflow)
            prop_assert_eq!(
                histogram.counts().len(),
                boundaries.len() + 1,
                "Counts length ({}) should be boundaries length + 1 ({})",
                histogram.counts().len(),
                boundaries.len() + 1
            );

            // Property 2e: Each latency value is placed in exactly one bucket
            // Verify by manually counting values per bucket and comparing
            let mut expected_counts = vec![0u64; boundaries.len() + 1];
            for &latency in &latencies {
                // Determine which bucket this latency should go into:
                // - Bucket 0: [0, boundaries[0])
                // - Bucket i: [boundaries[i-1], boundaries[i])
                // - Overflow: [boundaries[N], ∞)
                let bucket_idx = boundaries.iter()
                    .position(|&b| latency < b)
                    .unwrap_or(boundaries.len());
                expected_counts[bucket_idx] += 1;
            }

            prop_assert_eq!(
                histogram.counts(),
                &expected_counts[..],
                "Bucket counts should match expected distribution"
            );

            // Property 2f: Values in range [0, boundaries[0]) go to bucket 0
            // (Verified implicitly by the bucket distribution check above)

            // Property 2g: Values >= max boundary go to the overflow bucket
            // Verify overflow bucket specifically
            let overflow_count = latencies.iter()
                .filter(|&&v| v >= *boundaries.last().unwrap_or(&0))
                .count() as u64;
            let actual_overflow = *histogram.counts().last().unwrap();
            prop_assert_eq!(
                actual_overflow,
                overflow_count,
                "Overflow bucket count ({}) should match values >= max boundary ({})",
                actual_overflow,
                overflow_count
            );
        }

        #[test]
        fn property_histogram_bucketing_with_default_boundaries(
            // Generate random latencies covering a wide range
            latencies in prop::collection::vec(0u64..=20_000u64, 0..=200)
        ) {
            // Test with default boundaries
            let histogram = Histogram::from_measurements(&latencies, None);

            // Property: Sum of bucket counts equals input length
            let total_count: u64 = histogram.counts().iter().sum();
            prop_assert_eq!(
                total_count,
                latencies.len() as u64,
                "Sum of bucket counts ({}) should equal input length ({})",
                total_count,
                latencies.len()
            );

            // Property: Boundaries match DEFAULT_BOUNDARIES
            prop_assert_eq!(
                histogram.boundaries(),
                DEFAULT_BOUNDARIES,
                "Default boundaries should be used"
            );

            // Property: Each value is in exactly one bucket (verify via manual count)
            let mut expected_counts = vec![0u64; DEFAULT_BOUNDARIES.len() + 1];
            for &latency in &latencies {
                let bucket_idx = DEFAULT_BOUNDARIES.iter()
                    .position(|&b| latency < b)
                    .unwrap_or(DEFAULT_BOUNDARIES.len());
                expected_counts[bucket_idx] += 1;
            }

            prop_assert_eq!(
                histogram.counts(),
                &expected_counts[..],
                "Bucket counts should match expected distribution with default boundaries"
            );
        }

        #[test]
        fn property_histogram_record_incremental(
            // Generate random latencies
            latencies in prop::collection::vec(0u64..=10_000u64, 1..=100),
            // Generate random boundaries
            raw_boundaries in prop::collection::vec(1u64..=5_000u64, 1..=5)
        ) {
            // Prepare boundaries
            let mut boundaries = raw_boundaries.clone();
            boundaries.sort_unstable();
            boundaries.dedup();

            // Create histogram by recording values one at a time
            let mut histogram = Histogram::new(boundaries.clone());
            for &latency in &latencies {
                histogram.record(latency);
            }

            // Create histogram from measurements (batch)
            let batch_histogram = Histogram::from_measurements(&latencies, Some(boundaries.clone()));

            // Property: Both methods should produce identical results
            prop_assert_eq!(
                histogram.counts(),
                batch_histogram.counts(),
                "Incremental recording should match batch creation"
            );

            prop_assert_eq!(
                histogram.total(),
                batch_histogram.total(),
                "Totals should match between incremental and batch"
            );
        }

        #[test]
        fn property_histogram_boundary_values_exclusive(
            // Generate boundaries
            raw_boundaries in prop::collection::vec(100u64..=10_000u64, 1..=5)
        ) {
            // Prepare boundaries
            let mut boundaries = raw_boundaries.clone();
            boundaries.sort_unstable();
            boundaries.dedup();

            // Test that boundary values go to the NEXT bucket (exclusive upper bound)
            for (i, &boundary) in boundaries.iter().enumerate() {
                let mut histogram = Histogram::new(boundaries.clone());
                
                // Record the exact boundary value
                histogram.record(boundary);
                
                // The value should be in bucket i+1 (next bucket), not bucket i
                // Because boundaries are exclusive upper bounds
                prop_assert_eq!(
                    histogram.counts()[i + 1],
                    1,
                    "Boundary value {} should go to bucket {} (next bucket), not bucket {}",
                    boundary,
                    i + 1,
                    i
                );
                
                // All other buckets should be 0
                for (j, &count) in histogram.counts().iter().enumerate() {
                    if j != i + 1 {
                        prop_assert_eq!(
                            count,
                            0,
                            "Bucket {} should be 0 when only boundary value {} is recorded",
                            j,
                            boundary
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_new_creates_correct_bucket_count() {
        let histogram = Histogram::new(vec![100, 200, 500]);
        assert_eq!(histogram.boundaries().len(), 3);
        assert_eq!(histogram.counts().len(), 4); // 3 boundaries + 1 overflow
        assert_eq!(histogram.total(), 0);
    }

    #[test]
    fn test_with_defaults_uses_default_boundaries() {
        let histogram = Histogram::with_defaults();
        assert_eq!(histogram.boundaries(), DEFAULT_BOUNDARIES);
        assert_eq!(histogram.counts().len(), DEFAULT_BOUNDARIES.len() + 1);
    }

    #[test]
    fn test_record_first_bucket() {
        let mut histogram = Histogram::new(vec![100, 200, 500]);
        histogram.record(0);
        histogram.record(50);
        histogram.record(99);
        
        assert_eq!(histogram.counts()[0], 3);
        assert_eq!(histogram.total(), 3);
    }

    #[test]
    fn test_record_middle_buckets() {
        let mut histogram = Histogram::new(vec![100, 200, 500]);
        
        // Bucket 1: [100, 200)
        histogram.record(100);
        histogram.record(150);
        histogram.record(199);
        
        // Bucket 2: [200, 500)
        histogram.record(200);
        histogram.record(300);
        histogram.record(499);
        
        assert_eq!(histogram.counts()[1], 3);
        assert_eq!(histogram.counts()[2], 3);
        assert_eq!(histogram.total(), 6);
    }

    #[test]
    fn test_record_overflow_bucket() {
        let mut histogram = Histogram::new(vec![100, 200, 500]);
        histogram.record(500);
        histogram.record(1000);
        histogram.record(u64::MAX);
        
        assert_eq!(histogram.counts()[3], 3); // overflow bucket
        assert_eq!(histogram.total(), 3);
    }

    #[test]
    fn test_record_boundary_values() {
        // Test that boundary values go to the next bucket (exclusive upper bound)
        let mut histogram = Histogram::new(vec![100, 200]);
        
        histogram.record(99);   // bucket 0: [0, 100)
        histogram.record(100);  // bucket 1: [100, 200) - boundary value
        histogram.record(199);  // bucket 1: [100, 200)
        histogram.record(200);  // bucket 2: overflow - boundary value
        
        assert_eq!(histogram.counts(), &[1, 2, 1]);
    }

    #[test]
    fn test_empty_boundaries() {
        let mut histogram = Histogram::new(vec![]);
        histogram.record(0);
        histogram.record(100);
        histogram.record(1000);
        
        // All values go to the single overflow bucket
        assert_eq!(histogram.counts().len(), 1);
        assert_eq!(histogram.counts()[0], 3);
        assert_eq!(histogram.total(), 3);
    }

    #[test]
    fn test_single_boundary() {
        let mut histogram = Histogram::new(vec![100]);
        histogram.record(50);   // bucket 0: [0, 100)
        histogram.record(100);  // bucket 1: overflow [100, ∞)
        histogram.record(200);  // bucket 1: overflow [100, ∞)
        
        assert_eq!(histogram.counts(), &[1, 2]);
    }

    #[test]
    fn test_boundaries_accessor() {
        let boundaries = vec![50, 100, 250, 500];
        let histogram = Histogram::new(boundaries.clone());
        assert_eq!(histogram.boundaries(), &boundaries[..]);
    }

    #[test]
    fn test_counts_accessor() {
        let mut histogram = Histogram::new(vec![100, 200]);
        histogram.record(50);
        histogram.record(150);
        histogram.record(250);
        
        let counts = histogram.counts();
        assert_eq!(counts.len(), 3);
        assert_eq!(counts[0], 1);
        assert_eq!(counts[1], 1);
        assert_eq!(counts[2], 1);
    }

    #[test]
    fn test_total_accessor() {
        let mut histogram = Histogram::with_defaults();
        assert_eq!(histogram.total(), 0);
        
        histogram.record(100);
        assert_eq!(histogram.total(), 1);
        
        histogram.record(200);
        histogram.record(300);
        assert_eq!(histogram.total(), 3);
    }

    #[test]
    fn test_from_measurements_with_default_boundaries() {
        let latencies = vec![50, 150, 250, 750, 1500, 3000, 7000, 15000];
        let histogram = Histogram::from_measurements(&latencies, None);
        
        assert_eq!(histogram.boundaries(), DEFAULT_BOUNDARIES);
        assert_eq!(histogram.total(), 8);
        
        // Verify bucket distribution:
        // [0, 100): 50 -> 1
        // [100, 200): 150 -> 1
        // [200, 500): 250 -> 1
        // [500, 1000): 750 -> 1
        // [1000, 2000): 1500 -> 1
        // [2000, 5000): 3000 -> 1
        // [5000, 10000): 7000 -> 1
        // [10000, ∞): 15000 -> 1
        assert_eq!(histogram.counts(), &[1, 1, 1, 1, 1, 1, 1, 1]);
    }

    #[test]
    fn test_from_measurements_with_custom_boundaries() {
        let latencies = vec![50, 150, 250, 750, 1500];
        let custom_boundaries = vec![100, 500, 1000];
        let histogram = Histogram::from_measurements(&latencies, Some(custom_boundaries.clone()));
        
        assert_eq!(histogram.boundaries(), &custom_boundaries[..]);
        assert_eq!(histogram.total(), 5);
        
        // Verify bucket distribution:
        // [0, 100): 50 -> 1
        // [100, 500): 150, 250 -> 2
        // [500, 1000): 750 -> 1
        // [1000, ∞): 1500 -> 1
        assert_eq!(histogram.counts(), &[1, 2, 1, 1]);
    }

    #[test]
    fn test_from_measurements_empty_slice() {
        let latencies: Vec<u64> = vec![];
        let histogram = Histogram::from_measurements(&latencies, None);
        
        assert_eq!(histogram.boundaries(), DEFAULT_BOUNDARIES);
        assert_eq!(histogram.total(), 0);
        assert_eq!(histogram.counts(), &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_from_measurements_single_value() {
        let latencies = vec![500];
        let histogram = Histogram::from_measurements(&latencies, Some(vec![100, 1000]));
        
        assert_eq!(histogram.total(), 1);
        // 500 is in bucket [100, 1000)
        assert_eq!(histogram.counts(), &[0, 1, 0]);
    }

    #[test]
    fn test_from_measurements_all_in_overflow() {
        let latencies = vec![1000, 2000, 5000];
        let histogram = Histogram::from_measurements(&latencies, Some(vec![100, 500]));
        
        assert_eq!(histogram.total(), 3);
        // All values >= 500, so all in overflow bucket
        assert_eq!(histogram.counts(), &[0, 0, 3]);
    }

    #[test]
    fn test_from_measurements_all_in_first_bucket() {
        let latencies = vec![10, 20, 30, 40, 50];
        let histogram = Histogram::from_measurements(&latencies, Some(vec![100, 500, 1000]));
        
        assert_eq!(histogram.total(), 5);
        // All values < 100, so all in first bucket
        assert_eq!(histogram.counts(), &[5, 0, 0, 0]);
    }

    #[test]
    fn test_from_measurements_boundary_values() {
        // Test that boundary values go to the correct bucket (exclusive upper bound)
        let latencies = vec![99, 100, 199, 200];
        let histogram = Histogram::from_measurements(&latencies, Some(vec![100, 200]));
        
        // 99 -> bucket 0: [0, 100)
        // 100 -> bucket 1: [100, 200)
        // 199 -> bucket 1: [100, 200)
        // 200 -> bucket 2: overflow [200, ∞)
        assert_eq!(histogram.counts(), &[1, 2, 1]);
    }

    // ==================== Merge Tests ====================

    #[test]
    fn test_merge_basic() {
        let mut histogram1 = Histogram::new(vec![100, 500, 1000]);
        histogram1.record(50);   // bucket 0
        histogram1.record(200);  // bucket 1

        let mut histogram2 = Histogram::new(vec![100, 500, 1000]);
        histogram2.record(75);   // bucket 0
        histogram2.record(750);  // bucket 2

        histogram1.merge(&histogram2);

        assert_eq!(histogram1.total(), 4);
        assert_eq!(histogram1.counts(), &[2, 1, 1, 0]);
    }

    #[test]
    fn test_merge_empty_into_populated() {
        let mut histogram1 = Histogram::new(vec![100, 500]);
        histogram1.record(50);
        histogram1.record(200);
        histogram1.record(600);

        let histogram2 = Histogram::new(vec![100, 500]);

        histogram1.merge(&histogram2);

        assert_eq!(histogram1.total(), 3);
        assert_eq!(histogram1.counts(), &[1, 1, 1]);
    }

    #[test]
    fn test_merge_populated_into_empty() {
        let mut histogram1 = Histogram::new(vec![100, 500]);

        let mut histogram2 = Histogram::new(vec![100, 500]);
        histogram2.record(50);
        histogram2.record(200);
        histogram2.record(600);

        histogram1.merge(&histogram2);

        assert_eq!(histogram1.total(), 3);
        assert_eq!(histogram1.counts(), &[1, 1, 1]);
    }

    #[test]
    fn test_merge_both_empty() {
        let mut histogram1 = Histogram::new(vec![100, 500]);
        let histogram2 = Histogram::new(vec![100, 500]);

        histogram1.merge(&histogram2);

        assert_eq!(histogram1.total(), 0);
        assert_eq!(histogram1.counts(), &[0, 0, 0]);
    }

    #[test]
    fn test_merge_multiple_histograms() {
        let mut combined = Histogram::new(vec![100, 500]);

        let mut h1 = Histogram::new(vec![100, 500]);
        h1.record(50);
        h1.record(200);

        let mut h2 = Histogram::new(vec![100, 500]);
        h2.record(75);
        h2.record(300);

        let mut h3 = Histogram::new(vec![100, 500]);
        h3.record(600);
        h3.record(700);

        combined.merge(&h1);
        combined.merge(&h2);
        combined.merge(&h3);

        assert_eq!(combined.total(), 6);
        assert_eq!(combined.counts(), &[2, 2, 2]);
    }

    #[test]
    fn test_merge_with_default_boundaries() {
        let mut histogram1 = Histogram::with_defaults();
        histogram1.record(50);
        histogram1.record(150);

        let mut histogram2 = Histogram::with_defaults();
        histogram2.record(250);
        histogram2.record(750);

        histogram1.merge(&histogram2);

        assert_eq!(histogram1.total(), 4);
        // Verify specific buckets
        assert_eq!(histogram1.counts()[0], 1); // [0, 100): 50
        assert_eq!(histogram1.counts()[1], 1); // [100, 200): 150
        assert_eq!(histogram1.counts()[2], 1); // [200, 500): 250
        assert_eq!(histogram1.counts()[3], 1); // [500, 1000): 750
    }

    #[test]
    fn test_merge_preserves_boundaries() {
        let boundaries = vec![100, 500, 1000];
        let mut histogram1 = Histogram::new(boundaries.clone());
        histogram1.record(50);

        let mut histogram2 = Histogram::new(boundaries.clone());
        histogram2.record(200);

        histogram1.merge(&histogram2);

        assert_eq!(histogram1.boundaries(), &boundaries[..]);
    }

    #[test]
    fn test_merge_all_in_overflow() {
        let mut histogram1 = Histogram::new(vec![100]);
        histogram1.record(500);
        histogram1.record(1000);

        let mut histogram2 = Histogram::new(vec![100]);
        histogram2.record(200);
        histogram2.record(300);

        histogram1.merge(&histogram2);

        assert_eq!(histogram1.total(), 4);
        assert_eq!(histogram1.counts(), &[0, 4]);
    }

    #[test]
    #[should_panic(expected = "Cannot merge histograms with different boundaries")]
    fn test_merge_different_boundaries_panics() {
        let mut histogram1 = Histogram::new(vec![100, 500]);
        let histogram2 = Histogram::new(vec![100, 200, 500]);

        histogram1.merge(&histogram2);
    }

    #[test]
    #[should_panic(expected = "Cannot merge histograms with different boundaries")]
    fn test_merge_different_boundary_values_panics() {
        let mut histogram1 = Histogram::new(vec![100, 500]);
        let histogram2 = Histogram::new(vec![100, 600]);

        histogram1.merge(&histogram2);
    }

    #[test]
    #[should_panic(expected = "Cannot merge histograms with different boundaries")]
    fn test_merge_empty_vs_nonempty_boundaries_panics() {
        let mut histogram1 = Histogram::new(vec![]);
        let histogram2 = Histogram::new(vec![100]);

        histogram1.merge(&histogram2);
    }

    // ==================== Render ASCII Tests ====================

    #[test]
    fn test_render_ascii_basic() {
        let mut histogram = Histogram::new(vec![100, 200, 500]);
        histogram.record(50);   // bucket 0
        histogram.record(150);  // bucket 1
        histogram.record(300);  // bucket 2
        histogram.record(1000); // overflow

        let output = histogram.render_ascii(20);

        // Verify header
        assert!(output.contains("Latency Distribution:"));

        // Verify all bucket ranges are present
        assert!(output.contains("0-100µs"));
        assert!(output.contains("100-200µs"));
        assert!(output.contains("200-500µs"));
        assert!(output.contains(">500µs"));

        // Verify counts are present
        assert!(output.contains(" 1 "));
    }

    #[test]
    fn test_render_ascii_zero_count_buckets() {
        let mut histogram = Histogram::new(vec![100, 200, 500]);
        histogram.record(50);   // bucket 0 only

        let output = histogram.render_ascii(20);

        // Verify zero-count buckets display with count "0"
        assert!(output.contains(" 0 (0.0%)"));
    }

    #[test]
    fn test_render_ascii_proportional_bars() {
        let mut histogram = Histogram::new(vec![100, 200]);
        // Add 10 values to bucket 0
        for _ in 0..10 {
            histogram.record(50);
        }
        // Add 5 values to bucket 1
        for _ in 0..5 {
            histogram.record(150);
        }

        let output = histogram.render_ascii(20);
        println!("Output:\n{}", output);

        // The bucket with max count (10) should have full bar (20 chars)
        // The bucket with half count (5) should have half bar (10 chars)
        // Count the █ characters in each line
        let lines: Vec<&str> = output.lines().collect();

        // Find the line with bucket 0 (0-100µs)
        let bucket0_line = lines.iter().find(|l| l.contains("0-100µs")).unwrap();
        let bucket0_bars = bucket0_line.matches('█').count();
        println!("Bucket 0 line: '{}' (bars={})", bucket0_line, bucket0_bars);

        // Find the line with bucket 1 (100-200µs)
        let bucket1_line = lines.iter().find(|l| l.contains("100-200µs")).unwrap();
        let bucket1_bars = bucket1_line.matches('█').count();
        println!("Bucket 1 line: '{}' (bars={})", bucket1_line, bucket1_bars);

        // Bucket 0 should have full bar (20)
        assert_eq!(bucket0_bars, 20);
        // Bucket 1 should have half bar (10)
        assert_eq!(bucket1_bars, 10);
    }

    #[test]
    fn test_render_ascii_empty_histogram() {
        let histogram = Histogram::new(vec![100, 200]);

        let output = histogram.render_ascii(20);

        // All buckets should show 0 count
        assert!(output.contains("Latency Distribution:"));
        // All lines should have 0 count
        for line in output.lines().skip(1) {
            // Skip header line
            if !line.is_empty() {
                assert!(line.contains(" 0 ("));
            }
        }
    }

    #[test]
    fn test_render_ascii_single_bucket() {
        let mut histogram = Histogram::new(vec![100]);
        histogram.record(50);
        histogram.record(200);

        let output = histogram.render_ascii(20);

        assert!(output.contains("0-100µs"));
        assert!(output.contains(">100µs"));
    }

    #[test]
    fn test_render_ascii_line_width_constraint() {
        // Create histogram with default boundaries (which have longer labels)
        let mut histogram = Histogram::with_defaults();
        for i in 0..100 {
            histogram.record(i * 100);
        }

        let output = histogram.render_ascii(20);

        // Verify no line exceeds 80 characters (character count, not byte length)
        for line in output.lines() {
            let char_count = line.chars().count();
            assert!(
                char_count <= 80,
                "Line exceeds 80 characters: {} (chars={})",
                line,
                char_count
            );
        }
    }

    #[test]
    fn test_render_ascii_percentage_calculation() {
        let mut histogram = Histogram::new(vec![100, 200]);
        // Add 50 values to bucket 0, 50 to bucket 1
        for _ in 0..50 {
            histogram.record(50);
        }
        for _ in 0..50 {
            histogram.record(150);
        }

        let output = histogram.render_ascii(20);

        // Each bucket should show 50.0%
        assert!(output.contains("(50.0%)"));
    }

    #[test]
    fn test_render_ascii_with_default_boundaries() {
        let mut histogram = Histogram::with_defaults();
        histogram.record(50);
        histogram.record(150);
        histogram.record(350);
        histogram.record(750);
        histogram.record(1500);
        histogram.record(3500);
        histogram.record(7500);
        histogram.record(15000);

        let output = histogram.render_ascii(20);

        // Verify all default bucket ranges are present
        assert!(output.contains("0-100µs"));
        assert!(output.contains("100-200µs"));
        assert!(output.contains("200-500µs"));
        assert!(output.contains("500-1000µs"));
        assert!(output.contains("1000-2000µs"));
        assert!(output.contains("2000-5000µs"));
        assert!(output.contains("5000-10000µs"));
        assert!(output.contains(">10000µs"));
    }

    #[test]
    fn test_render_ascii_all_in_one_bucket() {
        let mut histogram = Histogram::new(vec![100, 200, 500]);
        // All values in first bucket
        for _ in 0..100 {
            histogram.record(50);
        }

        let output = histogram.render_ascii(20);

        // First bucket should have full bar and 100%
        let lines: Vec<&str> = output.lines().collect();
        let bucket0_line = lines.iter().find(|l| l.contains("0-100µs")).unwrap();
        assert!(bucket0_line.contains("100 (100.0%)"));
        assert_eq!(bucket0_line.matches('█').count(), 20);

        // Other buckets should have 0 count and no bars
        let bucket1_line = lines.iter().find(|l| l.contains("100-200µs")).unwrap();
        assert!(bucket1_line.contains(" 0 (0.0%)"));
        assert_eq!(bucket1_line.matches('█').count(), 0);
    }

    #[test]
    fn test_render_ascii_large_counts() {
        let mut histogram = Histogram::new(vec![100]);
        // Add many values
        for _ in 0..10000 {
            histogram.record(50);
        }
        for _ in 0..5000 {
            histogram.record(200);
        }

        let output = histogram.render_ascii(20);

        // Verify counts are displayed correctly
        assert!(output.contains("10000"));
        assert!(output.contains("5000"));
    }
}
