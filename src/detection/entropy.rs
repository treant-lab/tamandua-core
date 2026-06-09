//! Entropy analysis for detecting packed/encrypted files

use super::{DetectionResult, DetectionSeverity, DetectionType, ResponseAction};
use crate::error::Result;
use crate::platform;
use std::path::Path;
use tracing::debug;

/// Entropy analyzer
pub struct EntropyAnalyzer {
    /// Entropy threshold (0.0-8.0)
    threshold: f64,
}

impl EntropyAnalyzer {
    /// Create a new entropy analyzer
    pub fn new(threshold: f64) -> Self {
        Self { threshold }
    }

    /// Analyze a file's entropy
    pub fn analyze_file<P: AsRef<Path>>(&self, path: P) -> Result<Option<DetectionResult>> {
        let path = path.as_ref();
        let data = std::fs::read(path)?;

        if data.is_empty() {
            return Ok(None);
        }

        let entropy = platform::calculate_entropy(&data);
        debug!("File entropy: {} for {:?}", entropy, path);

        if entropy >= self.threshold {
            let severity = if entropy >= 7.8 {
                DetectionSeverity::High
            } else if entropy >= 7.5 {
                DetectionSeverity::Medium
            } else {
                DetectionSeverity::Low
            };

            let confidence = ((entropy - self.threshold) / (8.0 - self.threshold)).min(1.0);

            Ok(Some(DetectionResult {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                severity,
                detection_type: DetectionType::Entropy,
                target: path.to_string_lossy().to_string(),
                details: format!(
                    "High entropy detected: {:.2} (threshold: {:.2})",
                    entropy, self.threshold
                ),
                confidence,
                recommended_action: if severity == DetectionSeverity::High {
                    ResponseAction::Quarantine
                } else {
                    ResponseAction::Alert
                },
                metadata: serde_json::json!({
                    "entropy": entropy,
                    "threshold": self.threshold,
                    "file_size": data.len(),
                }),
            }))
        } else {
            Ok(None)
        }
    }

    /// Analyze data in memory
    pub fn analyze_memory(&self, data: &[u8], context: &str) -> Option<DetectionResult> {
        if data.is_empty() {
            return None;
        }

        let entropy = platform::calculate_entropy(data);

        if entropy >= self.threshold {
            let severity = if entropy >= 7.8 {
                DetectionSeverity::High
            } else if entropy >= 7.5 {
                DetectionSeverity::Medium
            } else {
                DetectionSeverity::Low
            };

            let confidence = ((entropy - self.threshold) / (8.0 - self.threshold)).min(1.0);

            Some(DetectionResult {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                severity,
                detection_type: DetectionType::Entropy,
                target: context.to_string(),
                details: format!(
                    "High entropy detected in memory: {:.2} (threshold: {:.2})",
                    entropy, self.threshold
                ),
                confidence,
                recommended_action: ResponseAction::Alert,
                metadata: serde_json::json!({
                    "entropy": entropy,
                    "threshold": self.threshold,
                    "data_size": data.len(),
                }),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_entropy_detection() {
        let analyzer = EntropyAnalyzer::new(7.0);

        // High entropy data (random-ish)
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let result = analyzer.analyze_memory(&data, "test");

        assert!(result.is_some());
        let detection = result.unwrap();
        assert_eq!(detection.detection_type, DetectionType::Entropy);
    }

    #[test]
    fn test_low_entropy_no_detection() {
        let analyzer = EntropyAnalyzer::new(7.0);

        // Low entropy data (all zeros)
        let data = vec![0u8; 1024];
        let result = analyzer.analyze_memory(&data, "test");

        assert!(result.is_none());
    }
}
