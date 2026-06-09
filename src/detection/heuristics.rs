//! Heuristic-based detection

use super::{DetectionResult, DetectionSeverity, DetectionType, ResponseAction};
use crate::error::Result;
use crate::platform::ProcessInfo;
use std::path::Path;
use tracing::debug;

/// Heuristic engine
pub struct HeuristicEngine {
    /// Suspicious extensions
    suspicious_extensions: Vec<String>,
}

impl HeuristicEngine {
    /// Create a new heuristic engine
    pub fn new() -> Self {
        Self {
            suspicious_extensions: vec![
                ".exe".to_string(),
                ".dll".to_string(),
                ".bat".to_string(),
                ".cmd".to_string(),
                ".ps1".to_string(),
                ".vbs".to_string(),
                ".js".to_string(),
                ".jar".to_string(),
                ".scr".to_string(),
            ],
        }
    }

    /// Analyze a file using heuristics
    pub fn analyze_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<DetectionResult>> {
        let path = path.as_ref();
        let mut detections = Vec::new();

        // Check for suspicious file name patterns
        if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
            // Double extension
            if filename.matches('.').count() > 1 {
                detections.push(DetectionResult {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    severity: DetectionSeverity::Medium,
                    detection_type: DetectionType::Heuristic,
                    target: path.to_string_lossy().to_string(),
                    details: "File has double extension (possible masquerading)".to_string(),
                    confidence: 0.6,
                    recommended_action: ResponseAction::Alert,
                    metadata: serde_json::json!({
                        "heuristic": "double_extension",
                        "filename": filename,
                    }),
                });
            }

            // Hidden executable (starts with dot on Unix)
            #[cfg(not(target_os = "windows"))]
            if filename.starts_with('.') && self.is_executable(path) {
                detections.push(DetectionResult {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    severity: DetectionSeverity::Medium,
                    detection_type: DetectionType::Heuristic,
                    target: path.to_string_lossy().to_string(),
                    details: "Hidden executable file detected".to_string(),
                    confidence: 0.7,
                    recommended_action: ResponseAction::Alert,
                    metadata: serde_json::json!({
                        "heuristic": "hidden_executable",
                        "filename": filename,
                    }),
                });
            }

            // Executable in temp directory
            let path_str = path.to_string_lossy().to_lowercase();
            if (path_str.contains("temp") || path_str.contains("tmp")) && self.is_executable(path) {
                detections.push(DetectionResult {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    severity: DetectionSeverity::Low,
                    detection_type: DetectionType::Heuristic,
                    target: path.to_string_lossy().to_string(),
                    details: "Executable in temporary directory".to_string(),
                    confidence: 0.5,
                    recommended_action: ResponseAction::Alert,
                    metadata: serde_json::json!({
                        "heuristic": "temp_executable",
                        "path": path_str,
                    }),
                });
            }
        }

        Ok(detections)
    }

    /// Analyze a process using heuristics
    pub fn analyze_process(&self, process: &ProcessInfo) -> Result<Vec<DetectionResult>> {
        let mut detections = Vec::new();

        // Process with no parent (PPID 0)
        if process.ppid == 0 && process.pid > 4 {
            detections.push(DetectionResult {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                severity: DetectionSeverity::Medium,
                detection_type: DetectionType::Heuristic,
                target: format!("PID {}", process.pid),
                details: format!(
                    "Process '{}' has no parent (possible parent process exit or hollowing)",
                    process.name
                ),
                confidence: 0.6,
                recommended_action: ResponseAction::Alert,
                metadata: serde_json::json!({
                    "heuristic": "orphan_process",
                    "pid": process.pid,
                    "name": process.name,
                }),
            });
        }

        // Process running from unusual location
        let exe_lower = process.exe_path.to_lowercase();
        if (exe_lower.contains("appdata") || exe_lower.contains("temp")) && process.is_elevated {
            detections.push(DetectionResult {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                severity: DetectionSeverity::High,
                detection_type: DetectionType::Heuristic,
                target: format!("PID {}", process.pid),
                details: format!(
                    "Elevated process '{}' running from unusual location",
                    process.name
                ),
                confidence: 0.75,
                recommended_action: ResponseAction::Alert,
                metadata: serde_json::json!({
                    "heuristic": "unusual_elevated_location",
                    "pid": process.pid,
                    "name": process.name,
                    "exe_path": process.exe_path,
                }),
            });
        }

        // Excessive memory usage
        if process.memory_usage > 2 * 1024 * 1024 * 1024 {
            // > 2GB
            debug!(
                "Process {} using excessive memory: {} bytes",
                process.pid, process.memory_usage
            );
        }

        Ok(detections)
    }

    /// Check if file is executable
    fn is_executable<P: AsRef<Path>>(&self, path: P) -> bool {
        let path = path.as_ref();
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            self.suspicious_extensions
                .iter()
                .any(|s| s.trim_start_matches('.') == ext.to_lowercase())
        } else {
            false
        }
    }
}

impl Default for HeuristicEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_extension_detection() {
        let engine = HeuristicEngine::new();
        let path = Path::new("/tmp/document.pdf.exe");

        let detections = engine.analyze_file(path).unwrap();
        assert!(!detections.is_empty());
        assert_eq!(detections[0].detection_type, DetectionType::Heuristic);
    }
}
