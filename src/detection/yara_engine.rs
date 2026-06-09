//! YARA engine integration

use super::{DetectionResult, DetectionSeverity, DetectionType, ResponseAction};
use crate::config::AgentConfig;
use crate::error::{Error, Result};
use std::path::Path;
use tracing::{debug, info};

#[cfg(feature = "yara-integration")]
use yara::{Compiler, Rules};

/// YARA engine
pub struct YaraEngine {
    /// Compiled YARA rules
    #[cfg(feature = "yara-integration")]
    rules: Option<Rules>,

    /// Rules directory
    rules_dir: Option<std::path::PathBuf>,
}

impl YaraEngine {
    /// Create a new YARA engine
    pub fn new(config: &AgentConfig) -> Result<Self> {
        Ok(Self {
            #[cfg(feature = "yara-integration")]
            rules: None,
            rules_dir: config.detection.yara_rules_dir.clone(),
        })
    }

    /// Load YARA rules from directory
    #[cfg(feature = "yara-integration")]
    pub fn load_rules(&mut self) -> Result<()> {
        let rules_dir = self
            .rules_dir
            .as_ref()
            .ok_or_else(|| Error::detection("YARA rules directory not configured"))?;

        if !rules_dir.exists() {
            return Err(Error::not_found(format!(
                "YARA rules directory not found: {:?}",
                rules_dir
            )));
        }

        info!("Loading YARA rules from {:?}", rules_dir);

        let mut compiler = Compiler::new()?;

        // Load all .yar and .yara files
        for entry in std::fs::read_dir(rules_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) == Some("yar")
                || path.extension().and_then(|e| e.to_str()) == Some("yara")
            {
                debug!("Loading YARA rule file: {:?}", path);
                compiler = compiler
                    .add_rules_file(&path)
                    .map_err(|e| Error::detection(format!("Failed to load YARA rule: {}", e)))?;
            }
        }

        self.rules = Some(compiler.compile_rules()?);
        info!("YARA rules loaded successfully");

        Ok(())
    }

    /// Simplified load_rules for non-YARA builds
    #[cfg(not(feature = "yara-integration"))]
    pub fn load_rules(&mut self) -> Result<()> {
        debug!("YARA support not compiled in");
        Ok(())
    }

    /// Scan a file with YARA rules
    #[cfg(feature = "yara-integration")]
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<DetectionResult>> {
        let path = path.as_ref();
        let rules = self
            .rules
            .as_ref()
            .ok_or_else(|| Error::detection("YARA rules not loaded"))?;

        let matches = rules
            .scan_file(path, 60) // 60 second timeout
            .map_err(|e| Error::detection(format!("YARA scan failed: {}", e)))?;

        let mut results = Vec::new();

        for rule in matches {
            let severity = self.severity_from_metadata(&rule);
            let confidence = 0.9; // YARA matches are high confidence

            results.push(DetectionResult {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                severity,
                detection_type: DetectionType::Yara,
                target: path.to_string_lossy().to_string(),
                details: format!("YARA rule matched: {}", rule.identifier),
                confidence,
                recommended_action: if severity == DetectionSeverity::Critical {
                    ResponseAction::Quarantine
                } else {
                    ResponseAction::Alert
                },
                metadata: serde_json::json!({
                    "rule": rule.identifier,
                    "namespace": rule.namespace,
                }),
            });
        }

        Ok(results)
    }

    /// Simplified scan_file for non-YARA builds
    #[cfg(not(feature = "yara-integration"))]
    pub fn scan_file<P: AsRef<Path>>(&self, _path: P) -> Result<Vec<DetectionResult>> {
        Ok(Vec::new())
    }

    /// Scan memory with YARA rules
    #[cfg(feature = "yara-integration")]
    pub fn scan_memory(&self, data: &[u8], context: &str) -> Result<Vec<DetectionResult>> {
        let rules = self
            .rules
            .as_ref()
            .ok_or_else(|| Error::detection("YARA rules not loaded"))?;

        let matches = rules
            .scan_mem(data, 60)
            .map_err(|e| Error::detection(format!("YARA scan failed: {}", e)))?;

        let mut results = Vec::new();

        for rule in matches {
            let severity = self.severity_from_metadata(&rule);
            let confidence = 0.9;

            results.push(DetectionResult {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                severity,
                detection_type: DetectionType::Yara,
                target: context.to_string(),
                details: format!("YARA rule matched in memory: {}", rule.identifier),
                confidence,
                recommended_action: if severity == DetectionSeverity::Critical {
                    ResponseAction::Kill
                } else {
                    ResponseAction::Alert
                },
                metadata: serde_json::json!({
                    "rule": rule.identifier,
                    "namespace": rule.namespace,
                    "context": context,
                }),
            });
        }

        Ok(results)
    }

    /// Simplified scan_memory for non-YARA builds
    #[cfg(not(feature = "yara-integration"))]
    pub fn scan_memory(&self, _data: &[u8], _context: &str) -> Result<Vec<DetectionResult>> {
        Ok(Vec::new())
    }

    /// Determine severity from YARA rule metadata
    #[cfg(feature = "yara-integration")]
    fn severity_from_metadata(&self, _rule: &yara::Rule) -> DetectionSeverity {
        // In production, parse metadata like:
        // meta:
        //   severity = "critical"
        DetectionSeverity::High
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yara_engine_creation() {
        let config = crate::config::AgentConfig::default();
        let engine = YaraEngine::new(&config);
        assert!(engine.is_ok());
    }
}
