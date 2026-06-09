//! File quarantine management

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Quarantine entry metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique quarantine ID
    pub id: String,

    /// Original file path
    pub original_path: String,

    /// Quarantine timestamp
    pub quarantined_at: u64,

    /// File SHA256
    pub sha256: String,

    /// File size
    pub size: u64,

    /// Reason for quarantine
    pub reason: String,
}

/// Quarantine manager
pub struct QuarantineManager {
    /// Quarantine directory
    quarantine_dir: PathBuf,
}

impl QuarantineManager {
    /// Create a new quarantine manager
    pub fn new<P: AsRef<Path>>(quarantine_dir: P) -> Result<Self> {
        let quarantine_dir = quarantine_dir.as_ref().to_path_buf();

        // Create quarantine directory if it doesn't exist
        if !quarantine_dir.exists() {
            fs::create_dir_all(&quarantine_dir)?;
            info!("Created quarantine directory: {:?}", quarantine_dir);
        }

        Ok(Self { quarantine_dir })
    }

    /// Quarantine a file
    pub fn quarantine_file<P: AsRef<Path>>(&self, path: P) -> Result<QuarantineEntry> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(Error::not_found(format!("File not found: {:?}", path)));
        }

        // Read file data
        let data = fs::read(path)?;

        // Calculate SHA256
        let sha256 = crate::platform::calculate_sha256(&data);

        // Generate quarantine ID
        let id = uuid::Uuid::new_v4().to_string();

        // Create quarantine entry
        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.to_string_lossy().to_string(),
            quarantined_at: chrono::Utc::now().timestamp_millis() as u64,
            sha256: sha256.clone(),
            size: data.len() as u64,
            reason: "Detected as malicious".to_string(),
        };

        // Save file to quarantine
        let quarantine_file_path = self.quarantine_dir.join(&id);
        fs::write(&quarantine_file_path, &data)?;

        // Save metadata
        let metadata_path = self.quarantine_dir.join(format!("{}.json", id));
        let metadata_json = serde_json::to_string_pretty(&entry)?;
        fs::write(metadata_path, metadata_json)?;

        // Delete original file
        fs::remove_file(path)?;

        info!("Quarantined file: {:?} -> {}", path, id);

        Ok(entry)
    }

    /// Restore a quarantined file
    pub fn restore_file(&self, quarantine_id: &str) -> Result<()> {
        // Load metadata
        let metadata_path = self.quarantine_dir.join(format!("{}.json", quarantine_id));
        if !metadata_path.exists() {
            return Err(Error::not_found(format!(
                "Quarantine entry not found: {}",
                quarantine_id
            )));
        }

        let metadata_json = fs::read_to_string(&metadata_path)?;
        let entry: QuarantineEntry = serde_json::from_str(&metadata_json)?;

        // Load quarantined file
        let quarantine_file_path = self.quarantine_dir.join(quarantine_id);
        let data = fs::read(&quarantine_file_path)?;

        // Verify SHA256
        let sha256 = crate::platform::calculate_sha256(&data);
        if sha256 != entry.sha256 {
            return Err(Error::internal(format!(
                "SHA256 mismatch for quarantine entry: {}",
                quarantine_id
            )));
        }

        // Restore to original location
        let original_path = Path::new(&entry.original_path);
        if let Some(parent) = original_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(original_path, &data)?;

        // Delete quarantine files
        fs::remove_file(&quarantine_file_path)?;
        fs::remove_file(&metadata_path)?;

        info!("Restored file: {} -> {:?}", quarantine_id, original_path);

        Ok(())
    }

    /// List all quarantined files
    pub fn list_quarantined(&self) -> Result<Vec<QuarantineEntry>> {
        let mut entries = Vec::new();

        for entry in fs::read_dir(&self.quarantine_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let metadata_json = fs::read_to_string(&path)?;
                if let Ok(entry) = serde_json::from_str::<QuarantineEntry>(&metadata_json) {
                    entries.push(entry);
                }
            }
        }

        Ok(entries)
    }

    /// Delete a quarantined file permanently
    pub fn delete_quarantined(&self, quarantine_id: &str) -> Result<()> {
        let quarantine_file_path = self.quarantine_dir.join(quarantine_id);
        let metadata_path = self.quarantine_dir.join(format!("{}.json", quarantine_id));

        if quarantine_file_path.exists() {
            fs::remove_file(&quarantine_file_path)?;
        }

        if metadata_path.exists() {
            fs::remove_file(&metadata_path)?;
        }

        info!("Deleted quarantined file: {}", quarantine_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_quarantine_and_restore() {
        let temp_dir = TempDir::new().unwrap();
        let quarantine_dir = temp_dir.path().join("quarantine");
        let manager = QuarantineManager::new(&quarantine_dir).unwrap();

        // Create test file
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"test data").unwrap();

        // Quarantine
        let entry = manager.quarantine_file(&test_file).unwrap();
        assert!(!test_file.exists());
        assert_eq!(entry.size, 9);

        // Restore
        manager.restore_file(&entry.id).unwrap();
        assert!(test_file.exists());
        assert_eq!(fs::read(&test_file).unwrap(), b"test data");
    }
}
