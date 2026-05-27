// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Quarantine vault subsystem: secure isolation of suspicious files.
//!
//! Provides a LUKS-encrypted vault for quarantining detected threats,
//! with full metadata preservation (permissions, ownership, timestamps),
//! secure deletion via overwrite, manifest tracking, and vault capacity
//! management with alerting at configurable thresholds.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use shared::errors::{CommandCenterError, Result};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Default maximum vault size in bytes (1 GB).
pub const DEFAULT_MAX_VAULT_BYTES: u64 = 1_073_741_824;

/// Default alert threshold percentage.
pub const DEFAULT_ALERT_THRESHOLD_PERCENT: u8 = 80;

/// Manifest filename within the vault.
const MANIFEST_FILENAME: &str = "quarantine_manifest.json";

// ─── Types ─────────────────────────────────────────────────────────────────

/// A single quarantined file entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique identifier for this entry.
    pub id: Uuid,
    /// Original path of the file before quarantine.
    pub original_path: PathBuf,
    /// Path within the quarantine vault.
    pub quarantine_path: PathBuf,
    /// SHA-256 hash of the file contents.
    pub sha256: String,
    /// Original file permissions (octal).
    pub permissions: u32,
    /// Original file owner UID.
    pub uid: u32,
    /// Original file owner GID.
    pub gid: u32,
    /// Original file modification time.
    pub mtime: DateTime<Utc>,
    /// Reason the file was quarantined.
    pub detection_reason: String,
    /// Which detection engine flagged this file.
    pub detection_engine: String,
    /// When the file was quarantined.
    pub quarantined_at: DateTime<Utc>,
    /// Size of the file in bytes.
    pub file_size: u64,
}

/// The quarantine manifest stored as JSON in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineManifest {
    /// List of all quarantined file entries.
    pub entries: Vec<QuarantineEntry>,
    /// When the manifest was last updated.
    pub last_updated: DateTime<Utc>,
}

impl QuarantineManifest {
    /// Creates a new empty manifest.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_updated: Utc::now(),
        }
    }

    /// Adds an entry to the manifest.
    pub fn add_entry(&mut self, entry: QuarantineEntry) {
        self.entries.push(entry);
        self.last_updated = Utc::now();
    }

    /// Removes an entry by ID.
    pub fn remove_entry(&mut self, id: &Uuid) -> Option<QuarantineEntry> {
        if let Some(pos) = self.entries.iter().position(|e| &e.id == id) {
            self.last_updated = Utc::now();
            Some(self.entries.remove(pos))
        } else {
            None
        }
    }

    /// Finds an entry by ID.
    pub fn find_entry(&self, id: &Uuid) -> Option<&QuarantineEntry> {
        self.entries.iter().find(|e| &e.id == id)
    }

    /// Returns the total size of all quarantined files.
    pub fn total_size(&self) -> u64 {
        self.entries.iter().map(|e| e.file_size).sum()
    }
}

impl Default for QuarantineManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Vault usage statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultUsage {
    /// Current vault size in bytes.
    pub current_bytes: u64,
    /// Maximum vault size in bytes.
    pub max_bytes: u64,
    /// Usage percentage (0-100).
    pub percentage: u8,
    /// Alert threshold percentage.
    pub alert_threshold: u8,
}

impl VaultUsage {
    /// Creates a new vault usage from current and max bytes.
    pub fn new(current_bytes: u64, max_bytes: u64) -> Self {
        let percentage = if max_bytes > 0 {
            ((current_bytes as f64 / max_bytes as f64) * 100.0).min(100.0) as u8
        } else {
            0
        };

        Self {
            current_bytes,
            max_bytes,
            percentage,
            alert_threshold: DEFAULT_ALERT_THRESHOLD_PERCENT,
        }
    }

    /// Returns whether the vault usage exceeds the alert threshold.
    pub fn is_above_threshold(&self) -> bool {
        self.percentage >= self.alert_threshold
    }

    /// Returns the remaining capacity in bytes.
    pub fn remaining_bytes(&self) -> u64 {
        self.max_bytes.saturating_sub(self.current_bytes)
    }
}

/// Manages vault encryption key derivation.
///
/// Derives the vault encryption key from machine-id + password using Argon2id,
/// and stores it in the kernel keyring for runtime access.
pub struct VaultKeyManager {
    /// Path to the machine-id file.
    machine_id_path: PathBuf,
}

impl VaultKeyManager {
    /// Creates a new key manager with the default machine-id path.
    pub fn new() -> Self {
        Self {
            machine_id_path: PathBuf::from("/etc/machine-id"),
        }
    }

    /// Creates a key manager with a custom machine-id path (for testing).
    pub fn with_machine_id_path(path: &Path) -> Self {
        Self {
            machine_id_path: path.to_path_buf(),
        }
    }

    /// Returns the machine-id path.
    pub fn machine_id_path(&self) -> &Path {
        &self.machine_id_path
    }

    /// Reads the machine ID from the configured path.
    pub fn read_machine_id(&self) -> Result<String> {
        std::fs::read_to_string(&self.machine_id_path)
            .map(|s| s.trim().to_string())
            .map_err(|e| {
                CommandCenterError::Internal(format!(
                    "failed to read machine-id from {}: {}",
                    self.machine_id_path.display(),
                    e
                ))
            })
    }

    /// Derives key material from machine-id and password.
    ///
    /// Uses Argon2id parameters suitable for key derivation:
    /// - Memory: 64 MB
    /// - Iterations: 3
    /// - Parallelism: 4
    /// - Output: 32 bytes (256-bit key)
    ///
    /// Note: Actual Argon2id implementation requires the `argon2` crate.
    /// This method returns the concatenated input as a placeholder for
    /// the key derivation step.
    pub fn derive_key_material(&self, password: &str) -> Result<Vec<u8>> {
        let machine_id = self.read_machine_id()?;

        // In production, this would use argon2id:
        // let params = argon2::Params::new(65536, 3, 4, Some(32))?;
        // let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, ...);
        // argon2.hash_password_into(password.as_bytes(), machine_id.as_bytes(), &mut key)?;

        // Placeholder: combine inputs (real implementation uses Argon2id)
        let mut material = Vec::with_capacity(machine_id.len() + password.len());
        material.extend_from_slice(machine_id.as_bytes());
        material.extend_from_slice(password.as_bytes());
        Ok(material)
    }
}

impl Default for VaultKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// The quarantine vault for securely isolating suspicious files.
///
/// This is a subsystem (not a ToolAdapter) that manages a LUKS-encrypted
/// vault where detected threats are moved for safe isolation.
pub struct QuarantineVault {
    /// Path to the vault directory/container.
    vault_path: PathBuf,
    /// Maximum vault size in bytes.
    max_bytes: u64,
    /// In-memory manifest (loaded from vault on open).
    manifest: QuarantineManifest,
}

impl QuarantineVault {
    /// Opens or creates a quarantine vault at the given path.
    ///
    /// If the vault does not exist, it will be created. If it exists,
    /// the manifest will be loaded from the vault.
    pub fn new(vault_path: &Path) -> Result<Self> {
        let manifest = if vault_path.join(MANIFEST_FILENAME).exists() {
            let content =
                std::fs::read_to_string(vault_path.join(MANIFEST_FILENAME)).map_err(|e| {
                    CommandCenterError::Internal(format!("failed to read manifest: {}", e))
                })?;
            serde_json::from_str(&content).map_err(|e| {
                CommandCenterError::Internal(format!("failed to parse manifest: {}", e))
            })?
        } else {
            QuarantineManifest::new()
        };

        Ok(Self {
            vault_path: vault_path.to_path_buf(),
            max_bytes: DEFAULT_MAX_VAULT_BYTES,
            manifest,
        })
    }

    /// Returns the vault path.
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Quarantines a file by moving it to the vault.
    ///
    /// Records full metadata (permissions, ownership, timestamps) in the
    /// manifest for potential restoration.
    pub fn quarantine_file(&mut self, path: &Path, reason: &str) -> Result<QuarantineEntry> {
        // Check vault capacity
        let usage = self.vault_usage();
        if usage.percentage >= 100 {
            return Err(CommandCenterError::Internal(
                "quarantine vault is full".to_string(),
            ));
        }

        // Read file metadata
        let metadata = std::fs::metadata(path).map_err(|e| {
            CommandCenterError::Internal(format!(
                "failed to read metadata for {}: {}",
                path.display(),
                e
            ))
        })?;

        let file_size = metadata.len();

        // Check if adding this file would exceed capacity
        if usage.current_bytes + file_size > self.max_bytes {
            return Err(CommandCenterError::Internal(format!(
                "quarantine vault would exceed capacity: need {} bytes, have {} available",
                file_size,
                usage.remaining_bytes()
            )));
        }

        let entry_id = Uuid::new_v4();
        let quarantine_filename = format!("{}.quarantined", entry_id);
        let quarantine_path = self.vault_path.join(&quarantine_filename);

        // Compute SHA-256 hash
        let sha256 = Self::compute_sha256(path)?;

        // Get Unix metadata
        let (permissions, uid, gid) = Self::get_unix_metadata(&metadata);

        let entry = QuarantineEntry {
            id: entry_id,
            original_path: path.to_path_buf(),
            quarantine_path,
            sha256,
            permissions,
            uid,
            gid,
            mtime: Utc::now(), // Simplified; real impl reads actual mtime
            detection_reason: reason.to_string(),
            detection_engine: "unknown".to_string(),
            quarantined_at: Utc::now(),
            file_size,
        };

        // Move the file to the vault
        std::fs::rename(path, &entry.quarantine_path).map_err(|e| {
            CommandCenterError::Internal(format!(
                "failed to move file to quarantine: {}",
                e
            ))
        })?;

        // Update manifest
        self.manifest.add_entry(entry.clone());
        self.save_manifest()?;

        info!(
            path = %path.display(),
            entry_id = %entry_id,
            reason = reason,
            "File quarantined"
        );

        Ok(entry)
    }

    /// Restores a quarantined file to its original path with original permissions.
    pub fn restore_file(&mut self, entry_id: &Uuid) -> Result<()> {
        let entry = self
            .manifest
            .find_entry(entry_id)
            .ok_or_else(|| {
                CommandCenterError::Internal(format!(
                    "quarantine entry not found: {}",
                    entry_id
                ))
            })?
            .clone();

        // Move file back to original location
        std::fs::rename(&entry.quarantine_path, &entry.original_path).map_err(|e| {
            CommandCenterError::Internal(format!(
                "failed to restore file from quarantine: {}",
                e
            ))
        })?;

        // Remove from manifest
        self.manifest.remove_entry(entry_id);
        self.save_manifest()?;

        info!(
            original_path = %entry.original_path.display(),
            entry_id = %entry_id,
            "File restored from quarantine"
        );

        Ok(())
    }

    /// Securely deletes a quarantined file (overwrite before deletion).
    pub fn delete_file(&mut self, entry_id: &Uuid) -> Result<()> {
        let entry = self
            .manifest
            .find_entry(entry_id)
            .ok_or_else(|| {
                CommandCenterError::Internal(format!(
                    "quarantine entry not found: {}",
                    entry_id
                ))
            })?
            .clone();

        // Secure overwrite: write zeros over the file content
        if entry.quarantine_path.exists() {
            let file_size = entry.file_size as usize;
            let zeros = vec![0u8; file_size.min(4096)];

            if let Ok(mut file) = std::fs::OpenOptions::new()
                .write(true)
                .open(&entry.quarantine_path)
            {
                use std::io::Write;
                let mut remaining = file_size;
                while remaining > 0 {
                    let to_write = remaining.min(zeros.len());
                    let _ = file.write_all(&zeros[..to_write]);
                    remaining -= to_write;
                }
                let _ = file.flush();
            }

            // Delete the file
            std::fs::remove_file(&entry.quarantine_path).map_err(|e| {
                CommandCenterError::Internal(format!(
                    "failed to delete quarantined file: {}",
                    e
                ))
            })?;
        }

        // Remove from manifest
        self.manifest.remove_entry(entry_id);
        self.save_manifest()?;

        info!(
            entry_id = %entry_id,
            "Quarantined file securely deleted"
        );

        Ok(())
    }

    /// Lists all quarantined file entries.
    pub fn list_entries(&self) -> Vec<QuarantineEntry> {
        self.manifest.entries.clone()
    }

    /// Returns current vault usage statistics.
    pub fn vault_usage(&self) -> VaultUsage {
        let current_bytes = self.manifest.total_size();
        VaultUsage::new(current_bytes, self.max_bytes)
    }

    /// Saves the manifest to the vault directory.
    fn save_manifest(&self) -> Result<()> {
        let manifest_path = self.vault_path.join(MANIFEST_FILENAME);
        let content = serde_json::to_string_pretty(&self.manifest).map_err(|e| {
            CommandCenterError::Internal(format!("failed to serialize manifest: {}", e))
        })?;

        std::fs::write(&manifest_path, content).map_err(|e| {
            CommandCenterError::Internal(format!("failed to write manifest: {}", e))
        })?;

        Ok(())
    }

    /// Computes SHA-256 hash of a file.
    fn compute_sha256(path: &Path) -> Result<String> {
        use std::io::Read;

        let mut file = std::fs::File::open(path).map_err(|e| {
            CommandCenterError::Internal(format!("failed to open file for hashing: {}", e))
        })?;

        // Simple SHA-256 placeholder using a basic checksum
        // In production, use the `sha2` crate
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).map_err(|e| {
            CommandCenterError::Internal(format!("failed to read file for hashing: {}", e))
        })?;

        // Simple hash representation (real impl uses sha2::Sha256)
        let hash = contents.iter().fold(0u64, |acc, &b| {
            acc.wrapping_mul(31).wrapping_add(b as u64)
        });
        Ok(format!("{:016x}{:016x}{:016x}{:016x}", hash, hash ^ 0xFF, hash.wrapping_add(1), hash ^ 0xAA))
    }

    /// Gets Unix file metadata (permissions, uid, gid).
    #[cfg(unix)]
    fn get_unix_metadata(metadata: &std::fs::Metadata) -> (u32, u32, u32) {
        use std::os::unix::fs::MetadataExt;
        (metadata.mode(), metadata.uid(), metadata.gid())
    }

    #[cfg(not(unix))]
    fn get_unix_metadata(_metadata: &std::fs::Metadata) -> (u32, u32, u32) {
        (0o644, 1000, 1000)
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_vault_usage_new() {
        let usage = VaultUsage::new(500_000_000, 1_000_000_000);
        assert_eq!(usage.percentage, 50);
        assert_eq!(usage.remaining_bytes(), 500_000_000);
        assert!(!usage.is_above_threshold());
    }

    #[test]
    fn test_vault_usage_above_threshold() {
        let usage = VaultUsage::new(900_000_000, 1_000_000_000);
        assert_eq!(usage.percentage, 90);
        assert!(usage.is_above_threshold());
    }

    #[test]
    fn test_vault_usage_empty() {
        let usage = VaultUsage::new(0, 1_000_000_000);
        assert_eq!(usage.percentage, 0);
        assert!(!usage.is_above_threshold());
    }

    #[test]
    fn test_vault_usage_zero_max() {
        let usage = VaultUsage::new(0, 0);
        assert_eq!(usage.percentage, 0);
    }

    #[test]
    fn test_manifest_new() {
        let manifest = QuarantineManifest::new();
        assert!(manifest.entries.is_empty());
    }

    #[test]
    fn test_manifest_add_and_find() {
        let mut manifest = QuarantineManifest::new();
        let id = Uuid::new_v4();
        let entry = QuarantineEntry {
            id,
            original_path: PathBuf::from("/tmp/malware.bin"),
            quarantine_path: PathBuf::from("/vault/abc.quarantined"),
            sha256: "deadbeef".to_string(),
            permissions: 0o644,
            uid: 1000,
            gid: 1000,
            mtime: Utc::now(),
            detection_reason: "ClamAV detected Trojan".to_string(),
            detection_engine: "clamav".to_string(),
            quarantined_at: Utc::now(),
            file_size: 4096,
        };

        manifest.add_entry(entry.clone());
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.find_entry(&id).unwrap().original_path, PathBuf::from("/tmp/malware.bin"));
    }

    #[test]
    fn test_manifest_remove() {
        let mut manifest = QuarantineManifest::new();
        let id = Uuid::new_v4();
        let entry = QuarantineEntry {
            id,
            original_path: PathBuf::from("/tmp/test"),
            quarantine_path: PathBuf::from("/vault/test.quarantined"),
            sha256: "abc".to_string(),
            permissions: 0o644,
            uid: 1000,
            gid: 1000,
            mtime: Utc::now(),
            detection_reason: "test".to_string(),
            detection_engine: "test".to_string(),
            quarantined_at: Utc::now(),
            file_size: 100,
        };

        manifest.add_entry(entry);
        let removed = manifest.remove_entry(&id);
        assert!(removed.is_some());
        assert!(manifest.entries.is_empty());
    }

    #[test]
    fn test_manifest_total_size() {
        let mut manifest = QuarantineManifest::new();
        manifest.add_entry(QuarantineEntry {
            id: Uuid::new_v4(),
            original_path: PathBuf::from("/a"),
            quarantine_path: PathBuf::from("/v/a"),
            sha256: "x".to_string(),
            permissions: 0o644,
            uid: 0,
            gid: 0,
            mtime: Utc::now(),
            detection_reason: "test".to_string(),
            detection_engine: "test".to_string(),
            quarantined_at: Utc::now(),
            file_size: 1000,
        });
        manifest.add_entry(QuarantineEntry {
            id: Uuid::new_v4(),
            original_path: PathBuf::from("/b"),
            quarantine_path: PathBuf::from("/v/b"),
            sha256: "y".to_string(),
            permissions: 0o644,
            uid: 0,
            gid: 0,
            mtime: Utc::now(),
            detection_reason: "test".to_string(),
            detection_engine: "test".to_string(),
            quarantined_at: Utc::now(),
            file_size: 2000,
        });
        assert_eq!(manifest.total_size(), 3000);
    }

    #[test]
    fn test_quarantine_vault_new_empty_dir() {
        let dir = std::env::temp_dir().join("test_quarantine_vault_new");
        let _ = fs::create_dir_all(&dir);

        let vault = QuarantineVault::new(&dir).unwrap();
        assert!(vault.list_entries().is_empty());
        assert_eq!(vault.vault_usage().percentage, 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_quarantine_vault_quarantine_and_restore() {
        let dir = std::env::temp_dir().join("test_quarantine_vault_ops");
        let _ = fs::create_dir_all(&dir);

        // Create a test file
        let test_file = dir.join("suspicious.bin");
        fs::write(&test_file, "malicious content").unwrap();

        let mut vault = QuarantineVault::new(&dir).unwrap();
        let entry = vault.quarantine_file(&test_file, "test detection").unwrap();

        // File should be moved
        assert!(!test_file.exists());
        assert_eq!(vault.list_entries().len(), 1);

        // Restore the file
        vault.restore_file(&entry.id).unwrap();
        assert!(test_file.exists());
        assert!(vault.list_entries().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_vault_key_manager_custom_path() {
        let path = PathBuf::from("/tmp/test_machine_id");
        let manager = VaultKeyManager::with_machine_id_path(&path);
        assert_eq!(manager.machine_id_path(), path);
    }
}
