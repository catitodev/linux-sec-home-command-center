// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Reference hash file management for integrity verification.
//!
//! Manages the immutable hash file that stores SHA256 reference hashes for
//! Command Center binaries and configuration files. The file format follows
//! the standard checksum format: `<sha256_hex>  <file_path>` (one entry per line).
//!
//! After writing, the file is made immutable via `chattr +i` to prevent
//! unauthorized modification.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;

use shared::errors::{CommandCenterError, Result};
use tracing::{info, warn};

/// Default path for the reference hash file.
pub const DEFAULT_REFERENCE_HASHES_PATH: &str =
    "/etc/security-command-center/integrity.sha256";

/// Stores reference SHA256 hashes for binaries and configuration files.
///
/// File format (one entry per line):
/// ```text
/// a1b2c3d4e5f6...  /usr/local/bin/scc-backend-api
/// e5f6g7h8i9j0...  /usr/local/bin/scc-privileged-daemon
/// k1l2m3n4o5p6...  /etc/security-command-center/whitelist.toml
/// ```
#[derive(Debug, Clone)]
pub struct ReferenceHashes {
    /// Map of file path → SHA256 hex digest.
    hashes: HashMap<String, String>,
}

impl ReferenceHashes {
    /// Create a new empty `ReferenceHashes`.
    pub fn new() -> Self {
        Self {
            hashes: HashMap::new(),
        }
    }

    /// Create `ReferenceHashes` from an existing map.
    pub fn from_map(hashes: HashMap<String, String>) -> Self {
        Self { hashes }
    }

    /// Load reference hashes from a file.
    ///
    /// Parses the file expecting the format: `<sha256_hex>  <file_path>`
    /// (two spaces between hash and path, matching sha256sum output format).
    ///
    /// # Errors
    ///
    /// Returns `CommandCenterError::IntegrityFailed` if the file cannot be read
    /// or contains malformed entries.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let file = fs::File::open(path).map_err(|e| {
            CommandCenterError::IntegrityFailed(format!(
                "cannot open reference hash file '{}': {}",
                path.display(),
                e
            ))
        })?;

        let reader = BufReader::new(file);
        let mut hashes = HashMap::new();

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result.map_err(|e| {
                CommandCenterError::IntegrityFailed(format!(
                    "error reading line {} of '{}': {}",
                    line_num + 1,
                    path.display(),
                    e
                ))
            })?;

            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Expected format: "<sha256_hex>  <file_path>" (two spaces)
            let parts: Vec<&str> = line.splitn(2, "  ").collect();
            if parts.len() != 2 {
                return Err(CommandCenterError::IntegrityFailed(format!(
                    "malformed entry at line {} of '{}': expected '<hash>  <path>'",
                    line_num + 1,
                    path.display()
                )));
            }

            let hash = parts[0].trim().to_string();
            let file_path = parts[1].trim().to_string();

            // Validate hash is a valid hex string of 64 characters (SHA256)
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(CommandCenterError::IntegrityFailed(format!(
                    "invalid SHA256 hash at line {} of '{}': '{}'",
                    line_num + 1,
                    path.display(),
                    hash
                )));
            }

            hashes.insert(file_path, hash);
        }

        info!(
            path = %path.display(),
            entries = hashes.len(),
            "loaded reference hashes"
        );

        Ok(Self { hashes })
    }

    /// Save reference hashes to a file and set it immutable.
    ///
    /// Writes the hash file in the standard format, then attempts to set
    /// the immutable attribute via `chattr +i`. The file must be owned by root.
    ///
    /// # Errors
    ///
    /// Returns `CommandCenterError::IntegrityFailed` if the file cannot be written.
    /// Logs a warning (but does not fail) if `chattr +i` cannot be applied.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                CommandCenterError::IntegrityFailed(format!(
                    "cannot create directory '{}': {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        // Remove immutable attribute if file already exists (needed to overwrite)
        if path.exists() {
            Self::remove_immutable(path);
        }

        // Write the hash file
        let mut file = fs::File::create(path).map_err(|e| {
            CommandCenterError::IntegrityFailed(format!(
                "cannot create hash file '{}': {}",
                path.display(),
                e
            ))
        })?;

        writeln!(file, "# Security Command Center — Reference Integrity Hashes")
            .map_err(|e| {
                CommandCenterError::IntegrityFailed(format!(
                    "cannot write to hash file '{}': {}",
                    path.display(),
                    e
                ))
            })?;
        writeln!(file, "# Format: <sha256>  <file_path>").map_err(|e| {
            CommandCenterError::IntegrityFailed(format!(
                "cannot write to hash file '{}': {}",
                path.display(),
                e
            ))
        })?;
        writeln!(file, "# DO NOT EDIT — this file is protected with chattr +i")
            .map_err(|e| {
                CommandCenterError::IntegrityFailed(format!(
                    "cannot write to hash file '{}': {}",
                    path.display(),
                    e
                ))
            })?;
        writeln!(file).map_err(|e| {
            CommandCenterError::IntegrityFailed(format!(
                "cannot write to hash file '{}': {}",
                path.display(),
                e
            ))
        })?;

        // Sort entries for deterministic output
        let mut entries: Vec<(&String, &String)> = self.hashes.iter().collect();
        entries.sort_by_key(|(path, _)| path.as_str());

        for (file_path, hash) in entries {
            writeln!(file, "{}  {}", hash, file_path).map_err(|e| {
                CommandCenterError::IntegrityFailed(format!(
                    "cannot write entry to hash file '{}': {}",
                    path.display(),
                    e
                ))
            })?;
        }

        // Set restrictive permissions (root read-only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o400);
            fs::set_permissions(path, perms).map_err(|e| {
                CommandCenterError::IntegrityFailed(format!(
                    "cannot set permissions on '{}': {}",
                    path.display(),
                    e
                ))
            })?;
        }

        // Set immutable attribute
        Self::set_immutable(path);

        info!(
            path = %path.display(),
            entries = self.hashes.len(),
            "saved reference hashes (immutable)"
        );

        Ok(())
    }

    /// Get the expected hash for a given file path.
    pub fn get_hash(&self, file_path: &str) -> Option<&str> {
        self.hashes.get(file_path).map(|s| s.as_str())
    }

    /// Insert or update a hash entry.
    pub fn set_hash(&mut self, file_path: String, hash: String) {
        self.hashes.insert(file_path, hash);
    }

    /// Remove a hash entry.
    pub fn remove_hash(&mut self, file_path: &str) -> Option<String> {
        self.hashes.remove(file_path)
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Returns true if there are no entries.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Returns an iterator over all (path, hash) entries.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.hashes.iter()
    }

    /// Set the immutable attribute on a file using `chattr +i`.
    fn set_immutable(path: &Path) {
        match Command::new("chattr").arg("+i").arg(path).output() {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!(
                        path = %path.display(),
                        stderr = %stderr.trim(),
                        "failed to set immutable attribute (chattr +i) — \
                         file may be modifiable"
                    );
                }
            }
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "chattr command not available — cannot set immutable attribute"
                );
            }
        }
    }

    /// Remove the immutable attribute from a file using `chattr -i`.
    fn remove_immutable(path: &Path) {
        match Command::new("chattr").arg("-i").arg(path).output() {
            Ok(output) => {
                if !output.status.success() {
                    // This is expected if the file wasn't immutable
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::debug!(
                        path = %path.display(),
                        stderr = %stderr.trim(),
                        "could not remove immutable attribute (may not have been set)"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %e,
                    "chattr command not available"
                );
            }
        }
    }
}

impl Default for ReferenceHashes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_valid_hash_file() {
        let tmp_dir = std::env::temp_dir().join("scc_test_hashes_load");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let hash_file = tmp_dir.join("integrity.sha256");
        let mut f = fs::File::create(&hash_file).unwrap();
        writeln!(
            f,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  /usr/local/bin/scc-backend-api"
        )
        .unwrap();
        writeln!(
            f,
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef  /etc/security-command-center/whitelist.toml"
        )
        .unwrap();

        let hashes = ReferenceHashes::load_from_file(&hash_file).unwrap();
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes.get_hash("/usr/local/bin/scc-backend-api"),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
        assert_eq!(
            hashes.get_hash("/etc/security-command-center/whitelist.toml"),
            Some("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        );

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_load_with_comments_and_empty_lines() {
        let tmp_dir = std::env::temp_dir().join("scc_test_hashes_comments");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let hash_file = tmp_dir.join("integrity.sha256");
        let mut f = fs::File::create(&hash_file).unwrap();
        writeln!(f, "# This is a comment").unwrap();
        writeln!(f).unwrap();
        writeln!(
            f,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  /usr/bin/test"
        )
        .unwrap();
        writeln!(f, "# Another comment").unwrap();

        let hashes = ReferenceHashes::load_from_file(&hash_file).unwrap();
        assert_eq!(hashes.len(), 1);

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_load_invalid_hash_length() {
        let tmp_dir = std::env::temp_dir().join("scc_test_hashes_invalid");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let hash_file = tmp_dir.join("integrity.sha256");
        let mut f = fs::File::create(&hash_file).unwrap();
        writeln!(f, "tooshort  /usr/bin/test").unwrap();

        let result = ReferenceHashes::load_from_file(&hash_file);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_save_and_reload() {
        let tmp_dir = std::env::temp_dir().join("scc_test_hashes_save");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let hash_file = tmp_dir.join("integrity.sha256");

        let mut hashes = ReferenceHashes::new();
        hashes.set_hash(
            "/usr/local/bin/scc-backend-api".to_string(),
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        );
        hashes.set_hash(
            "/usr/local/bin/scc-privileged-daemon".to_string(),
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        );

        hashes.save_to_file(&hash_file).unwrap();

        // Reload and verify
        let loaded = ReferenceHashes::load_from_file(&hash_file).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded.get_hash("/usr/local/bin/scc-backend-api"),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_set_and_remove_hash() {
        let mut hashes = ReferenceHashes::new();
        assert!(hashes.is_empty());

        hashes.set_hash("/bin/test".to_string(), "a".repeat(64));
        assert_eq!(hashes.len(), 1);
        assert!(hashes.get_hash("/bin/test").is_some());

        let removed = hashes.remove_hash("/bin/test");
        assert!(removed.is_some());
        assert!(hashes.is_empty());
    }
}
