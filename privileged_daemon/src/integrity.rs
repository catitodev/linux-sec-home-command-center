// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Self-integrity verification for the Linux Security Home Command Center.
//!
//! At startup, the Privileged Daemon verifies the SHA256 hashes of Command Center
//! binaries and configuration files against reference hashes stored in a
//! root-owned immutable file. If any binary fails verification, the daemon
//! refuses to start the Backend_API and emits a tamper alert via libnotify.
//!
//! The verification process has a 30-second timeout to prevent hanging at startup.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use shared::errors::{CommandCenterError, Result};
use tokio::time::timeout;
use tracing::{error, info, warn};

use crate::integrity_hashes::ReferenceHashes;

/// Default timeout for integrity verification (30 seconds).
const DEFAULT_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Default path for the tamper evidence log.
const TAMPER_LOG_PATH: &str = "/var/log/security-command-center/tamper.log";

/// Result of an integrity verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityResult {
    /// All binaries and configs passed verification.
    Valid,
    /// A binary file has been tampered with.
    BinaryTampered {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    /// A configuration file has been tampered with.
    ConfigTampered { path: PathBuf },
    /// Verification timed out (exceeded 30 seconds).
    Timeout,
}

/// Performs self-integrity verification of Command Center binaries and configs.
///
/// Computes SHA256 hashes of binaries and compares them against reference hashes
/// stored in a root-owned immutable file. Verification must complete within the
/// configured timeout (default: 30 seconds).
pub struct IntegrityVerifier {
    /// Path to the immutable reference hash file.
    reference_hashes_path: PathBuf,
    /// Path to the AIDE database (for cross-reference).
    aide_db_path: PathBuf,
    /// Maximum time allowed for verification.
    timeout_duration: Duration,
    /// Loaded reference hashes (populated on first use).
    reference_hashes: Option<ReferenceHashes>,
}

impl IntegrityVerifier {
    /// Create a new `IntegrityVerifier` from daemon configuration.
    pub fn new(
        reference_hashes_path: PathBuf,
        aide_db_path: PathBuf,
    ) -> Self {
        Self {
            reference_hashes_path,
            aide_db_path,
            timeout_duration: DEFAULT_VERIFICATION_TIMEOUT,
            reference_hashes: None,
        }
    }

    /// Create a new `IntegrityVerifier` with a custom timeout.
    pub fn with_timeout(
        reference_hashes_path: PathBuf,
        aide_db_path: PathBuf,
        timeout_duration: Duration,
    ) -> Self {
        Self {
            reference_hashes_path,
            aide_db_path,
            timeout_duration,
            reference_hashes: None,
        }
    }

    /// Load reference hashes from the immutable file.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference hash file cannot be read or parsed.
    fn load_reference_hashes(&mut self) -> Result<&ReferenceHashes> {
        if self.reference_hashes.is_none() {
            let hashes =
                ReferenceHashes::load_from_file(&self.reference_hashes_path)?;
            self.reference_hashes = Some(hashes);
        }
        Ok(self.reference_hashes.as_ref().unwrap())
    }

    /// Verify all Command Center binaries against stored reference hashes.
    ///
    /// Computes SHA256 of each binary listed in the reference hash file and
    /// compares against the stored expected value. The entire verification
    /// must complete within the configured timeout (default: 30 seconds).
    ///
    /// # Returns
    ///
    /// - `Ok(IntegrityResult::Valid)` if all binaries match their expected hashes
    /// - `Ok(IntegrityResult::BinaryTampered { .. })` if a binary hash mismatch is found
    /// - `Ok(IntegrityResult::Timeout)` if verification exceeds the timeout
    /// - `Err(..)` if the reference hash file cannot be loaded or a binary cannot be read
    pub async fn verify_binaries(&mut self) -> Result<IntegrityResult> {
        info!("starting binary integrity verification");

        let result = timeout(self.timeout_duration, self.do_verify_binaries()).await;

        match result {
            Ok(inner_result) => inner_result,
            Err(_elapsed) => {
                error!(
                    timeout_secs = self.timeout_duration.as_secs(),
                    "integrity verification timed out"
                );
                Ok(IntegrityResult::Timeout)
            }
        }
    }

    /// Internal binary verification logic (runs within timeout).
    async fn do_verify_binaries(&mut self) -> Result<IntegrityResult> {
        self.load_reference_hashes()?;

        let hashes = self.reference_hashes.as_ref().unwrap();

        for (file_path, expected_hash) in hashes.iter() {
            let path = Path::new(file_path);

            // Skip non-binary paths (config files are verified separately)
            if !Self::is_binary_path(file_path) {
                continue;
            }

            if !path.exists() {
                error!(
                    path = %file_path,
                    "binary not found during integrity verification"
                );
                return Err(CommandCenterError::IntegrityFailed(format!(
                    "binary not found: {}",
                    file_path
                )));
            }

            let actual_hash = compute_sha256(path)?;

            if actual_hash != *expected_hash {
                error!(
                    path = %file_path,
                    expected = %expected_hash,
                    actual = %actual_hash,
                    "BINARY INTEGRITY FAILURE — possible tampering detected"
                );
                return Ok(IntegrityResult::BinaryTampered {
                    path: path.to_path_buf(),
                    expected: expected_hash.clone(),
                    actual: actual_hash,
                });
            }

            info!(path = %file_path, "binary integrity verified");
        }

        info!("all binary integrity checks passed");
        Ok(IntegrityResult::Valid)
    }

    /// Verify a configuration file's hash against the reference.
    ///
    /// # Errors
    ///
    /// Returns `CommandCenterError::IntegrityFailed` if the config file hash
    /// does not match the stored reference, or if the file cannot be read.
    pub fn verify_config_file(&mut self, path: &Path) -> Result<()> {
        self.load_reference_hashes()?;

        let hashes = self.reference_hashes.as_ref().unwrap();
        let path_str = path.to_string_lossy().to_string();

        let expected_hash = match hashes.get_hash(&path_str) {
            Some(h) => h.to_string(),
            None => {
                warn!(
                    path = %path.display(),
                    "no reference hash found for config file — skipping verification"
                );
                return Ok(());
            }
        };

        if !path.exists() {
            return Err(CommandCenterError::IntegrityFailed(format!(
                "configuration file not found: {}",
                path.display()
            )));
        }

        let actual_hash = compute_sha256(path)?;

        if actual_hash != expected_hash {
            error!(
                path = %path.display(),
                expected = %expected_hash,
                actual = %actual_hash,
                "CONFIG INTEGRITY FAILURE — configuration file tampered"
            );
            return Err(CommandCenterError::IntegrityFailed(format!(
                "configuration file integrity check failed for '{}': \
                 expected hash '{}', got '{}'",
                path.display(),
                expected_hash,
                actual_hash
            )));
        }

        info!(path = %path.display(), "config file integrity verified");
        Ok(())
    }

    /// Determine if a path is a binary (vs. a config file).
    fn is_binary_path(path: &str) -> bool {
        path.contains("/bin/") || path.contains("/sbin/") || path.contains("/libexec/")
    }

    /// Returns the configured timeout duration.
    pub fn timeout_duration(&self) -> Duration {
        self.timeout_duration
    }

    /// Returns the reference hashes path.
    pub fn reference_hashes_path(&self) -> &Path {
        &self.reference_hashes_path
    }

    /// Returns the AIDE database path.
    pub fn aide_db_path(&self) -> &Path {
        &self.aide_db_path
    }
}

/// Compute the SHA256 hex digest of a file.
///
/// Reads the file in chunks to handle large binaries efficiently.
///
/// # Errors
///
/// Returns `CommandCenterError::IntegrityFailed` if the file cannot be read.
pub fn compute_sha256(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|e| {
        CommandCenterError::IntegrityFailed(format!(
            "cannot open file '{}' for hashing: {}",
            path.display(),
            e
        ))
    })?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer).map_err(|e| {
            CommandCenterError::IntegrityFailed(format!(
                "error reading file '{}': {}",
                path.display(),
                e
            ))
        })?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

/// Emit a tamper alert via desktop notification and logging.
///
/// Sends a critical desktop notification using `notify-send` (libnotify),
/// logs the event to journald, and writes to the tamper evidence log file.
pub fn emit_tamper_alert(details: &str) {
    // Log critical event to journald
    error!(
        operation_type = "integrity_tamper_alert",
        user = "system",
        target_resource = "command_center_binaries",
        result = "failure",
        details = %details,
        "CRITICAL: Integrity verification failed — possible binary tampering"
    );

    // Send desktop notification via notify-rust (libnotify)
    send_desktop_notification(details);

    // Write to tamper evidence log
    write_tamper_log(details);
}

/// Send a desktop notification about the tamper alert.
fn send_desktop_notification(details: &str) {
    let summary = "⚠️ SECURITY ALERT: Binary Tampering Detected";
    let body = format!(
        "Command Center integrity verification failed.\n\n{}",
        details
    );

    // Try notify-rust first
    match notify_rust::Notification::new()
        .summary(summary)
        .body(&body)
        .urgency(notify_rust::Urgency::Critical)
        .timeout(notify_rust::Timeout::Never)
        .show()
    {
        Ok(_) => {
            info!("tamper alert desktop notification sent via notify-rust");
        }
        Err(e) => {
            warn!(
                error = %e,
                "notify-rust failed, falling back to notify-send command"
            );
            // Fallback: shell out to notify-send
            send_notification_fallback(summary, &body);
        }
    }
}

/// Fallback notification via `notify-send` command.
fn send_notification_fallback(summary: &str, body: &str) {
    match std::process::Command::new("notify-send")
        .arg("--urgency=critical")
        .arg("--app-name=Security Command Center")
        .arg(summary)
        .arg(body)
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                info!("tamper alert sent via notify-send");
            } else {
                warn!(
                    "notify-send failed with status {}",
                    output.status
                );
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                "notify-send command not available — desktop notification not sent"
            );
        }
    }
}

/// Write tamper details to the tamper evidence log file.
fn write_tamper_log(details: &str) {
    let log_path = Path::new(TAMPER_LOG_PATH);

    // Ensure parent directory exists
    if let Some(parent) = log_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            warn!(
                error = %e,
                path = %parent.display(),
                "cannot create tamper log directory"
            );
            return;
        }
    }

    let timestamp = chrono::Utc::now().to_rfc3339();
    let entry = format!("[{}] TAMPER ALERT: {}\n", timestamp, details);

    match fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        Ok(mut file) => {
            use std::io::Write;
            if let Err(e) = file.write_all(entry.as_bytes()) {
                warn!(
                    error = %e,
                    "failed to write to tamper log"
                );
            } else {
                info!(path = %log_path.display(), "tamper event recorded");
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                path = %log_path.display(),
                "cannot open tamper log file"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_compute_sha256_known_value() {
        let tmp_dir = std::env::temp_dir().join("scc_test_sha256");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let test_file = tmp_dir.join("test.bin");
        {
            let mut f = fs::File::create(&test_file).unwrap();
            f.write_all(b"hello world").unwrap();
        }

        let hash = compute_sha256(&test_file).unwrap();
        // SHA256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_compute_sha256_empty_file() {
        let tmp_dir = std::env::temp_dir().join("scc_test_sha256_empty");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let test_file = tmp_dir.join("empty.bin");
        fs::File::create(&test_file).unwrap();

        let hash = compute_sha256(&test_file).unwrap();
        // SHA256 of empty input
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_compute_sha256_nonexistent_file() {
        let result = compute_sha256(Path::new("/nonexistent/file.bin"));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_binaries_valid() {
        let tmp_dir = std::env::temp_dir().join("scc_test_verify_valid");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        // Create a fake binary
        let bin_path = tmp_dir.join("bin").join("scc-backend-api");
        fs::create_dir_all(bin_path.parent().unwrap()).unwrap();
        {
            let mut f = fs::File::create(&bin_path).unwrap();
            f.write_all(b"fake binary content").unwrap();
        }

        // Compute its hash
        let hash = compute_sha256(&bin_path).unwrap();

        // Create reference hash file
        let hash_file = tmp_dir.join("integrity.sha256");
        {
            let mut f = fs::File::create(&hash_file).unwrap();
            writeln!(f, "{}  {}", hash, bin_path.display()).unwrap();
        }

        let mut verifier = IntegrityVerifier::new(
            hash_file,
            PathBuf::from("/var/lib/aide/aide.db"),
        );

        let result = verifier.verify_binaries().await.unwrap();
        assert_eq!(result, IntegrityResult::Valid);

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn test_verify_binaries_tampered() {
        let tmp_dir = std::env::temp_dir().join("scc_test_verify_tampered");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        // Create a fake binary
        let bin_path = tmp_dir.join("bin").join("scc-backend-api");
        fs::create_dir_all(bin_path.parent().unwrap()).unwrap();
        {
            let mut f = fs::File::create(&bin_path).unwrap();
            f.write_all(b"original content").unwrap();
        }

        // Store a different hash (simulating the binary was modified after hash was stored)
        let hash_file = tmp_dir.join("integrity.sha256");
        {
            let mut f = fs::File::create(&hash_file).unwrap();
            writeln!(
                f,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  {}",
                bin_path.display()
            )
            .unwrap();
        }

        let mut verifier = IntegrityVerifier::new(
            hash_file,
            PathBuf::from("/var/lib/aide/aide.db"),
        );

        let result = verifier.verify_binaries().await.unwrap();
        match result {
            IntegrityResult::BinaryTampered { path, expected, actual } => {
                assert_eq!(path, bin_path);
                assert_eq!(expected, "a".repeat(64));
                assert_ne!(actual, expected);
            }
            other => panic!("expected BinaryTampered, got {:?}", other),
        }

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_verify_config_file_valid() {
        let tmp_dir = std::env::temp_dir().join("scc_test_verify_config");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        // Create a config file
        let config_path = tmp_dir.join("whitelist.toml");
        {
            let mut f = fs::File::create(&config_path).unwrap();
            f.write_all(b"[operations]\nname = \"test\"").unwrap();
        }

        // Compute its hash
        let hash = compute_sha256(&config_path).unwrap();

        // Create reference hash file
        let hash_file = tmp_dir.join("integrity.sha256");
        {
            let mut f = fs::File::create(&hash_file).unwrap();
            writeln!(f, "{}  {}", hash, config_path.display()).unwrap();
        }

        let mut verifier = IntegrityVerifier::new(
            hash_file,
            PathBuf::from("/var/lib/aide/aide.db"),
        );

        let result = verifier.verify_config_file(&config_path);
        assert!(result.is_ok());

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_verify_config_file_tampered() {
        let tmp_dir = std::env::temp_dir().join("scc_test_verify_config_bad");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        // Create a config file
        let config_path = tmp_dir.join("whitelist.toml");
        {
            let mut f = fs::File::create(&config_path).unwrap();
            f.write_all(b"modified content").unwrap();
        }

        // Store a wrong hash
        let hash_file = tmp_dir.join("integrity.sha256");
        {
            let mut f = fs::File::create(&hash_file).unwrap();
            writeln!(
                f,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  {}",
                config_path.display()
            )
            .unwrap();
        }

        let mut verifier = IntegrityVerifier::new(
            hash_file,
            PathBuf::from("/var/lib/aide/aide.db"),
        );

        let result = verifier.verify_config_file(&config_path);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_is_binary_path() {
        assert!(IntegrityVerifier::is_binary_path("/usr/local/bin/scc-backend-api"));
        assert!(IntegrityVerifier::is_binary_path("/usr/sbin/something"));
        assert!(IntegrityVerifier::is_binary_path("/usr/libexec/helper"));
        assert!(!IntegrityVerifier::is_binary_path("/etc/security-command-center/whitelist.toml"));
        assert!(!IntegrityVerifier::is_binary_path("/var/lib/config.toml"));
    }
}
