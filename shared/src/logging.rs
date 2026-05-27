// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Structured logging for the Linux Security Home Command Center.
//!
//! All operations are logged to journald with the syslog identifier
//! "security-command-center". Each log entry includes timestamp, operation type,
//! initiating user, target resource, and result as structured fields.
//!
//! This module also provides journal integrity monitoring to detect tampering
//! with journal files.

use std::path::PathBuf;
use std::time::Duration;

use tracing::subscriber::set_global_default;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::LoggingConfig;

/// Errors that can occur during logging initialization.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    /// Failed to initialize the journald layer.
    #[error("failed to initialize journald layer: {0}")]
    JournaldInit(String),

    /// Failed to set the global tracing subscriber.
    #[error("failed to set global subscriber: {0}")]
    SetGlobal(String),

    /// Failed to parse the env filter directive.
    #[error("invalid log level filter: {0}")]
    InvalidFilter(String),
}

/// Initialize the logging subsystem.
///
/// Sets up a `tracing` subscriber with:
/// - A journald layer tagged with "security-command-center" (if `config.journald` is true)
/// - An env-filter based on the configured log level
/// - A fallback fmt layer for stderr output when journald is unavailable
///
/// # Errors
///
/// Returns `LoggingError` if the subscriber cannot be initialized.
pub fn init_logging(config: &LoggingConfig) -> Result<(), LoggingError> {
    let env_filter = EnvFilter::try_new(&config.level)
        .map_err(|e| LoggingError::InvalidFilter(e.to_string()))?;

    if config.journald {
        // Attempt to connect to journald
        match tracing_journald::layer() {
            Ok(journald_layer) => {
                let journald_layer =
                    journald_layer.with_syslog_identifier("security-command-center".to_string());

                let subscriber = tracing_subscriber::registry()
                    .with(env_filter)
                    .with(journald_layer);

                set_global_default(subscriber)
                    .map_err(|e| LoggingError::SetGlobal(e.to_string()))?;
            }
            Err(e) => {
                // Fall back to stderr fmt layer if journald is unavailable
                tracing::warn!(
                    "journald unavailable ({}), falling back to stderr logging",
                    e
                );
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().with_target(true))
                    .init();
            }
        }
    } else {
        // journald disabled in config — use stderr fmt layer
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .init();
    }

    Ok(())
}

/// Log a structured security operation.
///
/// This macro-like helper emits a tracing event at INFO level with the standard
/// structured fields required by the audit log specification.
///
/// # Fields
///
/// - `operation_type` — The type of operation (e.g., "tool_start", "firewall_rule_add")
/// - `user` — The initiating user
/// - `target_resource` — The resource being acted upon
/// - `result` — "success" or "failure"
#[inline]
pub fn log_operation(operation_type: &str, user: &str, target_resource: &str, result: &str) {
    tracing::info!(
        operation_type = operation_type,
        user = user,
        target_resource = target_resource,
        result = result,
        "security operation executed"
    );
}

/// Log a security operation that succeeded.
#[inline]
pub fn log_operation_success(operation_type: &str, user: &str, target_resource: &str) {
    log_operation(operation_type, user, target_resource, "success");
}

/// Log a security operation that failed.
#[inline]
pub fn log_operation_failure(operation_type: &str, user: &str, target_resource: &str) {
    log_operation(operation_type, user, target_resource, "failure");
}

// ─── Journal Integrity Monitoring ──────────────────────────────────────────

/// Metadata snapshot of a journal file used for tamper detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalFileState {
    /// Path to the journal file.
    pub path: PathBuf,
    /// File size in bytes at the time of snapshot.
    pub size: u64,
    /// Inode number at the time of snapshot.
    pub inode: u64,
}

/// Result of a journal integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityCheckResult {
    /// Journal file is intact — size has not decreased and inode is unchanged.
    Ok,
    /// Journal file size decreased (possible truncation/tampering).
    SizeDecreased { path: PathBuf, previous: u64, current: u64 },
    /// Journal file inode changed (file was replaced).
    InodeChanged { path: PathBuf, previous: u64, current: u64 },
    /// Journal file was deleted or is inaccessible.
    FileRemoved { path: PathBuf },
}

/// Monitors journal file integrity for tamper detection.
///
/// Periodically checks that journal files have not been truncated, replaced,
/// or deleted outside of normal systemd-journald operation.
pub struct JournalIntegrityMonitor {
    /// Known journal file states from the last check.
    known_states: Vec<JournalFileState>,
    /// Directory containing journal files.
    journal_dir: PathBuf,
    /// How often to check integrity.
    check_interval: Duration,
}

impl JournalIntegrityMonitor {
    /// Default journal directory for systemd-journald persistent storage.
    const DEFAULT_JOURNAL_DIR: &'static str = "/var/log/journal";

    /// Default check interval (60 seconds).
    const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(60);

    /// Create a new `JournalIntegrityMonitor` with default settings.
    pub fn new() -> Self {
        Self {
            known_states: Vec::new(),
            journal_dir: PathBuf::from(Self::DEFAULT_JOURNAL_DIR),
            check_interval: Self::DEFAULT_CHECK_INTERVAL,
        }
    }

    /// Create a new monitor with a custom journal directory and check interval.
    pub fn with_config(journal_dir: PathBuf, check_interval: Duration) -> Self {
        Self {
            known_states: Vec::new(),
            journal_dir,
            check_interval,
        }
    }

    /// Returns the configured check interval.
    pub fn check_interval(&self) -> Duration {
        self.check_interval
    }

    /// Returns the configured journal directory.
    pub fn journal_dir(&self) -> &PathBuf {
        &self.journal_dir
    }

    /// Initialize the monitor by scanning the journal directory and recording
    /// the current state of all `.journal` files.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the journal directory cannot be read.
    pub fn initialize(&mut self) -> std::io::Result<()> {
        self.known_states = self.scan_journal_files()?;
        tracing::info!(
            journal_dir = %self.journal_dir.display(),
            file_count = self.known_states.len(),
            "journal integrity monitor initialized"
        );
        Ok(())
    }

    /// Perform an integrity check against the previously recorded states.
    ///
    /// Returns a list of integrity violations found. An empty list means
    /// all journal files are intact.
    pub fn check_integrity(&mut self) -> Vec<IntegrityCheckResult> {
        let mut violations = Vec::new();

        for known in &self.known_states {
            match std::fs::metadata(&known.path) {
                Ok(metadata) => {
                    use std::os::unix::fs::MetadataExt;

                    let current_size = metadata.len();
                    let current_inode = metadata.ino();

                    if current_size < known.size {
                        let violation = IntegrityCheckResult::SizeDecreased {
                            path: known.path.clone(),
                            previous: known.size,
                            current: current_size,
                        };
                        tracing::error!(
                            operation_type = "journal_integrity_check",
                            user = "system",
                            target_resource = %known.path.display(),
                            result = "failure",
                            previous_size = known.size,
                            current_size = current_size,
                            "journal file size decreased — possible tampering"
                        );
                        violations.push(violation);
                    }

                    if current_inode != known.inode {
                        let violation = IntegrityCheckResult::InodeChanged {
                            path: known.path.clone(),
                            previous: known.inode,
                            current: current_inode,
                        };
                        tracing::error!(
                            operation_type = "journal_integrity_check",
                            user = "system",
                            target_resource = %known.path.display(),
                            result = "failure",
                            previous_inode = known.inode,
                            current_inode = current_inode,
                            "journal file inode changed — file may have been replaced"
                        );
                        violations.push(violation);
                    }
                }
                Err(_) => {
                    let violation = IntegrityCheckResult::FileRemoved {
                        path: known.path.clone(),
                    };
                    tracing::error!(
                        operation_type = "journal_integrity_check",
                        user = "system",
                        target_resource = %known.path.display(),
                        result = "failure",
                        "journal file removed or inaccessible — possible tampering"
                    );
                    violations.push(violation);
                }
            }
        }

        // Update known states with current snapshot (including new files)
        if let Ok(current_states) = self.scan_journal_files() {
            self.known_states = current_states;
        }

        if violations.is_empty() {
            tracing::debug!(
                operation_type = "journal_integrity_check",
                user = "system",
                target_resource = "journald",
                result = "success",
                "journal integrity check passed"
            );
        }

        violations
    }

    /// Scan the journal directory for `.journal` files and record their metadata.
    fn scan_journal_files(&self) -> std::io::Result<Vec<JournalFileState>> {
        let mut states = Vec::new();

        if !self.journal_dir.exists() {
            return Ok(states);
        }

        // Journal files may be in subdirectories (per machine-id)
        Self::scan_dir_recursive(&self.journal_dir, &mut states)?;

        Ok(states)
    }

    /// Recursively scan a directory for `.journal` files.
    fn scan_dir_recursive(
        dir: &std::path::Path,
        states: &mut Vec<JournalFileState>,
    ) -> std::io::Result<()> {
        let entries = std::fs::read_dir(dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Recurse into subdirectories
                Self::scan_dir_recursive(&path, states)?;
            } else if let Some(ext) = path.extension() {
                if ext == "journal" {
                    let metadata = std::fs::metadata(&path)?;
                    use std::os::unix::fs::MetadataExt;

                    states.push(JournalFileState {
                        path,
                        size: metadata.len(),
                        inode: metadata.ino(),
                    });
                }
            }
        }

        Ok(())
    }
}

impl Default for JournalIntegrityMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_env_filter_parsing_valid() {
        // Valid filter directives should parse without error
        let filter = EnvFilter::try_new("info");
        assert!(filter.is_ok());

        let filter = EnvFilter::try_new("debug");
        assert!(filter.is_ok());

        let filter = EnvFilter::try_new("shared=trace,backend_api=info");
        assert!(filter.is_ok());
    }

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, "info");
        assert!(config.journald);
    }

    #[test]
    fn test_journal_integrity_monitor_detects_size_decrease() {
        let tmp_dir = std::env::temp_dir().join("scc_test_journal_size");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        // Create a fake journal file
        let journal_path = tmp_dir.join("test.journal");
        {
            let mut f = fs::File::create(&journal_path).unwrap();
            f.write_all(&[0u8; 1024]).unwrap();
        }

        let mut monitor = JournalIntegrityMonitor::with_config(
            tmp_dir.clone(),
            Duration::from_secs(1),
        );
        monitor.initialize().unwrap();

        // Truncate the file (simulate tampering)
        {
            let mut f = fs::File::create(&journal_path).unwrap();
            f.write_all(&[0u8; 512]).unwrap();
        }

        let violations = monitor.check_integrity();
        assert!(!violations.is_empty());
        assert!(matches!(
            &violations[0],
            IntegrityCheckResult::SizeDecreased { previous: 1024, current: 512, .. }
        ));

        // Cleanup
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_journal_integrity_monitor_detects_file_removal() {
        let tmp_dir = std::env::temp_dir().join("scc_test_journal_removal");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let journal_path = tmp_dir.join("test.journal");
        {
            let mut f = fs::File::create(&journal_path).unwrap();
            f.write_all(&[0u8; 256]).unwrap();
        }

        let mut monitor = JournalIntegrityMonitor::with_config(
            tmp_dir.clone(),
            Duration::from_secs(1),
        );
        monitor.initialize().unwrap();

        // Remove the file
        fs::remove_file(&journal_path).unwrap();

        let violations = monitor.check_integrity();
        assert!(!violations.is_empty());
        assert!(matches!(
            &violations[0],
            IntegrityCheckResult::FileRemoved { .. }
        ));

        // Cleanup
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_journal_integrity_monitor_no_violations_when_intact() {
        let tmp_dir = std::env::temp_dir().join("scc_test_journal_intact");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let journal_path = tmp_dir.join("test.journal");
        {
            let mut f = fs::File::create(&journal_path).unwrap();
            f.write_all(&[0u8; 512]).unwrap();
        }

        let mut monitor = JournalIntegrityMonitor::with_config(
            tmp_dir.clone(),
            Duration::from_secs(1),
        );
        monitor.initialize().unwrap();

        // File grows (normal behavior) — append data
        {
            let mut f = fs::OpenOptions::new()
                .append(true)
                .open(&journal_path)
                .unwrap();
            f.write_all(&[0u8; 256]).unwrap();
        }

        let violations = monitor.check_integrity();
        assert!(violations.is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_journal_integrity_monitor_empty_dir() {
        let tmp_dir = std::env::temp_dir().join("scc_test_journal_empty");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        let mut monitor = JournalIntegrityMonitor::with_config(
            tmp_dir.clone(),
            Duration::from_secs(1),
        );
        monitor.initialize().unwrap();

        let violations = monitor.check_integrity();
        assert!(violations.is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
