// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! AIDE (Advanced Intrusion Detection Environment) adapter.
//!
//! Provides file integrity monitoring by managing the AIDE baseline database,
//! running periodic integrity checks, parsing change reports, and supporting
//! baseline updates when legitimate changes are acknowledged.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use shared::distro::{DistroInfo, PackageManager};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Default AIDE database path.
const AIDE_DB_PATH: &str = "/var/lib/aide/aide.db";

/// AIDE new database path (generated during check/update).
const AIDE_DB_NEW_PATH: &str = "/var/lib/aide/aide.db.new";

/// Default check interval in seconds (4 hours).
pub const DEFAULT_CHECK_INTERVAL_SECS: u64 = 4 * 60 * 60;

/// Default baseline paths monitored by AIDE.
pub const BASELINE_PATHS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/etc",
    "/boot",
];

// ─── Types ─────────────────────────────────────────────────────────────────

/// Type of change detected in a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    /// File content was modified.
    Content,
    /// File permissions changed.
    Permissions,
    /// File ownership changed.
    Ownership,
    /// File was added (not in baseline).
    Added,
    /// File was removed (in baseline but missing).
    Removed,
}

/// A single file change detected by AIDE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
    /// Path to the changed file.
    pub path: PathBuf,
    /// Type of change detected.
    pub change_type: ChangeType,
    /// Previous value (if applicable).
    pub old_value: Option<String>,
    /// New value (if applicable).
    pub new_value: Option<String>,
    /// When the change was detected.
    pub detected_at: DateTime<Utc>,
}

/// Result of an integrity check run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntegrityCheckResult {
    /// Unique identifier for this check.
    pub id: Uuid,
    /// List of detected changes.
    pub changes: Vec<FileChange>,
    /// When the check was performed.
    pub checked_at: DateTime<Utc>,
    /// Duration of the check in seconds.
    pub duration_secs: u64,
    /// Whether the check completed successfully.
    pub success: bool,
}

/// Runs AIDE integrity checks and parses output.
pub struct IntegrityCheck;

impl IntegrityCheck {
    /// Parses AIDE check output into a list of file changes.
    ///
    /// AIDE output format for changes typically looks like:
    /// ```text
    /// changed: /etc/passwd
    /// added: /etc/newfile.conf
    /// removed: /etc/oldfile.conf
    /// ```
    pub fn parse_aide_output(output: &str) -> Vec<FileChange> {
        let mut changes = Vec::new();
        let now = Utc::now();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Parse "changed: /path" format
            if let Some(path_str) = line.strip_prefix("changed: ") {
                changes.push(FileChange {
                    path: PathBuf::from(path_str.trim()),
                    change_type: ChangeType::Content,
                    old_value: None,
                    new_value: None,
                    detected_at: now,
                });
            } else if let Some(path_str) = line.strip_prefix("added: ") {
                changes.push(FileChange {
                    path: PathBuf::from(path_str.trim()),
                    change_type: ChangeType::Added,
                    old_value: None,
                    new_value: None,
                    detected_at: now,
                });
            } else if let Some(path_str) = line.strip_prefix("removed: ") {
                changes.push(FileChange {
                    path: PathBuf::from(path_str.trim()),
                    change_type: ChangeType::Removed,
                    old_value: None,
                    new_value: None,
                    detected_at: now,
                });
            }
            // Parse AIDE summary format: "f = .... : /path"
            else if line.starts_with('f') || line.starts_with('d') || line.starts_with('l') {
                if let Some(colon_pos) = line.rfind(": ") {
                    let path_str = &line[colon_pos + 2..];
                    let attrs = &line[..colon_pos];

                    let change_type = if attrs.contains('p') {
                        ChangeType::Permissions
                    } else if attrs.contains('u') || attrs.contains('g') {
                        ChangeType::Ownership
                    } else {
                        ChangeType::Content
                    };

                    changes.push(FileChange {
                        path: PathBuf::from(path_str.trim()),
                        change_type,
                        old_value: None,
                        new_value: None,
                        detected_at: now,
                    });
                }
            }
        }

        changes
    }
}

/// Manages the AIDE baseline database.
pub struct BaselineManager {
    /// Path to the AIDE database.
    db_path: PathBuf,
    /// Path to the new database generated during checks.
    db_new_path: PathBuf,
}

impl BaselineManager {
    /// Creates a new baseline manager with default paths.
    pub fn new() -> Self {
        Self {
            db_path: PathBuf::from(AIDE_DB_PATH),
            db_new_path: PathBuf::from(AIDE_DB_NEW_PATH),
        }
    }

    /// Creates a baseline manager with custom paths (for testing).
    pub fn with_paths(db_path: &Path, db_new_path: &Path) -> Self {
        Self {
            db_path: db_path.to_path_buf(),
            db_new_path: db_new_path.to_path_buf(),
        }
    }

    /// Returns the database path.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Checks whether the AIDE database exists.
    pub fn database_exists(&self) -> bool {
        self.db_path.exists()
    }

    /// Initializes the AIDE baseline database.
    pub async fn initialize_baseline(&self) -> Result<()> {
        info!("Initializing AIDE baseline database");

        let mut cmd = SafeCommand::new("aide");
        cmd.args(&["--init"])?;
        cmd.timeout(Duration::from_secs(600));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "aide".to_string(),
                reason: format!("aide --init failed: {}", output.stderr),
            });
        }

        // Move the new database to the active position.
        if self.db_new_path.exists() {
            let mut mv_cmd = SafeCommand::new("mv");
            mv_cmd.args(&[
                &self.db_new_path.to_string_lossy(),
                &self.db_path.to_string_lossy(),
            ])?;
            mv_cmd.timeout(Duration::from_secs(10));

            let mv_output = mv_cmd.execute().await?;
            if mv_output.exit_code != Some(0) {
                return Err(CommandCenterError::ToolOperationFailed {
                    tool: "aide".to_string(),
                    reason: format!("failed to move new database: {}", mv_output.stderr),
                });
            }
        }

        info!("AIDE baseline database initialized");
        Ok(())
    }

    /// Updates the baseline for a specific path (after acknowledging changes).
    pub async fn update_baseline(&self, path: &Path) -> Result<()> {
        info!(path = %path.display(), "Updating AIDE baseline");

        let mut cmd = SafeCommand::new("aide");
        cmd.args(&["--update"])?;
        cmd.timeout(Duration::from_secs(600));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) && output.exit_code != Some(7) {
            // Exit code 7 means changes detected (expected during update)
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "aide".to_string(),
                reason: format!("aide --update failed: {}", output.stderr),
            });
        }

        // Move the new database to the active position.
        if self.db_new_path.exists() {
            let mut mv_cmd = SafeCommand::new("mv");
            mv_cmd.args(&[
                &self.db_new_path.to_string_lossy(),
                &self.db_path.to_string_lossy(),
            ])?;
            mv_cmd.timeout(Duration::from_secs(10));
            let _ = mv_cmd.execute().await;
        }

        info!(path = %path.display(), "AIDE baseline updated");
        Ok(())
    }

    /// Checks the integrity of the AIDE database itself.
    pub fn check_database_integrity(&self) -> bool {
        self.db_path.exists() && self.db_path.metadata().map(|m| m.len() > 0).unwrap_or(false)
    }
}

impl Default for BaselineManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── AideAdapter ───────────────────────────────────────────────────────────

/// Adapter for AIDE file integrity monitoring.
pub struct AideAdapter;

#[async_trait]
impl ToolAdapter for AideAdapter {
    fn name(&self) -> &str {
        "aide"
    }

    fn display_name(&self) -> &str {
        "AIDE"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Detection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let pkg = match distro.package_manager {
            PackageManager::Apt => "aide",
            PackageManager::Dnf => "aide",
            PackageManager::Pacman => "aide",
            PackageManager::Zypper => "aide",
        };

        info!(package = pkg, distro = %distro.id, "Installing AIDE");

        let install_args: Vec<&str> = match distro.package_manager {
            PackageManager::Apt => vec!["apt-get", "install", "-y", pkg],
            PackageManager::Dnf => vec!["dnf", "install", "-y", pkg],
            PackageManager::Pacman => vec!["pacman", "-S", "--noconfirm", pkg],
            PackageManager::Zypper => vec!["zypper", "install", "-y", pkg],
        };

        let mut cmd = SafeCommand::new(install_args[0]);
        cmd.args(&install_args[1..])?;
        cmd.timeout(Duration::from_secs(120));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "aide".to_string(),
                reason: format!("package install failed: {}", output.stderr),
            });
        }

        // Initialize the baseline database.
        let manager = BaselineManager::new();
        manager.initialize_baseline().await?;

        info!("AIDE installed and baseline initialized");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        // AIDE is scheduled-check based, no service to start.
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        // AIDE is scheduled-check based, no service to stop.
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        // Check that aide binary exists.
        let mut cmd = SafeCommand::new("which");
        if cmd.arg("aide").is_err() {
            return HealthStatus::Unhealthy("failed to build command".to_string());
        }
        cmd.timeout(Duration::from_secs(5));

        let binary_ok = cmd
            .execute()
            .await
            .map(|o| o.exit_code == Some(0))
            .unwrap_or(false);

        if !binary_ok {
            return HealthStatus::Unhealthy("aide binary not found".to_string());
        }

        // Check that the database exists.
        let db_exists = Path::new(AIDE_DB_PATH).exists();
        if !db_exists {
            return HealthStatus::Degraded("AIDE database not initialized".to_string());
        }

        HealthStatus::Healthy
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // ~3 MB for aide package
        3_000_000
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = AideAdapter;
        assert_eq!(adapter.name(), "aide");
        assert_eq!(adapter.display_name(), "AIDE");
        assert_eq!(adapter.category(), ToolCategory::Detection);
    }

    #[test]
    fn test_adapter_available_for_all_distros() {
        let adapter = AideAdapter;
        let distro = DistroInfo {
            id: "arch".to_string(),
            version_id: "".to_string(),
            name: "Arch Linux".to_string(),
            package_manager: PackageManager::Pacman,
            has_btrfs: false,
            kernel_version: (6, 7),
            has_ebpf: true,
            mac_framework: shared::distro::MACFramework::None,
        };
        assert!(adapter.is_available_for(&distro));
    }

    #[test]
    fn test_parse_aide_output_changed() {
        let output = "changed: /etc/passwd\nchanged: /etc/shadow\n";
        let changes = IntegrityCheck::parse_aide_output(output);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].path, PathBuf::from("/etc/passwd"));
        assert_eq!(changes[0].change_type, ChangeType::Content);
        assert_eq!(changes[1].path, PathBuf::from("/etc/shadow"));
    }

    #[test]
    fn test_parse_aide_output_added() {
        let output = "added: /etc/newconfig.conf\n";
        let changes = IntegrityCheck::parse_aide_output(output);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Added);
    }

    #[test]
    fn test_parse_aide_output_removed() {
        let output = "removed: /etc/oldfile.conf\n";
        let changes = IntegrityCheck::parse_aide_output(output);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Removed);
    }

    #[test]
    fn test_parse_aide_output_empty() {
        let output = "\n\n";
        let changes = IntegrityCheck::parse_aide_output(output);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_baseline_manager_custom_paths() {
        let db = PathBuf::from("/tmp/test_aide.db");
        let db_new = PathBuf::from("/tmp/test_aide.db.new");
        let manager = BaselineManager::with_paths(&db, &db_new);
        assert_eq!(manager.db_path(), db);
    }

    #[test]
    fn test_baseline_manager_database_not_exists() {
        let db = PathBuf::from("/nonexistent/aide.db");
        let db_new = PathBuf::from("/nonexistent/aide.db.new");
        let manager = BaselineManager::with_paths(&db, &db_new);
        assert!(!manager.database_exists());
    }

    #[test]
    fn test_baseline_paths_coverage() {
        assert!(BASELINE_PATHS.contains(&"/bin"));
        assert!(BASELINE_PATHS.contains(&"/sbin"));
        assert!(BASELINE_PATHS.contains(&"/usr/bin"));
        assert!(BASELINE_PATHS.contains(&"/usr/sbin"));
        assert!(BASELINE_PATHS.contains(&"/etc"));
        assert!(BASELINE_PATHS.contains(&"/boot"));
    }

    #[test]
    fn test_default_check_interval() {
        // 4 hours in seconds
        assert_eq!(DEFAULT_CHECK_INTERVAL_SECS, 14400);
    }

    #[test]
    fn test_estimated_size() {
        let adapter = AideAdapter;
        assert!(adapter.estimated_size_bytes() > 0);
    }
}
