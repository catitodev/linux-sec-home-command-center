// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Lynis adapter: system hardening audits and health score calculation.
//!
//! Provides system security auditing via Lynis, parses audit findings into
//! actionable recommendations, supports one-click fixes for common issues,
//! and implements the composite health score formula used by the dashboard.

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

// ─── Types ─────────────────────────────────────────────────────────────────

/// Category of a Lynis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LynisCategory {
    /// Authentication and access control.
    Auth,
    /// Network configuration and security.
    Networking,
    /// Filesystem permissions and integrity.
    Filesystem,
    /// Kernel hardening and parameters.
    Kernel,
    /// Software and package management.
    Software,
    /// Logging and auditing.
    Logging,
    /// Other/uncategorized.
    Other,
}

/// Priority level for a Lynis finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LynisPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// A single finding from a Lynis audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LynisFinding {
    /// Unique identifier for this finding.
    pub id: Uuid,
    /// Lynis test ID (e.g., "AUTH-9262").
    pub test_id: String,
    /// Category of the finding.
    pub category: LynisCategory,
    /// Description of the finding.
    pub description: String,
    /// Priority level.
    pub priority: LynisPriority,
    /// Suggested remediation.
    pub suggestion: String,
}

/// A hardening recommendation with optional one-click fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningRecommendation {
    /// The underlying finding.
    pub finding: LynisFinding,
    /// Whether a one-click fix is available.
    pub one_click_fix: bool,
    /// Command to execute for the fix (if available).
    pub fix_command: Option<String>,
}

/// A historical health score entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HealthScoreEntry {
    /// The computed health score (0-100).
    pub score: u32,
    /// When this score was computed.
    pub computed_at: DateTime<Utc>,
    /// Lynis hardening index at the time.
    pub lynis_index: u32,
    /// Number of active running tools at the time.
    pub active_tools: u32,
    /// Total installed tools at the time.
    pub total_tools: u32,
    /// Number of open critical alerts at the time.
    pub open_critical_alerts: u32,
}

/// Stores historical health scores.
pub struct HealthScoreHistory {
    /// Historical score entries.
    entries: Vec<HealthScoreEntry>,
}

impl HealthScoreHistory {
    /// Creates a new empty history.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a score entry to the history.
    pub fn add_entry(&mut self, entry: HealthScoreEntry) {
        self.entries.push(entry);
    }

    /// Returns all historical entries.
    pub fn entries(&self) -> &[HealthScoreEntry] {
        &self.entries
    }

    /// Returns the most recent score, if any.
    pub fn latest(&self) -> Option<&HealthScoreEntry> {
        self.entries.last()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for HealthScoreHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculates the composite health score for the dashboard.
///
/// Formula:
/// ```text
/// health_score = (lynis_component × 0.40) + (tools_component × 0.30) + (alerts_component × 0.30)
/// ```
///
/// Where:
/// - `lynis_component` = Lynis hardening index (0-100)
/// - `tools_component` = (active_running_tools / total_installed_tools) × 100
/// - `alerts_component` = max(0, 100 - (open_critical_alerts × 10))
/// - Final result clamped to 0-100 integer
pub struct HealthScoreCalculator;

impl HealthScoreCalculator {
    /// Computes the health score from the three components.
    ///
    /// # Arguments
    ///
    /// * `lynis_index` - Lynis hardening index (0-100)
    /// * `active_tools` - Number of actively running security tools
    /// * `total_tools` - Total number of installed security tools
    /// * `open_critical_alerts` - Number of unacknowledged critical alerts
    ///
    /// # Returns
    ///
    /// Health score as an integer in the range 0-100.
    pub fn calculate(
        lynis_index: u32,
        active_tools: u32,
        total_tools: u32,
        open_critical_alerts: u32,
    ) -> u32 {
        let lynis_component = lynis_index.min(100) as f64;

        let tools_component = if total_tools > 0 {
            (active_tools as f64 / total_tools as f64) * 100.0
        } else {
            0.0
        };

        let alerts_penalty = (open_critical_alerts as f64) * 10.0;
        let alerts_component = (100.0 - alerts_penalty).max(0.0);

        let raw_score =
            (lynis_component * 0.40) + (tools_component * 0.30) + (alerts_component * 0.30);

        // Clamp to 0-100 integer.
        raw_score.round().min(100.0).max(0.0) as u32
    }
}

/// Runs Lynis audits and parses output.
pub struct LynisAudit;

impl LynisAudit {
    /// Parses Lynis audit output into findings.
    ///
    /// Lynis outputs suggestions in the format:
    /// ```text
    /// * Suggestion: description [test:TEST-ID]
    /// ```
    pub fn parse_audit_output(output: &str) -> Vec<LynisFinding> {
        let mut findings = Vec::new();

        for line in output.lines() {
            let line = line.trim();

            // Parse suggestion lines
            if let Some(suggestion_text) = line.strip_prefix("* ") {
                let (description, test_id) = Self::extract_test_id(suggestion_text);
                let category = Self::categorize_test_id(&test_id);
                let priority = Self::determine_priority(line);

                findings.push(LynisFinding {
                    id: Uuid::new_v4(),
                    test_id,
                    category,
                    description: description.to_string(),
                    priority,
                    suggestion: description.to_string(),
                });
            }
            // Parse warning lines
            else if line.starts_with("! ") || line.contains("[WARNING]") {
                let description = line
                    .trim_start_matches("! ")
                    .trim_start_matches("[WARNING] ")
                    .to_string();
                let (desc, test_id) = Self::extract_test_id(&description);

                findings.push(LynisFinding {
                    id: Uuid::new_v4(),
                    test_id,
                    category: Self::categorize_test_id(""),
                    description: desc.to_string(),
                    priority: LynisPriority::High,
                    suggestion: desc.to_string(),
                });
            }
        }

        findings
    }

    /// Extracts the test ID from a finding line.
    /// Returns (description, test_id).
    fn extract_test_id(text: &str) -> (&str, String) {
        if let Some(bracket_start) = text.rfind('[') {
            if let Some(bracket_end) = text.rfind(']') {
                if bracket_start < bracket_end {
                    let test_id = &text[bracket_start + 1..bracket_end];
                    // Remove "test:" prefix if present
                    let test_id = test_id.strip_prefix("test:").unwrap_or(test_id);
                    let description = text[..bracket_start].trim();
                    return (description, test_id.to_string());
                }
            }
        }
        (text, "UNKNOWN".to_string())
    }

    /// Categorizes a finding based on its test ID prefix.
    fn categorize_test_id(test_id: &str) -> LynisCategory {
        if test_id.starts_with("AUTH") {
            LynisCategory::Auth
        } else if test_id.starts_with("NETW") || test_id.starts_with("FIRE") {
            LynisCategory::Networking
        } else if test_id.starts_with("FILE") || test_id.starts_with("STRG") {
            LynisCategory::Filesystem
        } else if test_id.starts_with("KRNL") {
            LynisCategory::Kernel
        } else if test_id.starts_with("PKGS") || test_id.starts_with("BINA") {
            LynisCategory::Software
        } else if test_id.starts_with("LOGG") || test_id.starts_with("ACCT") {
            LynisCategory::Logging
        } else {
            LynisCategory::Other
        }
    }

    /// Determines priority based on line content.
    fn determine_priority(line: &str) -> LynisPriority {
        let lower = line.to_lowercase();
        if lower.contains("critical") || lower.contains("immediate") {
            LynisPriority::Critical
        } else if lower.contains("warning") || lower.contains("high") {
            LynisPriority::High
        } else if lower.contains("medium") || lower.contains("consider") {
            LynisPriority::Medium
        } else {
            LynisPriority::Low
        }
    }

    /// Parses the hardening index from Lynis output.
    ///
    /// Lynis outputs: "Hardening index : 67 [#############       ]"
    pub fn parse_hardening_index(output: &str) -> Option<u32> {
        for line in output.lines() {
            let line = line.trim();
            if line.contains("Hardening index") {
                // Extract the number after ":"
                if let Some(colon_pos) = line.find(':') {
                    let after_colon = line[colon_pos + 1..].trim();
                    // Take digits only
                    let num_str: String =
                        after_colon.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(index) = num_str.parse::<u32>() {
                        return Some(index.min(100));
                    }
                }
            }
        }
        None
    }
}

// ─── LynisAdapter ──────────────────────────────────────────────────────────

/// Adapter for Lynis system hardening audits.
pub struct LynisAdapter;

#[async_trait]
impl ToolAdapter for LynisAdapter {
    fn name(&self) -> &str {
        "lynis"
    }

    fn display_name(&self) -> &str {
        "Lynis"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Detection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let pkg = match distro.package_manager {
            PackageManager::Apt => "lynis",
            PackageManager::Dnf => "lynis",
            PackageManager::Pacman => "lynis",
            PackageManager::Zypper => "lynis",
        };

        info!(package = pkg, distro = %distro.id, "Installing Lynis");

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
                tool: "lynis".to_string(),
                reason: format!("package install failed: {}", output.stderr),
            });
        }

        info!("Lynis installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        // Audit-based tool — no service to start.
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        // Audit-based tool — no service to stop.
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("which");
        if cmd.arg("lynis").is_err() {
            return HealthStatus::Unhealthy("failed to build command".to_string());
        }
        cmd.timeout(Duration::from_secs(5));

        match cmd.execute().await {
            Ok(output) => {
                if output.exit_code == Some(0) {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Unhealthy("lynis binary not found".to_string())
                }
            }
            Err(e) => HealthStatus::Unhealthy(format!("health check failed: {}", e)),
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // ~2 MB
        2_000_000
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = LynisAdapter;
        assert_eq!(adapter.name(), "lynis");
        assert_eq!(adapter.display_name(), "Lynis");
        assert_eq!(adapter.category(), ToolCategory::Detection);
    }

    #[test]
    fn test_adapter_available_for_all_distros() {
        let adapter = LynisAdapter;
        let distro = DistroInfo {
            id: "opensuse-tumbleweed".to_string(),
            version_id: "20231201".to_string(),
            name: "openSUSE Tumbleweed".to_string(),
            package_manager: PackageManager::Zypper,
            has_btrfs: true,
            kernel_version: (6, 6),
            has_ebpf: true,
            mac_framework: shared::distro::MACFramework::AppArmor,
        };
        assert!(adapter.is_available_for(&distro));
    }

    #[test]
    fn test_health_score_perfect() {
        // All components at maximum
        let score = HealthScoreCalculator::calculate(100, 10, 10, 0);
        assert_eq!(score, 100);
    }

    #[test]
    fn test_health_score_zero() {
        // All components at minimum
        let score = HealthScoreCalculator::calculate(0, 0, 10, 10);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_health_score_mixed() {
        // lynis=80, tools=5/10=50%, alerts=2 critical
        // (80*0.40) + (50*0.30) + (80*0.30) = 32 + 15 + 24 = 71
        let score = HealthScoreCalculator::calculate(80, 5, 10, 2);
        assert_eq!(score, 71);
    }

    #[test]
    fn test_health_score_no_tools_installed() {
        // Edge case: no tools installed (avoid division by zero)
        let score = HealthScoreCalculator::calculate(50, 0, 0, 0);
        // (50*0.40) + (0*0.30) + (100*0.30) = 20 + 0 + 30 = 50
        assert_eq!(score, 50);
    }

    #[test]
    fn test_health_score_many_alerts() {
        // Many critical alerts should floor the alerts component at 0
        let score = HealthScoreCalculator::calculate(100, 10, 10, 20);
        // (100*0.40) + (100*0.30) + (0*0.30) = 40 + 30 + 0 = 70
        assert_eq!(score, 70);
    }

    #[test]
    fn test_parse_hardening_index() {
        let output = "  Hardening index : 67 [#############       ]\n";
        assert_eq!(LynisAudit::parse_hardening_index(output), Some(67));
    }

    #[test]
    fn test_parse_hardening_index_not_found() {
        let output = "Some other output\nNo index here\n";
        assert_eq!(LynisAudit::parse_hardening_index(output), None);
    }

    #[test]
    fn test_parse_audit_output_suggestion() {
        let output = "* Consider hardening SSH configuration [test:AUTH-9262]\n";
        let findings = LynisAudit::parse_audit_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].test_id, "AUTH-9262");
        assert_eq!(findings[0].category, LynisCategory::Auth);
    }

    #[test]
    fn test_parse_audit_output_warning() {
        let output = "! Found vulnerable package [WARNING]\n";
        let findings = LynisAudit::parse_audit_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].priority, LynisPriority::High);
    }

    #[test]
    fn test_categorize_test_ids() {
        assert_eq!(LynisAudit::categorize_test_id("AUTH-9262"), LynisCategory::Auth);
        assert_eq!(LynisAudit::categorize_test_id("NETW-3200"), LynisCategory::Networking);
        assert_eq!(LynisAudit::categorize_test_id("FILE-6310"), LynisCategory::Filesystem);
        assert_eq!(LynisAudit::categorize_test_id("KRNL-5820"), LynisCategory::Kernel);
        assert_eq!(LynisAudit::categorize_test_id("PKGS-7392"), LynisCategory::Software);
        assert_eq!(LynisAudit::categorize_test_id("LOGG-2154"), LynisCategory::Logging);
        assert_eq!(LynisAudit::categorize_test_id("MISC-1234"), LynisCategory::Other);
    }

    #[test]
    fn test_health_score_history() {
        let mut history = HealthScoreHistory::new();
        assert!(history.is_empty());
        assert_eq!(history.len(), 0);

        history.add_entry(HealthScoreEntry {
            score: 75,
            computed_at: Utc::now(),
            lynis_index: 80,
            active_tools: 8,
            total_tools: 10,
            open_critical_alerts: 1,
        });

        assert_eq!(history.len(), 1);
        assert!(!history.is_empty());
        assert_eq!(history.latest().unwrap().score, 75);
    }

    #[test]
    fn test_estimated_size() {
        let adapter = LynisAdapter;
        assert!(adapter.estimated_size_bytes() > 0);
    }
}
