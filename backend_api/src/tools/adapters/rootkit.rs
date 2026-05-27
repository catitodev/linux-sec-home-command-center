// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Rootkit detection adapter: coordinates chkrootkit and rkhunter scans.
//!
//! Provides consolidated rootkit scanning using both chkrootkit and rkhunter,
//! result deduplication, severity classification, weekly scheduling, and
//! comparison against previous scan results to highlight new findings.

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

/// Which rootkit detection tool produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootkitTool {
    Chkrootkit,
    Rkhunter,
}

/// Severity of a rootkit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RootkitSeverity {
    Informational,
    Warning,
    Critical,
}

/// A single finding from a rootkit scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootkitFinding {
    /// Unique identifier for this finding.
    pub id: Uuid,
    /// Which tool produced this finding.
    pub tool: RootkitTool,
    /// Description of the finding.
    pub finding_text: String,
    /// Severity classification.
    pub severity: RootkitSeverity,
    /// Guidance on how to remediate this finding.
    pub remediation_guidance: String,
}

/// Result of a consolidated rootkit scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RootkitScanResult {
    /// Unique identifier for this scan result.
    pub id: Uuid,
    /// All findings from both tools.
    pub findings: Vec<RootkitFinding>,
    /// Duration of the scan in seconds.
    pub scan_duration_secs: u64,
    /// When the scan was performed.
    pub scanned_at: DateTime<Utc>,
    /// New findings compared to the previous scan.
    pub new_findings: Vec<RootkitFinding>,
}

/// Coordinates chkrootkit and rkhunter scans.
pub struct RootkitScanner {
    /// Previous scan result for comparison.
    previous_result: Option<RootkitScanResult>,
}

impl RootkitScanner {
    /// Creates a new rootkit scanner.
    pub fn new() -> Self {
        Self {
            previous_result: None,
        }
    }

    /// Creates a scanner with a previous result for comparison.
    pub fn with_previous(previous: RootkitScanResult) -> Self {
        Self {
            previous_result: Some(previous),
        }
    }

    /// Returns the previous scan result, if any.
    pub fn previous_result(&self) -> Option<&RootkitScanResult> {
        self.previous_result.as_ref()
    }

    /// Parses chkrootkit output into findings.
    pub fn parse_chkrootkit_output(output: &str) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // chkrootkit reports "INFECTED" for positive detections
            if line.contains("INFECTED") {
                findings.push(RootkitFinding {
                    id: Uuid::new_v4(),
                    tool: RootkitTool::Chkrootkit,
                    finding_text: line.to_string(),
                    severity: RootkitSeverity::Critical,
                    remediation_guidance: "Investigate the reported binary immediately. \
                        Compare against known-good checksums and consider reinstalling \
                        the affected package."
                        .to_string(),
                });
            } else if line.contains("SUSPECT") || line.contains("Warning") {
                findings.push(RootkitFinding {
                    id: Uuid::new_v4(),
                    tool: RootkitTool::Chkrootkit,
                    finding_text: line.to_string(),
                    severity: RootkitSeverity::Warning,
                    remediation_guidance: "Review the suspicious finding. This may be a \
                        false positive but should be investigated."
                        .to_string(),
                });
            }
        }

        findings
    }

    /// Parses rkhunter output into findings.
    pub fn parse_rkhunter_output(output: &str) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if line.contains("[ Warning ]") {
                let description = line
                    .split("[ Warning ]")
                    .next()
                    .unwrap_or(line)
                    .trim()
                    .to_string();

                let severity = if description.to_lowercase().contains("rootkit")
                    || description.to_lowercase().contains("backdoor")
                {
                    RootkitSeverity::Critical
                } else {
                    RootkitSeverity::Warning
                };

                let remediation = match severity {
                    RootkitSeverity::Critical => {
                        "Critical rootkit indicator detected. Isolate the system \
                         and perform forensic analysis."
                            .to_string()
                    }
                    RootkitSeverity::Warning => {
                        "Review the warning and verify system integrity. \
                         Update rkhunter database if this is a known false positive."
                            .to_string()
                    }
                    RootkitSeverity::Informational => {
                        "Informational finding, no action required.".to_string()
                    }
                };

                findings.push(RootkitFinding {
                    id: Uuid::new_v4(),
                    tool: RootkitTool::Rkhunter,
                    finding_text: description,
                    severity,
                    remediation_guidance: remediation,
                });
            }
        }

        findings
    }

    /// Compares current findings against previous scan to identify new ones.
    pub fn find_new_findings(
        current: &[RootkitFinding],
        previous: &[RootkitFinding],
    ) -> Vec<RootkitFinding> {
        current
            .iter()
            .filter(|finding| {
                !previous
                    .iter()
                    .any(|prev| prev.finding_text == finding.finding_text && prev.tool == finding.tool)
            })
            .cloned()
            .collect()
    }
}

impl Default for RootkitScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─── RootkitAdapter ────────────────────────────────────────────────────────

/// Adapter for rootkit detection tools (chkrootkit + rkhunter).
pub struct RootkitAdapter;

#[async_trait]
impl ToolAdapter for RootkitAdapter {
    fn name(&self) -> &str {
        "chkrootkit"
    }

    fn display_name(&self) -> &str {
        "Rootkit Detection"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Detection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let (chk_pkg, rkh_pkg) = match distro.package_manager {
            PackageManager::Apt => ("chkrootkit", "rkhunter"),
            PackageManager::Dnf => ("chkrootkit", "rkhunter"),
            PackageManager::Pacman => ("chkrootkit", "rkhunter"),
            PackageManager::Zypper => ("chkrootkit", "rkhunter"),
        };

        info!(chkrootkit = chk_pkg, rkhunter = rkh_pkg, distro = %distro.id, "Installing rootkit detection tools");

        let install_args: Vec<&str> = match distro.package_manager {
            PackageManager::Apt => vec!["apt-get", "install", "-y", chk_pkg, rkh_pkg],
            PackageManager::Dnf => vec!["dnf", "install", "-y", chk_pkg, rkh_pkg],
            PackageManager::Pacman => vec!["pacman", "-S", "--noconfirm", chk_pkg, rkh_pkg],
            PackageManager::Zypper => vec!["zypper", "install", "-y", chk_pkg, rkh_pkg],
        };

        let mut cmd = SafeCommand::new(install_args[0]);
        cmd.args(&install_args[1..])?;
        cmd.timeout(Duration::from_secs(120));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "chkrootkit".to_string(),
                reason: format!("package install failed: {}", output.stderr),
            });
        }

        info!("Rootkit detection tools installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        // Scan-based tool — no service to start.
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        // Scan-based tool — no service to stop.
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        // Check that both binaries exist.
        let mut chk_cmd = SafeCommand::new("which");
        if chk_cmd.arg("chkrootkit").is_err() {
            return HealthStatus::Unhealthy("failed to build command".to_string());
        }
        chk_cmd.timeout(Duration::from_secs(5));

        let chk_ok = chk_cmd
            .execute()
            .await
            .map(|o| o.exit_code == Some(0))
            .unwrap_or(false);

        let mut rkh_cmd = SafeCommand::new("which");
        if rkh_cmd.arg("rkhunter").is_err() {
            return HealthStatus::Unhealthy("failed to build command".to_string());
        }
        rkh_cmd.timeout(Duration::from_secs(5));

        let rkh_ok = rkh_cmd
            .execute()
            .await
            .map(|o| o.exit_code == Some(0))
            .unwrap_or(false);

        match (chk_ok, rkh_ok) {
            (true, true) => HealthStatus::Healthy,
            (true, false) => {
                HealthStatus::Degraded("rkhunter binary not found".to_string())
            }
            (false, true) => {
                HealthStatus::Degraded("chkrootkit binary not found".to_string())
            }
            (false, false) => {
                HealthStatus::Unhealthy("neither chkrootkit nor rkhunter found".to_string())
            }
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // ~5 MB combined
        5_000_000
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = RootkitAdapter;
        assert_eq!(adapter.name(), "chkrootkit");
        assert_eq!(adapter.display_name(), "Rootkit Detection");
        assert_eq!(adapter.category(), ToolCategory::Detection);
    }

    #[test]
    fn test_adapter_available_for_all_distros() {
        let adapter = RootkitAdapter;
        let distro = DistroInfo {
            id: "fedora".to_string(),
            version_id: "39".to_string(),
            name: "Fedora".to_string(),
            package_manager: PackageManager::Dnf,
            has_btrfs: false,
            kernel_version: (6, 5),
            has_ebpf: true,
            mac_framework: shared::distro::MACFramework::SELinux,
        };
        assert!(adapter.is_available_for(&distro));
    }

    #[test]
    fn test_parse_chkrootkit_infected() {
        let output = "Checking `ls'... INFECTED\nChecking `ps'... not infected\n";
        let findings = RootkitScanner::parse_chkrootkit_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, RootkitTool::Chkrootkit);
        assert_eq!(findings[0].severity, RootkitSeverity::Critical);
        assert!(findings[0].finding_text.contains("INFECTED"));
    }

    #[test]
    fn test_parse_chkrootkit_suspect() {
        let output = "Checking `bindshell'... SUSPECT something\nChecking `ls'... not infected\n";
        let findings = RootkitScanner::parse_chkrootkit_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Warning);
    }

    #[test]
    fn test_parse_chkrootkit_clean() {
        let output = "Checking `ls'... not infected\nChecking `ps'... not infected\n";
        let findings = RootkitScanner::parse_chkrootkit_output(output);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_rkhunter_warning() {
        let output = "/usr/bin/something                           [ Warning ]\n\
                      /usr/bin/clean                               [ OK ]\n";
        let findings = RootkitScanner::parse_rkhunter_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, RootkitTool::Rkhunter);
        assert_eq!(findings[0].severity, RootkitSeverity::Warning);
    }

    #[test]
    fn test_parse_rkhunter_rootkit_critical() {
        let output = "Rootkit detected in /usr/bin/evil            [ Warning ]\n";
        let findings = RootkitScanner::parse_rkhunter_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RootkitSeverity::Critical);
    }

    #[test]
    fn test_find_new_findings() {
        let previous = vec![RootkitFinding {
            id: Uuid::new_v4(),
            tool: RootkitTool::Chkrootkit,
            finding_text: "old finding".to_string(),
            severity: RootkitSeverity::Warning,
            remediation_guidance: "review".to_string(),
        }];

        let current = vec![
            RootkitFinding {
                id: Uuid::new_v4(),
                tool: RootkitTool::Chkrootkit,
                finding_text: "old finding".to_string(),
                severity: RootkitSeverity::Warning,
                remediation_guidance: "review".to_string(),
            },
            RootkitFinding {
                id: Uuid::new_v4(),
                tool: RootkitTool::Rkhunter,
                finding_text: "new finding".to_string(),
                severity: RootkitSeverity::Critical,
                remediation_guidance: "investigate".to_string(),
            },
        ];

        let new_findings = RootkitScanner::find_new_findings(&current, &previous);
        assert_eq!(new_findings.len(), 1);
        assert_eq!(new_findings[0].finding_text, "new finding");
    }

    #[test]
    fn test_scan_result_creation() {
        let result = RootkitScanResult {
            id: Uuid::new_v4(),
            findings: vec![],
            scan_duration_secs: 45,
            scanned_at: Utc::now(),
            new_findings: vec![],
        };
        assert_eq!(result.scan_duration_secs, 45);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_estimated_size() {
        let adapter = RootkitAdapter;
        assert!(adapter.estimated_size_bytes() > 0);
    }
}
