// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! ClamAV + YARA adapter: antivirus scanning with signature-based and rule-based detection.
//!
//! Provides parallel scanning using ClamAV (signature-based) and YARA (rule-based),
//! scheduled scans, progress tracking, and default YARA rules for common Linux threats.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use shared::distro::{DistroInfo, PackageManager};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Default YARA rule: ELF malware detection.
pub const YARA_RULE_ELF_MALWARE: &str = r#"
rule elf_malware {
    meta:
        description = "Detects suspicious ELF binaries with common malware traits"
        severity = "high"
    strings:
        $elf_header = { 7F 45 4C 46 }
        $packed = "/proc/self/exe"
        $memfd = "memfd_create"
        $anti_debug = "ptrace"
    condition:
        $elf_header at 0 and (2 of ($packed, $memfd, $anti_debug))
}
"#;

/// Default YARA rule: crypto miner detection.
pub const YARA_RULE_CRYPTO_MINER: &str = r#"
rule crypto_miner {
    meta:
        description = "Detects cryptocurrency mining software"
        severity = "medium"
    strings:
        $stratum = "stratum+tcp://"
        $pool = "mining pool"
        $xmrig = "xmrig"
        $hashrate = "hashrate"
        $wallet = /[0-9a-zA-Z]{95}/
    condition:
        2 of them
}
"#;

/// Default YARA rule: webshell detection.
pub const YARA_RULE_WEBSHELL: &str = r#"
rule webshell {
    meta:
        description = "Detects common webshell patterns in scripts"
        severity = "critical"
    strings:
        $eval_base64 = /eval\s*\(\s*base64_decode/
        $system_call = /system\s*\(\s*\$_(GET|POST|REQUEST)/
        $passthru = "passthru"
        $shell_exec = "shell_exec"
        $cmd_exec = /exec\s*\(\s*\$/
    condition:
        2 of them
}
"#;

/// Default YARA rule: backdoor detection.
pub const YARA_RULE_BACKDOOR: &str = r#"
rule linux_backdoor {
    meta:
        description = "Detects common Linux backdoor indicators"
        severity = "critical"
    strings:
        $bind_shell = { 6A 02 5F 6A 01 5E 6A 06 }
        $reverse_shell = "/bin/sh -i"
        $nc_backdoor = "nc -e /bin/"
        $socat = "socat exec:"
        $hidden_service = ".hidden"
    condition:
        any of them
}
"#;

// ─── Types ─────────────────────────────────────────────────────────────────

/// Which scan engine produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanEngineType {
    /// ClamAV signature-based detection.
    ClamAv,
    /// YARA rule-based detection.
    Yara,
}

/// Scope of a scan request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanScope {
    /// Full system scan.
    Full,
    /// Home directory scan.
    Home,
    /// Custom paths to scan.
    Custom(Vec<PathBuf>),
}

/// A request to perform a malware scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Unique identifier for this scan request.
    pub id: Uuid,
    /// Scope of the scan.
    pub scope: ScanScope,
    /// Which engines to use for scanning.
    pub engines: Vec<ScanEngineType>,
    /// When the scan was requested.
    pub requested_at: DateTime<Utc>,
}

/// A finding from a malware scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanFinding {
    /// Path to the infected/suspicious file.
    pub file_path: PathBuf,
    /// Name of the detected threat.
    pub threat_name: String,
    /// Which engine detected this threat.
    pub engine: ScanEngineType,
    /// Severity of the finding.
    pub severity: FindingSeverity,
    /// Recommended action for this finding.
    pub recommended_action: RecommendedAction,
}

/// Severity level for scan findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Recommended action for a scan finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    /// Quarantine the file.
    Quarantine,
    /// Delete the file.
    Delete,
    /// Review manually.
    Review,
    /// Ignore (false positive).
    Ignore,
}

/// Progress information for an ongoing scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanProgress {
    /// Name of the tool currently scanning.
    pub tool_name: String,
    /// Percentage complete (0-100).
    pub percentage: u8,
    /// Estimated remaining time in seconds.
    pub estimated_remaining_secs: Option<u64>,
}

/// Frequency for scheduled scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanFrequency {
    Daily,
    Weekly,
}

/// A scheduled scan configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledScan {
    /// Unique identifier for this schedule.
    pub id: Uuid,
    /// How often to run the scan.
    pub frequency: ScanFrequency,
    /// Directories to scan.
    pub target_dirs: Vec<PathBuf>,
    /// When the last scan was run.
    pub last_run: Option<DateTime<Utc>>,
    /// When the next scan is scheduled.
    pub next_run: DateTime<Utc>,
}

/// Coordinates ClamAV and YARA scans in parallel.
pub struct ScanEngine {
    /// Whether ClamAV is available.
    pub clamav_available: bool,
    /// Whether YARA is available.
    pub yara_available: bool,
}

impl ScanEngine {
    /// Creates a new scan engine instance.
    pub fn new() -> Self {
        Self {
            clamav_available: false,
            yara_available: false,
        }
    }

    /// Checks availability of both scan engines.
    pub async fn check_availability(&mut self) -> Result<()> {
        let mut cmd = SafeCommand::new("which");
        cmd.arg("clamscan")?;
        cmd.timeout(Duration::from_secs(5));
        self.clamav_available = cmd.execute().await.map(|o| o.exit_code == Some(0)).unwrap_or(false);

        let mut cmd = SafeCommand::new("which");
        cmd.arg("yara")?;
        cmd.timeout(Duration::from_secs(5));
        self.yara_available = cmd.execute().await.map(|o| o.exit_code == Some(0)).unwrap_or(false);

        Ok(())
    }

    /// Returns the paths to scan based on the scope.
    pub fn resolve_paths(scope: &ScanScope) -> Vec<PathBuf> {
        match scope {
            ScanScope::Full => vec![PathBuf::from("/")],
            ScanScope::Home => {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/home".to_string());
                vec![PathBuf::from(home)]
            }
            ScanScope::Custom(paths) => paths.clone(),
        }
    }
}

impl Default for ScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ClamAvAdapter ─────────────────────────────────────────────────────────

/// Adapter for ClamAV antivirus + YARA rule engine.
pub struct ClamAvAdapter;

#[async_trait]
impl ToolAdapter for ClamAvAdapter {
    fn name(&self) -> &str {
        "clamav"
    }

    fn display_name(&self) -> &str {
        "ClamAV + YARA"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Detection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let (clamav_pkg, yara_pkg) = match distro.package_manager {
            PackageManager::Apt => ("clamav", "yara"),
            PackageManager::Dnf => ("clamav", "yara"),
            PackageManager::Pacman => ("clamav", "yara"),
            PackageManager::Zypper => ("clamav", "yara"),
        };

        info!(clamav = clamav_pkg, yara = yara_pkg, distro = %distro.id, "Installing ClamAV + YARA");

        // Install ClamAV
        let install_args: Vec<&str> = match distro.package_manager {
            PackageManager::Apt => vec!["apt-get", "install", "-y", clamav_pkg, yara_pkg],
            PackageManager::Dnf => vec!["dnf", "install", "-y", clamav_pkg, yara_pkg],
            PackageManager::Pacman => vec!["pacman", "-S", "--noconfirm", clamav_pkg, yara_pkg],
            PackageManager::Zypper => vec!["zypper", "install", "-y", clamav_pkg, yara_pkg],
        };

        let mut cmd = SafeCommand::new(install_args[0]);
        cmd.args(&install_args[1..])?;
        cmd.timeout(Duration::from_secs(180));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "clamav".to_string(),
                reason: format!("package install failed: {}", output.stderr),
            });
        }

        // Run freshclam for initial signature update
        info!("Running freshclam for initial signature update");
        let mut cmd = SafeCommand::new("freshclam");
        cmd.timeout(Duration::from_secs(300));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            warn!(stderr = %output.stderr, "freshclam returned non-zero (signatures may still be usable)");
        }

        info!("ClamAV + YARA installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["start", "clamav-daemon"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "clamav".to_string(),
                reason: format!("failed to start clamd: {}", output.stderr),
            });
        }

        info!("clamd service started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["stop", "clamav-daemon"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "clamav".to_string(),
                reason: format!("failed to stop clamd: {}", output.stderr),
            });
        }

        info!("clamd service stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("systemctl");
        if cmd.args(&["is-active", "clamav-daemon"]).is_err() {
            return HealthStatus::Unhealthy("failed to build health check command".to_string());
        }
        cmd.timeout(Duration::from_secs(10));

        match cmd.execute().await {
            Ok(output) => {
                let status = output.stdout.trim().to_string();
                match status.as_str() {
                    "active" => HealthStatus::Healthy,
                    "inactive" | "dead" => HealthStatus::NotRunning,
                    _ => HealthStatus::Degraded(format!("clamd status: {}", status)),
                }
            }
            Err(e) => HealthStatus::Unhealthy(format!("health check failed: {}", e)),
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // ~200 MB with signatures
        200_000_000
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = ClamAvAdapter;
        assert_eq!(adapter.name(), "clamav");
        assert_eq!(adapter.display_name(), "ClamAV + YARA");
        assert_eq!(adapter.category(), ToolCategory::Detection);
    }

    #[test]
    fn test_adapter_available_for_all_distros() {
        let adapter = ClamAvAdapter;
        let distro = DistroInfo {
            id: "ubuntu".to_string(),
            version_id: "22.04".to_string(),
            name: "Ubuntu".to_string(),
            package_manager: PackageManager::Apt,
            has_btrfs: false,
            kernel_version: (6, 5),
            has_ebpf: true,
            mac_framework: shared::distro::MACFramework::AppArmor,
        };
        assert!(adapter.is_available_for(&distro));
    }

    #[test]
    fn test_scan_request_creation() {
        let request = ScanRequest {
            id: Uuid::new_v4(),
            scope: ScanScope::Home,
            engines: vec![ScanEngineType::ClamAv, ScanEngineType::Yara],
            requested_at: Utc::now(),
        };
        assert_eq!(request.engines.len(), 2);
        assert_eq!(request.scope, ScanScope::Home);
    }

    #[test]
    fn test_scan_finding_creation() {
        let finding = ScanFinding {
            file_path: PathBuf::from("/tmp/malware.bin"),
            threat_name: "Trojan.Linux.Generic".to_string(),
            engine: ScanEngineType::ClamAv,
            severity: FindingSeverity::Critical,
            recommended_action: RecommendedAction::Quarantine,
        };
        assert_eq!(finding.engine, ScanEngineType::ClamAv);
        assert_eq!(finding.severity, FindingSeverity::Critical);
    }

    #[test]
    fn test_scan_engine_resolve_paths_full() {
        let paths = ScanEngine::resolve_paths(&ScanScope::Full);
        assert_eq!(paths, vec![PathBuf::from("/")]);
    }

    #[test]
    fn test_scan_engine_resolve_paths_custom() {
        let custom = vec![PathBuf::from("/opt"), PathBuf::from("/var/www")];
        let paths = ScanEngine::resolve_paths(&ScanScope::Custom(custom.clone()));
        assert_eq!(paths, custom);
    }

    #[test]
    fn test_scheduled_scan_creation() {
        let scan = ScheduledScan {
            id: Uuid::new_v4(),
            frequency: ScanFrequency::Daily,
            target_dirs: vec![PathBuf::from("/home")],
            last_run: None,
            next_run: Utc::now(),
        };
        assert_eq!(scan.frequency, ScanFrequency::Daily);
        assert!(scan.last_run.is_none());
    }

    #[test]
    fn test_yara_rules_not_empty() {
        assert!(!YARA_RULE_ELF_MALWARE.is_empty());
        assert!(!YARA_RULE_CRYPTO_MINER.is_empty());
        assert!(!YARA_RULE_WEBSHELL.is_empty());
        assert!(!YARA_RULE_BACKDOOR.is_empty());
    }

    #[test]
    fn test_scan_progress_creation() {
        let progress = ScanProgress {
            tool_name: "clamav".to_string(),
            percentage: 45,
            estimated_remaining_secs: Some(120),
        };
        assert_eq!(progress.percentage, 45);
        assert_eq!(progress.estimated_remaining_secs, Some(120));
    }

    #[test]
    fn test_estimated_size() {
        let adapter = ClamAvAdapter;
        assert!(adapter.estimated_size_bytes() > 0);
    }
}
