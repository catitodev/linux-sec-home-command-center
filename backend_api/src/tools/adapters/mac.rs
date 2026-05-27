// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Mandatory Access Control (AppArmor/SELinux) adapter for the Linux Security
//! Home Command Center.
//!
//! Detects which MAC framework is active on the system and provides a unified
//! interface for profile management, enforcement status, and violation tracking.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use shared::distro::{adapter_for, DistroInfo, MACFramework};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Enums ─────────────────────────────────────────────────────────────────

/// Status of a MAC profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileStatus {
    /// Profile is enforcing (blocking violations).
    Enforcing,
    /// Profile is in complain/permissive mode (logging but not blocking).
    Complaining,
    /// Profile is disabled.
    Disabled,
}

/// Detected MAC framework on the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectedFramework {
    /// AppArmor is active.
    AppArmor,
    /// SELinux is active.
    SELinux,
    /// No MAC framework detected.
    None,
}

// ─── Structs ───────────────────────────────────────────────────────────────

/// Detects which MAC framework is active on the system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MACFrameworkDetector {
    /// The detected framework.
    pub framework: DetectedFramework,
}

impl MACFrameworkDetector {
    /// Detects the active MAC framework by checking system state.
    pub async fn detect() -> Self {
        // Check AppArmor first
        let mut cmd = SafeCommand::new("aa-status");
        cmd.timeout(Duration::from_secs(5));
        if let Ok(output) = cmd.execute().await {
            if output.exit_code == Some(0) {
                return Self {
                    framework: DetectedFramework::AppArmor,
                };
            }
        }

        // Check SELinux
        let mut cmd = SafeCommand::new("getenforce");
        cmd.timeout(Duration::from_secs(5));
        if let Ok(output) = cmd.execute().await {
            if output.exit_code == Some(0) {
                let status = output.stdout.trim().to_lowercase();
                if status == "enforcing" || status == "permissive" {
                    return Self {
                        framework: DetectedFramework::SELinux,
                    };
                }
            }
        }

        Self {
            framework: DetectedFramework::None,
        }
    }

    /// Creates a detector from a known distro's MAC framework.
    pub fn from_distro(distro: &DistroInfo) -> Self {
        let framework = match distro.mac_framework {
            MACFramework::AppArmor => DetectedFramework::AppArmor,
            MACFramework::SELinux => DetectedFramework::SELinux,
            MACFramework::None => DetectedFramework::None,
        };
        Self { framework }
    }
}

/// A MAC profile with its current status and violation count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MACProfile {
    /// Profile name (e.g., "/usr/bin/firefox" for AppArmor, "httpd_t" for SELinux).
    pub name: String,
    /// Current enforcement status.
    pub status: ProfileStatus,
    /// Number of violations recorded for this profile.
    pub violations_count: u64,
}

/// Manages MAC profiles (AppArmor or SELinux).
#[derive(Debug)]
pub struct MACManager {
    /// The detected framework this manager operates on.
    framework: DetectedFramework,
}

impl MACManager {
    /// Creates a new `MACManager` for the given framework.
    pub fn new(framework: DetectedFramework) -> Self {
        Self { framework }
    }

    /// Lists all MAC profiles and their status.
    pub async fn list_profiles(&self) -> Result<Vec<MACProfile>> {
        match self.framework {
            DetectedFramework::AppArmor => self.list_apparmor_profiles().await,
            DetectedFramework::SELinux => self.list_selinux_profiles().await,
            DetectedFramework::None => Ok(Vec::new()),
        }
    }

    /// Gets the status of a specific profile.
    pub async fn get_profile_status(&self, name: &str) -> Result<ProfileStatus> {
        let profiles = self.list_profiles().await?;
        profiles
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.status)
            .ok_or_else(|| CommandCenterError::Internal(format!(
                "profile '{}' not found", name
            )))
    }

    /// Sets a profile to enforcing mode.
    pub async fn enforce_profile(&self, name: &str) -> Result<()> {
        match self.framework {
            DetectedFramework::AppArmor => {
                let mut cmd = SafeCommand::new("aa-enforce");
                cmd.arg(name)?;
                cmd.timeout(Duration::from_secs(15));

                let output = cmd.execute().await?;
                if output.exit_code != Some(0) {
                    return Err(CommandCenterError::ToolOperationFailed {
                        tool: "apparmor".to_owned(),
                        reason: format!("failed to enforce profile: {}", output.stderr.trim()),
                    });
                }
            }
            DetectedFramework::SELinux => {
                let mut cmd = SafeCommand::new("semanage");
                cmd.args(&["permissive", "-d", name])?;
                cmd.timeout(Duration::from_secs(15));

                let output = cmd.execute().await?;
                if output.exit_code != Some(0) {
                    return Err(CommandCenterError::ToolOperationFailed {
                        tool: "selinux".to_owned(),
                        reason: format!("failed to enforce profile: {}", output.stderr.trim()),
                    });
                }
            }
            DetectedFramework::None => {
                return Err(CommandCenterError::ToolNotAvailable {
                    tool: "mac".to_owned(),
                });
            }
        }

        info!(profile = %name, framework = ?self.framework, "Profile set to enforcing");
        Ok(())
    }

    /// Gets recent violations for the MAC framework.
    pub async fn get_violations(&self) -> Result<Vec<String>> {
        match self.framework {
            DetectedFramework::AppArmor => {
                let mut cmd = SafeCommand::new("aa-logprof");
                cmd.args(&["-d", "/var/log/audit/"])?;
                cmd.timeout(Duration::from_secs(10));

                // In production, parse audit log for AppArmor denials
                Ok(Vec::new())
            }
            DetectedFramework::SELinux => {
                let mut cmd = SafeCommand::new("ausearch");
                cmd.args(&["-m", "AVC", "--raw"])?;
                cmd.timeout(Duration::from_secs(10));

                let output = cmd.execute().await?;
                let violations: Vec<String> = output
                    .stdout
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| l.to_owned())
                    .collect();
                Ok(violations)
            }
            DetectedFramework::None => Ok(Vec::new()),
        }
    }

    /// Lists AppArmor profiles via aa-status.
    async fn list_apparmor_profiles(&self) -> Result<Vec<MACProfile>> {
        let mut cmd = SafeCommand::new("aa-status");
        cmd.args(&["--json"])?;
        cmd.timeout(Duration::from_secs(10));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "apparmor".to_owned(),
                reason: format!("aa-status failed: {}", output.stderr.trim()),
            });
        }

        // Parse aa-status JSON output in production
        Ok(Vec::new())
    }

    /// Lists SELinux profiles via semanage.
    async fn list_selinux_profiles(&self) -> Result<Vec<MACProfile>> {
        let mut cmd = SafeCommand::new("semanage");
        cmd.args(&["boolean", "-l"])?;
        cmd.timeout(Duration::from_secs(10));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "selinux".to_owned(),
                reason: format!("semanage failed: {}", output.stderr.trim()),
            });
        }

        // Parse semanage output in production
        Ok(Vec::new())
    }
}

// ─── MACAdapter ────────────────────────────────────────────────────────────

/// Tool adapter for Mandatory Access Control (AppArmor/SELinux).
///
/// Detects the active MAC framework and provides unified profile management.
/// MAC is always active if installed, so start is a no-op.
pub struct MACAdapter;

impl MACAdapter {
    /// Creates a new `MACAdapter`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for MACAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolAdapter for MACAdapter {
    fn name(&self) -> &str {
        "apparmor"
    }

    fn display_name(&self) -> &str {
        "AppArmor/SELinux"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Protection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        // Detect which MAC framework is appropriate for this distro
        let detector = MACFrameworkDetector::from_distro(distro);

        match detector.framework {
            DetectedFramework::AppArmor => {
                let distro_adapter = adapter_for(distro.package_manager);
                let package_name = distro_adapter
                    .map_tool_package("apparmor")
                    .ok_or_else(|| CommandCenterError::ToolNotAvailable {
                        tool: "apparmor".to_owned(),
                    })?;

                info!(package = %package_name, "Installing AppArmor utilities");
                distro_adapter.install_package(&package_name)?;
                info!("AppArmor utilities installed");
            }
            DetectedFramework::SELinux => {
                info!("SELinux is the native MAC framework for this distro — already installed");
            }
            DetectedFramework::None => {
                warn!("No MAC framework detected for this distribution");
                return Err(CommandCenterError::ToolNotAvailable {
                    tool: "mac".to_owned(),
                });
            }
        }

        Ok(())
    }

    async fn start(&self) -> Result<()> {
        // MAC is always active if installed — start is a no-op.
        info!("MAC framework is always active if installed; no action needed");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        // Stopping MAC is dangerous and generally not recommended.
        warn!("Stopping MAC framework is not recommended; no action taken");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        // Try AppArmor first
        let mut cmd = SafeCommand::new("aa-status");
        cmd.timeout(Duration::from_secs(5));
        if let Ok(output) = cmd.execute().await {
            if output.exit_code == Some(0) {
                return HealthStatus::Healthy;
            }
        }

        // Try SELinux
        let mut cmd = SafeCommand::new("getenforce");
        cmd.timeout(Duration::from_secs(5));
        if let Ok(output) = cmd.execute().await {
            if output.exit_code == Some(0) {
                let status = output.stdout.trim().to_lowercase();
                return match status.as_str() {
                    "enforcing" => HealthStatus::Healthy,
                    "permissive" => HealthStatus::Degraded("SELinux in permissive mode".to_owned()),
                    "disabled" => HealthStatus::NotRunning,
                    _ => HealthStatus::Degraded(format!("unknown SELinux status: {}", status)),
                };
            }
        }

        HealthStatus::NotRunning
    }

    fn is_available_for(&self, distro: &DistroInfo) -> bool {
        // MAC is available for all distros except those with no framework
        distro.mac_framework != MACFramework::None
    }

    fn estimated_size_bytes(&self) -> u64 {
        // AppArmor/SELinux utilities approximately 5 MB.
        5 * 1024 * 1024
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = MACAdapter::new();
        assert_eq!(adapter.name(), "apparmor");
    }

    #[test]
    fn test_adapter_display_name() {
        let adapter = MACAdapter::new();
        assert_eq!(adapter.display_name(), "AppArmor/SELinux");
    }

    #[test]
    fn test_adapter_category() {
        let adapter = MACAdapter::new();
        assert_eq!(adapter.category(), ToolCategory::Protection);
    }

    #[test]
    fn test_adapter_available_for_ubuntu() {
        let adapter = MACAdapter::new();
        let ubuntu = shared::distro::detect_distro_from_content(
            "ID=ubuntu\nVERSION_ID=\"22.04\"\nNAME=\"Ubuntu\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&ubuntu));
    }

    #[test]
    fn test_adapter_available_for_fedora() {
        let adapter = MACAdapter::new();
        let fedora = shared::distro::detect_distro_from_content(
            "ID=fedora\nVERSION_ID=39\nNAME=\"Fedora\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&fedora));
    }

    #[test]
    fn test_adapter_not_available_for_arch() {
        let adapter = MACAdapter::new();
        let arch = shared::distro::detect_distro_from_content(
            "ID=arch\nNAME=\"Arch Linux\"\n",
        )
        .unwrap();
        // Arch doesn't ship with a MAC framework by default
        assert!(!adapter.is_available_for(&arch));
    }

    #[test]
    fn test_adapter_estimated_size() {
        let adapter = MACAdapter::new();
        assert!(adapter.estimated_size_bytes() > 0);
    }

    #[test]
    fn test_mac_framework_detector_from_ubuntu() {
        let ubuntu = shared::distro::detect_distro_from_content(
            "ID=ubuntu\nVERSION_ID=\"22.04\"\nNAME=\"Ubuntu\"\n",
        )
        .unwrap();
        let detector = MACFrameworkDetector::from_distro(&ubuntu);
        assert_eq!(detector.framework, DetectedFramework::AppArmor);
    }

    #[test]
    fn test_mac_framework_detector_from_fedora() {
        let fedora = shared::distro::detect_distro_from_content(
            "ID=fedora\nVERSION_ID=39\nNAME=\"Fedora\"\n",
        )
        .unwrap();
        let detector = MACFrameworkDetector::from_distro(&fedora);
        assert_eq!(detector.framework, DetectedFramework::SELinux);
    }

    #[test]
    fn test_mac_framework_detector_from_arch() {
        let arch = shared::distro::detect_distro_from_content(
            "ID=arch\nNAME=\"Arch Linux\"\n",
        )
        .unwrap();
        let detector = MACFrameworkDetector::from_distro(&arch);
        assert_eq!(detector.framework, DetectedFramework::None);
    }

    #[test]
    fn test_mac_profile_serialization() {
        let profile = MACProfile {
            name: "/usr/bin/firefox".to_owned(),
            status: ProfileStatus::Enforcing,
            violations_count: 5,
        };

        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: MACProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, deserialized);
    }

    #[test]
    fn test_profile_status_variants() {
        let statuses = [
            ProfileStatus::Enforcing,
            ProfileStatus::Complaining,
            ProfileStatus::Disabled,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: ProfileStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, deserialized);
        }
    }

    #[test]
    fn test_detected_framework_serialization() {
        let frameworks = [
            DetectedFramework::AppArmor,
            DetectedFramework::SELinux,
            DetectedFramework::None,
        ];
        for fw in &frameworks {
            let json = serde_json::to_string(fw).unwrap();
            let deserialized: DetectedFramework = serde_json::from_str(&json).unwrap();
            assert_eq!(*fw, deserialized);
        }
    }

    #[test]
    fn test_mac_framework_detector_serialization() {
        let detector = MACFrameworkDetector {
            framework: DetectedFramework::AppArmor,
        };
        let json = serde_json::to_string(&detector).unwrap();
        let deserialized: MACFrameworkDetector = serde_json::from_str(&json).unwrap();
        assert_eq!(detector, deserialized);
    }
}
