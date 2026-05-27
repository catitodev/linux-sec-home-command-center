// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Firejail adapter for the Linux Security Home Command Center.
//!
//! Provides application sandboxing through Firejail with pre-built profiles
//! for common desktop applications. Firejail is per-application (not a service),
//! so start/stop are no-ops.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::info;

use shared::distro::{adapter_for, DistroInfo};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Default applications that have pre-built sandbox profiles.
pub const DEFAULT_SANDBOXED_APPS: &[&str] = &[
    "firefox",
    "chromium",
    "thunderbird",
    "libreoffice",
    "evince",
];

// ─── Enums ─────────────────────────────────────────────────────────────────

/// Filesystem restriction level for a sandbox profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemRestriction {
    /// Read-only access to most of the filesystem.
    ReadOnly,
    /// Private home directory (tmpfs overlay).
    PrivateHome,
    /// No access to home directory.
    NoHome,
    /// Full filesystem access (no restriction).
    None,
}

/// Network restriction level for a sandbox profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkRestriction {
    /// No network access.
    NoNetwork,
    /// Network access through a separate namespace.
    Namespace,
    /// Full network access (no restriction).
    None,
}

/// D-Bus restriction level for a sandbox profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbusRestriction {
    /// No D-Bus access.
    NoDbus,
    /// Filtered D-Bus access (specific interfaces only).
    Filtered,
    /// Full D-Bus access (no restriction).
    None,
}

// ─── Structs ───────────────────────────────────────────────────────────────

/// Restrictions applied to a sandboxed application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRestrictions {
    /// Filesystem access restriction.
    pub filesystem: FilesystemRestriction,
    /// Network access restriction.
    pub network: NetworkRestriction,
    /// D-Bus access restriction.
    pub dbus: DbusRestriction,
}

impl SandboxRestrictions {
    /// Creates default restrictions (private home, namespace network, filtered dbus).
    pub fn default_desktop() -> Self {
        Self {
            filesystem: FilesystemRestriction::PrivateHome,
            network: NetworkRestriction::Namespace,
            dbus: DbusRestriction::Filtered,
        }
    }

    /// Creates strict restrictions (read-only fs, no network, no dbus).
    pub fn strict() -> Self {
        Self {
            filesystem: FilesystemRestriction::ReadOnly,
            network: NetworkRestriction::NoNetwork,
            dbus: DbusRestriction::NoDbus,
        }
    }
}

/// A sandbox profile for an application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProfile {
    /// Application name (e.g., "firefox").
    pub app_name: String,
    /// Restrictions applied to this application.
    pub restrictions: SandboxRestrictions,
    /// Whether this sandbox profile is currently active.
    pub active: bool,
}

impl SandboxProfile {
    /// Creates a new sandbox profile with default desktop restrictions.
    pub fn new_default(app_name: &str) -> Self {
        Self {
            app_name: app_name.to_owned(),
            restrictions: SandboxRestrictions::default_desktop(),
            active: false,
        }
    }
}

/// Manages Firejail sandbox profiles for applications.
#[derive(Debug)]
pub struct SandboxManager;

impl SandboxManager {
    /// Creates a new `SandboxManager`.
    pub fn new() -> Self {
        Self
    }

    /// Lists all applications with sandbox profiles.
    pub async fn list_sandboxed_apps(&self) -> Result<Vec<SandboxProfile>> {
        let mut cmd = SafeCommand::new("firejail");
        cmd.args(&["--list"])?;
        cmd.timeout(Duration::from_secs(10));

        let output = cmd.execute().await?;
        // Parse running sandboxed applications
        let profiles: Vec<SandboxProfile> = DEFAULT_SANDBOXED_APPS
            .iter()
            .map(|app| {
                let active = output.exit_code == Some(0)
                    && output.stdout.contains(app);
                SandboxProfile {
                    app_name: app.to_string(),
                    restrictions: SandboxRestrictions::default_desktop(),
                    active,
                }
            })
            .collect();

        Ok(profiles)
    }

    /// Enables sandboxing for an application by creating a symlink.
    pub async fn enable_sandbox(&self, app_name: &str) -> Result<()> {
        // Firejail uses symlinks in /usr/local/bin to intercept application launches
        let mut cmd = SafeCommand::new("firecfg");
        cmd.args(&["--add", app_name])?;
        cmd.timeout(Duration::from_secs(15));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "firejail".to_owned(),
                reason: format!("failed to enable sandbox for {}: {}", app_name, output.stderr.trim()),
            });
        }

        info!(app = %app_name, "Sandbox enabled");
        Ok(())
    }

    /// Disables sandboxing for an application.
    pub async fn disable_sandbox(&self, app_name: &str) -> Result<()> {
        let mut cmd = SafeCommand::new("firecfg");
        cmd.args(&["--remove", app_name])?;
        cmd.timeout(Duration::from_secs(15));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "firejail".to_owned(),
                reason: format!("failed to disable sandbox for {}: {}", app_name, output.stderr.trim()),
            });
        }

        info!(app = %app_name, "Sandbox disabled");
        Ok(())
    }

    /// Gets security violations for sandboxed applications.
    pub async fn get_violations(&self) -> Result<Vec<String>> {
        let mut cmd = SafeCommand::new("firejail");
        cmd.args(&["--audit"])?;
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
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── FirejailAdapter ───────────────────────────────────────────────────────

/// Tool adapter for Firejail application sandboxing.
///
/// Firejail provides lightweight sandboxing for desktop applications using
/// Linux namespaces and seccomp-bpf. It is per-application, not a system service.
pub struct FirejailAdapter;

impl FirejailAdapter {
    /// Creates a new `FirejailAdapter`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for FirejailAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolAdapter for FirejailAdapter {
    fn name(&self) -> &str {
        "firejail"
    }

    fn display_name(&self) -> &str {
        "Firejail"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Protection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let distro_adapter = adapter_for(distro.package_manager);
        let package_name = distro_adapter
            .map_tool_package("firejail")
            .ok_or_else(|| CommandCenterError::ToolNotAvailable {
                tool: "firejail".to_owned(),
            })?;

        info!(package = %package_name, distro = %distro.id, "Installing Firejail");
        distro_adapter.install_package(&package_name)?;
        info!("Firejail installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        // Firejail is per-application, not a service — start is a no-op.
        info!("Firejail is per-application; no service to start");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        // Firejail is per-application, not a service — stop is a no-op.
        info!("Firejail is per-application; no service to stop");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("firejail");
        if cmd.arg("--version").is_err() {
            return HealthStatus::Unhealthy("failed to build health check command".to_owned());
        }
        cmd.timeout(Duration::from_secs(5));

        match cmd.execute().await {
            Ok(output) => {
                if output.exit_code == Some(0) {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Degraded(format!(
                        "firejail --version exited with code {:?}",
                        output.exit_code
                    ))
                }
            }
            Err(e) => HealthStatus::Unhealthy(format!("firejail not available: {}", e)),
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        // Firejail is available for all supported distributions.
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // Firejail approximately 3 MB.
        3 * 1024 * 1024
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = FirejailAdapter::new();
        assert_eq!(adapter.name(), "firejail");
    }

    #[test]
    fn test_adapter_display_name() {
        let adapter = FirejailAdapter::new();
        assert_eq!(adapter.display_name(), "Firejail");
    }

    #[test]
    fn test_adapter_category() {
        let adapter = FirejailAdapter::new();
        assert_eq!(adapter.category(), ToolCategory::Protection);
    }

    #[test]
    fn test_adapter_is_available_for_all_distros() {
        let adapter = FirejailAdapter::new();

        let ubuntu = shared::distro::detect_distro_from_content(
            "ID=ubuntu\nVERSION_ID=\"22.04\"\nNAME=\"Ubuntu\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&ubuntu));

        let fedora = shared::distro::detect_distro_from_content(
            "ID=fedora\nVERSION_ID=39\nNAME=\"Fedora\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&fedora));
    }

    #[test]
    fn test_adapter_estimated_size() {
        let adapter = FirejailAdapter::new();
        assert!(adapter.estimated_size_bytes() > 0);
    }

    #[test]
    fn test_sandbox_profile_new_default() {
        let profile = SandboxProfile::new_default("firefox");
        assert_eq!(profile.app_name, "firefox");
        assert!(!profile.active);
        assert_eq!(profile.restrictions.filesystem, FilesystemRestriction::PrivateHome);
        assert_eq!(profile.restrictions.network, NetworkRestriction::Namespace);
        assert_eq!(profile.restrictions.dbus, DbusRestriction::Filtered);
    }

    #[test]
    fn test_sandbox_restrictions_strict() {
        let restrictions = SandboxRestrictions::strict();
        assert_eq!(restrictions.filesystem, FilesystemRestriction::ReadOnly);
        assert_eq!(restrictions.network, NetworkRestriction::NoNetwork);
        assert_eq!(restrictions.dbus, DbusRestriction::NoDbus);
    }

    #[test]
    fn test_sandbox_profile_serialization() {
        let profile = SandboxProfile {
            app_name: "chromium".to_owned(),
            restrictions: SandboxRestrictions::default_desktop(),
            active: true,
        };

        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: SandboxProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, deserialized);
    }

    #[test]
    fn test_sandbox_restrictions_serialization() {
        let restrictions = SandboxRestrictions {
            filesystem: FilesystemRestriction::NoHome,
            network: NetworkRestriction::NoNetwork,
            dbus: DbusRestriction::NoDbus,
        };

        let json = serde_json::to_string(&restrictions).unwrap();
        let deserialized: SandboxRestrictions = serde_json::from_str(&json).unwrap();
        assert_eq!(restrictions, deserialized);
    }

    #[test]
    fn test_default_sandboxed_apps_list() {
        assert!(DEFAULT_SANDBOXED_APPS.contains(&"firefox"));
        assert!(DEFAULT_SANDBOXED_APPS.contains(&"chromium"));
        assert!(DEFAULT_SANDBOXED_APPS.contains(&"thunderbird"));
        assert!(DEFAULT_SANDBOXED_APPS.contains(&"libreoffice"));
        assert!(DEFAULT_SANDBOXED_APPS.contains(&"evince"));
        assert_eq!(DEFAULT_SANDBOXED_APPS.len(), 5);
    }

    #[test]
    fn test_filesystem_restriction_variants() {
        let variants = [
            FilesystemRestriction::ReadOnly,
            FilesystemRestriction::PrivateHome,
            FilesystemRestriction::NoHome,
            FilesystemRestriction::None,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let deserialized: FilesystemRestriction = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, deserialized);
        }
    }

    #[test]
    fn test_network_restriction_variants() {
        let variants = [
            NetworkRestriction::NoNetwork,
            NetworkRestriction::Namespace,
            NetworkRestriction::None,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let deserialized: NetworkRestriction = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, deserialized);
        }
    }
}
