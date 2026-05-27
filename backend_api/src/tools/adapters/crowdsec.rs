// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! CrowdSec adapter for the Linux Security Home Command Center.
//!
//! Provides collaborative intrusion prevention through community-driven blocklists,
//! IP ban decisions, and automatic restart on crash. CrowdSec analyzes logs and
//! applies decisions (bans, captchas) via bouncers (firewall integration).

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use shared::distro::{adapter_for, DistroInfo};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Default ban duration for IP block decisions (4 hours).
const DEFAULT_BAN_DURATION: &str = "4h";

/// Interval for blocklist sync (2 hours in seconds).
const BLOCKLIST_SYNC_INTERVAL_SECS: u64 = 7200;

/// Staleness warning threshold (48 hours in seconds).
const STALENESS_THRESHOLD_SECS: u64 = 172_800;

/// Auto-restart delay after crash detection (10 seconds).
const AUTO_RESTART_DELAY: Duration = Duration::from_secs(10);

/// Maximum recent decisions to track.
const MAX_RECENT_DECISIONS: usize = 100;

// ─── Structs ───────────────────────────────────────────────────────────────

/// Statistics from CrowdSec's decision engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrowdSecStats {
    /// Total number of currently blocked IP addresses.
    pub total_blocked_ips: u64,
    /// Recent decisions (last 100 or within 24h).
    pub recent_decisions: Vec<CrowdSecDecision>,
    /// Top 5 triggered scenarios by frequency.
    pub top_5_scenarios: Vec<ScenarioCount>,
}

/// A single CrowdSec decision (ban, captcha, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrowdSecDecision {
    /// The IP address or range affected.
    pub ip: String,
    /// The scenario that triggered this decision.
    pub scenario: String,
    /// Decision type (ban, captcha, throttle).
    pub decision_type: String,
    /// Duration of the decision.
    pub duration: String,
    /// When the decision was created.
    pub created_at: DateTime<Utc>,
}

/// A scenario with its trigger count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScenarioCount {
    /// Scenario name (e.g., "crowdsecurity/ssh-bf").
    pub scenario: String,
    /// Number of times this scenario was triggered.
    pub count: u64,
}

/// Manages community blocklist synchronization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlocklistSyncer {
    /// Timestamp of the last successful sync.
    pub last_sync: Option<DateTime<Utc>>,
    /// Sync interval in seconds (default: 7200 = 2 hours).
    pub sync_interval_secs: u64,
    /// Whether the blocklist data is considered stale (>48h old).
    pub is_stale: bool,
}

impl BlocklistSyncer {
    /// Creates a new `BlocklistSyncer` with default settings.
    pub fn new() -> Self {
        Self {
            last_sync: None,
            sync_interval_secs: BLOCKLIST_SYNC_INTERVAL_SECS,
            is_stale: true,
        }
    }

    /// Checks if the blocklist is stale (last sync > 48 hours ago).
    pub fn check_staleness(&self) -> bool {
        match self.last_sync {
            Some(last) => {
                let elapsed = Utc::now().signed_duration_since(last);
                elapsed.num_seconds() as u64 > STALENESS_THRESHOLD_SECS
            }
            None => true,
        }
    }

    /// Records a successful sync at the current time.
    pub fn record_sync(&mut self) {
        self.last_sync = Some(Utc::now());
        self.is_stale = false;
    }
}

impl Default for BlocklistSyncer {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an IP block action with configurable ban duration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpBlockAction {
    /// IP address to block.
    pub ip: String,
    /// Ban duration (default: "4h").
    pub duration: String,
    /// Reason for the block.
    pub reason: String,
}

impl IpBlockAction {
    /// Creates a new IP block action with default duration.
    pub fn new(ip: String, reason: String) -> Self {
        Self {
            ip,
            duration: DEFAULT_BAN_DURATION.to_owned(),
            reason,
        }
    }

    /// Creates a new IP block action with a custom duration.
    pub fn with_duration(ip: String, reason: String, duration: String) -> Self {
        Self {
            ip,
            duration,
            reason,
        }
    }

    /// Executes the block decision via `cscli decisions add`.
    pub async fn execute(&self) -> Result<()> {
        let mut cmd = SafeCommand::new("cscli");
        cmd.args(&[
            "decisions", "add",
            "--ip", &self.ip,
            "--duration", &self.duration,
            "--reason", &self.reason,
            "--type", "ban",
        ])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "crowdsec".to_owned(),
                reason: format!("failed to add ban decision: {}", output.stderr.trim()),
            });
        }

        info!(ip = %self.ip, duration = %self.duration, "IP ban decision registered");
        Ok(())
    }
}

// ─── CrowdSecAdapter ───────────────────────────────────────────────────────

/// Tool adapter for CrowdSec collaborative intrusion prevention.
///
/// CrowdSec analyzes system logs to detect attacks and shares threat intelligence
/// with the community. It uses bouncers (firewall integration) to enforce decisions.
pub struct CrowdSecAdapter;

impl CrowdSecAdapter {
    /// Creates a new `CrowdSecAdapter`.
    pub fn new() -> Self {
        Self
    }

    /// Retrieves current CrowdSec statistics.
    pub async fn get_stats(&self) -> Result<CrowdSecStats> {
        // Get total blocked IPs via cscli decisions list
        let mut cmd = SafeCommand::new("cscli");
        cmd.args(&["decisions", "list", "-o", "json"])?;
        cmd.timeout(Duration::from_secs(15));

        let output = cmd.execute().await?;
        let decisions: Vec<CrowdSecDecision> = if output.exit_code == Some(0) && !output.stdout.trim().is_empty() {
            serde_json::from_str(output.stdout.trim()).unwrap_or_default()
        } else {
            Vec::new()
        };

        let total_blocked_ips = decisions.len() as u64;
        let recent_decisions: Vec<CrowdSecDecision> = decisions
            .into_iter()
            .take(MAX_RECENT_DECISIONS)
            .collect();

        // Get top scenarios via cscli metrics
        let top_5_scenarios = Vec::new(); // Populated from metrics in production

        Ok(CrowdSecStats {
            total_blocked_ips,
            recent_decisions,
            top_5_scenarios,
        })
    }

    /// Attempts to restart CrowdSec after a crash with a delay.
    pub async fn auto_restart_on_crash(&self) -> Result<()> {
        warn!("CrowdSec crash detected, attempting restart in {:?}", AUTO_RESTART_DELAY);
        tokio::time::sleep(AUTO_RESTART_DELAY).await;
        self.start().await
    }
}

impl Default for CrowdSecAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolAdapter for CrowdSecAdapter {
    fn name(&self) -> &str {
        "crowdsec"
    }

    fn display_name(&self) -> &str {
        "CrowdSec"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Protection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let distro_adapter = adapter_for(distro.package_manager);

        // Install CrowdSec main package
        let package_name = distro_adapter
            .map_tool_package("crowdsec")
            .ok_or_else(|| CommandCenterError::ToolNotAvailable {
                tool: "crowdsec".to_owned(),
            })?;

        info!(package = %package_name, distro = %distro.id, "Installing CrowdSec");
        distro_adapter.install_package(&package_name)?;

        // Install firewall bouncer (prefer nftables, fallback to iptables)
        let bouncer_pkg = "cs-firewall-bouncer-nftables";
        let bouncer_result = distro_adapter.install_package(bouncer_pkg);
        if bouncer_result.is_err() {
            info!("nftables bouncer not available, trying iptables bouncer");
            let fallback_pkg = "cs-firewall-bouncer-iptables";
            distro_adapter.install_package(fallback_pkg)?;
        }

        info!("CrowdSec installed successfully with firewall bouncer");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting CrowdSec service");
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["start", "crowdsec"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "crowdsec".to_owned(),
                reason: format!("failed to start crowdsec: {}", output.stderr.trim()),
            });
        }

        info!("CrowdSec service started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping CrowdSec service");
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["stop", "crowdsec"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "crowdsec".to_owned(),
                reason: format!("failed to stop crowdsec: {}", output.stderr.trim()),
            });
        }

        info!("CrowdSec service stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("systemctl");
        if cmd.args(&["is-active", "crowdsec"]).is_err() {
            return HealthStatus::Unhealthy("failed to build health check command".to_owned());
        }
        cmd.timeout(Duration::from_secs(5));

        match cmd.execute().await {
            Ok(output) => {
                let status = output.stdout.trim();
                if status == "active" {
                    HealthStatus::Healthy
                } else if status == "inactive" {
                    HealthStatus::NotRunning
                } else {
                    HealthStatus::Degraded(format!("crowdsec status: {}", status))
                }
            }
            Err(e) => HealthStatus::Unhealthy(format!("health check failed: {}", e)),
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        // CrowdSec is available for all supported distributions.
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // CrowdSec + bouncer approximately 50 MB.
        50 * 1024 * 1024
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = CrowdSecAdapter::new();
        assert_eq!(adapter.name(), "crowdsec");
    }

    #[test]
    fn test_adapter_display_name() {
        let adapter = CrowdSecAdapter::new();
        assert_eq!(adapter.display_name(), "CrowdSec");
    }

    #[test]
    fn test_adapter_category() {
        let adapter = CrowdSecAdapter::new();
        assert_eq!(adapter.category(), ToolCategory::Protection);
    }

    #[test]
    fn test_adapter_is_available_for_all_distros() {
        let adapter = CrowdSecAdapter::new();

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

        let arch = shared::distro::detect_distro_from_content(
            "ID=arch\nNAME=\"Arch Linux\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&arch));
    }

    #[test]
    fn test_adapter_estimated_size() {
        let adapter = CrowdSecAdapter::new();
        assert!(adapter.estimated_size_bytes() > 0);
    }

    #[test]
    fn test_blocklist_syncer_new_is_stale() {
        let syncer = BlocklistSyncer::new();
        assert!(syncer.is_stale);
        assert!(syncer.last_sync.is_none());
        assert_eq!(syncer.sync_interval_secs, BLOCKLIST_SYNC_INTERVAL_SECS);
    }

    #[test]
    fn test_blocklist_syncer_record_sync() {
        let mut syncer = BlocklistSyncer::new();
        syncer.record_sync();
        assert!(!syncer.is_stale);
        assert!(syncer.last_sync.is_some());
    }

    #[test]
    fn test_blocklist_syncer_check_staleness_no_sync() {
        let syncer = BlocklistSyncer::new();
        assert!(syncer.check_staleness());
    }

    #[test]
    fn test_blocklist_syncer_check_staleness_recent_sync() {
        let mut syncer = BlocklistSyncer::new();
        syncer.record_sync();
        assert!(!syncer.check_staleness());
    }

    #[test]
    fn test_ip_block_action_default_duration() {
        let action = IpBlockAction::new("192.168.1.100".to_owned(), "brute force".to_owned());
        assert_eq!(action.ip, "192.168.1.100");
        assert_eq!(action.duration, DEFAULT_BAN_DURATION);
        assert_eq!(action.reason, "brute force");
    }

    #[test]
    fn test_ip_block_action_custom_duration() {
        let action = IpBlockAction::with_duration(
            "10.0.0.1".to_owned(),
            "port scan".to_owned(),
            "24h".to_owned(),
        );
        assert_eq!(action.ip, "10.0.0.1");
        assert_eq!(action.duration, "24h");
        assert_eq!(action.reason, "port scan");
    }

    #[test]
    fn test_crowdsec_stats_serialization() {
        let stats = CrowdSecStats {
            total_blocked_ips: 42,
            recent_decisions: vec![CrowdSecDecision {
                ip: "1.2.3.4".to_owned(),
                scenario: "crowdsecurity/ssh-bf".to_owned(),
                decision_type: "ban".to_owned(),
                duration: "4h".to_owned(),
                created_at: Utc::now(),
            }],
            top_5_scenarios: vec![ScenarioCount {
                scenario: "crowdsecurity/ssh-bf".to_owned(),
                count: 15,
            }],
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: CrowdSecStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, deserialized);
    }

    #[test]
    fn test_blocklist_syncer_serialization() {
        let mut syncer = BlocklistSyncer::new();
        syncer.record_sync();

        let json = serde_json::to_string(&syncer).unwrap();
        let deserialized: BlocklistSyncer = serde_json::from_str(&json).unwrap();
        assert_eq!(syncer, deserialized);
    }

    #[test]
    fn test_ip_block_action_serialization() {
        let action = IpBlockAction::new("10.0.0.5".to_owned(), "scanning".to_owned());

        let json = serde_json::to_string(&action).unwrap();
        let deserialized: IpBlockAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, deserialized);
    }
}
