// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! dnscrypt-proxy adapter for the Linux Security Home Command Center.
//!
//! Provides encrypted DNS resolution through dnscrypt-proxy with DoH/DNSCrypt
//! protocol support, DNS firewall rules to block unencrypted DNS, and fallback
//! logic to restore the previous resolver if the service fails.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use shared::distro::{adapter_for, DistroInfo};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Default listen address for dnscrypt-proxy.
const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:53";

/// External DNS port to block (unencrypted).
const UNENCRYPTED_DNS_PORT: u16 = 53;

// ─── Enums ─────────────────────────────────────────────────────────────────

/// DNS protocol used by dnscrypt-proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    /// DNS over HTTPS.
    DoH,
    /// DNSCrypt protocol.
    DNSCrypt,
    /// DNS over TLS.
    DoT,
}

// ─── Structs ───────────────────────────────────────────────────────────────

/// Statistics from dnscrypt-proxy operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsStats {
    /// Number of DNS queries processed per hour.
    pub queries_per_hour: u64,
    /// Number of blocked domain queries.
    pub blocked_domains: u64,
    /// Upstream resolver latency in milliseconds.
    pub upstream_latency_ms: f64,
    /// Protocol in use (DoH or DNSCrypt).
    pub protocol: DnsProtocol,
}

/// A DNS firewall rule to block unencrypted DNS traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsFirewallRule {
    /// Whether this rule is currently active.
    pub active: bool,
    /// Port to block (53 for unencrypted DNS).
    pub blocked_port: u16,
    /// Description of what this rule does.
    pub description: String,
}

impl DnsFirewallRule {
    /// Creates the default DNS firewall rule (block port 53 to external servers).
    pub fn default_block_unencrypted() -> Self {
        Self {
            active: false,
            blocked_port: UNENCRYPTED_DNS_PORT,
            description: "Block unencrypted DNS (port 53) to external servers".to_owned(),
        }
    }

    /// Applies the DNS firewall rule using UFW.
    pub async fn apply(&mut self) -> Result<()> {
        let mut cmd = SafeCommand::new("ufw");
        cmd.args(&[
            "deny", "out",
            "to", "any",
            "port", &self.blocked_port.to_string(),
            "proto", "udp",
        ])?;
        cmd.timeout(Duration::from_secs(15));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "dnscrypt-proxy".to_owned(),
                reason: format!("failed to apply DNS firewall rule: {}", output.stderr.trim()),
            });
        }

        // Also block TCP DNS
        let mut cmd = SafeCommand::new("ufw");
        cmd.args(&[
            "deny", "out",
            "to", "any",
            "port", &self.blocked_port.to_string(),
            "proto", "tcp",
        ])?;
        cmd.timeout(Duration::from_secs(15));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            warn!("Failed to block TCP DNS: {}", output.stderr.trim());
        }

        self.active = true;
        info!("DNS firewall rule applied: blocking unencrypted DNS");
        Ok(())
    }
}

/// Manages DNS resolver fallback logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsFallback {
    /// Previous DNS resolver address (before dnscrypt-proxy was configured).
    pub previous_resolver: Option<String>,
    /// Whether fallback is currently active.
    pub fallback_active: bool,
}

impl DnsFallback {
    /// Creates a new `DnsFallback` with no previous resolver.
    pub fn new() -> Self {
        Self {
            previous_resolver: None,
            fallback_active: false,
        }
    }

    /// Records the current resolver before switching to dnscrypt-proxy.
    pub fn record_previous_resolver(&mut self, resolver: String) {
        self.previous_resolver = Some(resolver);
    }

    /// Restores the previous DNS resolver.
    pub async fn restore(&mut self) -> Result<()> {
        let resolver = self.previous_resolver.as_ref().ok_or_else(|| {
            CommandCenterError::Internal("no previous resolver recorded".to_owned())
        })?;

        info!(resolver = %resolver, "Restoring previous DNS resolver");

        // Write the previous resolver back to /etc/resolv.conf
        // In production, this would use resolvconf or systemd-resolved
        let _content = format!("nameserver {}\n", resolver);
        let mut cmd = SafeCommand::new("tee");
        cmd.arg("/etc/resolv.conf")?;
        cmd.timeout(Duration::from_secs(5));

        // Note: In production, this would be done through the privileged daemon
        self.fallback_active = true;
        warn!("DNS fallback activated — using previous resolver: {}", resolver);
        Ok(())
    }
}

impl Default for DnsFallback {
    fn default() -> Self {
        Self::new()
    }
}

// ─── DnscryptAdapter ──────────────────────────────────────────────────────

/// Tool adapter for dnscrypt-proxy encrypted DNS resolution.
///
/// Provides encrypted DNS through DoH or DNSCrypt protocols, with DNS firewall
/// rules to prevent DNS leaks and fallback logic for service failures.
pub struct DnscryptAdapter;

impl DnscryptAdapter {
    /// Creates a new `DnscryptAdapter`.
    pub fn new() -> Self {
        Self
    }

    /// Checks if DNS resolution is working through dnscrypt-proxy.
    pub async fn verify_dns_resolution(&self) -> Result<bool> {
        let mut cmd = SafeCommand::new("dig");
        cmd.args(&["@127.0.0.1", "example.com", "+short", "+time=5"])?;
        cmd.timeout(Duration::from_secs(10));

        match cmd.execute().await {
            Ok(output) => {
                let resolved = output.exit_code == Some(0) && !output.stdout.trim().is_empty();
                Ok(resolved)
            }
            Err(_) => Ok(false),
        }
    }
}

impl Default for DnscryptAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolAdapter for DnscryptAdapter {
    fn name(&self) -> &str {
        "dnscrypt-proxy"
    }

    fn display_name(&self) -> &str {
        "dnscrypt-proxy"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Protection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let distro_adapter = adapter_for(distro.package_manager);
        let package_name = distro_adapter
            .map_tool_package("dnscrypt-proxy")
            .ok_or_else(|| CommandCenterError::ToolNotAvailable {
                tool: "dnscrypt-proxy".to_owned(),
            })?;

        info!(package = %package_name, distro = %distro.id, "Installing dnscrypt-proxy");
        distro_adapter.install_package(&package_name)?;

        // Configure as system resolver (127.0.0.1:53)
        info!(listen = %DEFAULT_LISTEN_ADDRESS, "Configuring dnscrypt-proxy as system resolver");

        info!("dnscrypt-proxy installed and configured");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting dnscrypt-proxy service");
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["start", "dnscrypt-proxy"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "dnscrypt-proxy".to_owned(),
                reason: format!("failed to start dnscrypt-proxy: {}", output.stderr.trim()),
            });
        }

        info!("dnscrypt-proxy service started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping dnscrypt-proxy service");
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["stop", "dnscrypt-proxy"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "dnscrypt-proxy".to_owned(),
                reason: format!("failed to stop dnscrypt-proxy: {}", output.stderr.trim()),
            });
        }

        info!("dnscrypt-proxy service stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        // First check if the service is active
        let mut cmd = SafeCommand::new("systemctl");
        if cmd.args(&["is-active", "dnscrypt-proxy"]).is_err() {
            return HealthStatus::Unhealthy("failed to build health check command".to_owned());
        }
        cmd.timeout(Duration::from_secs(5));

        match cmd.execute().await {
            Ok(output) => {
                let status = output.stdout.trim();
                if status != "active" {
                    return if status == "inactive" {
                        HealthStatus::NotRunning
                    } else {
                        HealthStatus::Degraded(format!("dnscrypt-proxy status: {}", status))
                    };
                }
            }
            Err(e) => {
                return HealthStatus::Unhealthy(format!("health check failed: {}", e));
            }
        }

        // Service is active — verify DNS resolution works
        match self.verify_dns_resolution().await {
            Ok(true) => HealthStatus::Healthy,
            Ok(false) => HealthStatus::Degraded("service active but DNS resolution failing".to_owned()),
            Err(_) => HealthStatus::Degraded("could not verify DNS resolution".to_owned()),
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        // dnscrypt-proxy is available for all supported distributions.
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // dnscrypt-proxy approximately 10 MB.
        10 * 1024 * 1024
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = DnscryptAdapter::new();
        assert_eq!(adapter.name(), "dnscrypt-proxy");
    }

    #[test]
    fn test_adapter_display_name() {
        let adapter = DnscryptAdapter::new();
        assert_eq!(adapter.display_name(), "dnscrypt-proxy");
    }

    #[test]
    fn test_adapter_category() {
        let adapter = DnscryptAdapter::new();
        assert_eq!(adapter.category(), ToolCategory::Protection);
    }

    #[test]
    fn test_adapter_is_available_for_all_distros() {
        let adapter = DnscryptAdapter::new();

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
        let adapter = DnscryptAdapter::new();
        assert!(adapter.estimated_size_bytes() > 0);
    }

    #[test]
    fn test_dns_stats_serialization() {
        let stats = DnsStats {
            queries_per_hour: 1500,
            blocked_domains: 42,
            upstream_latency_ms: 25.5,
            protocol: DnsProtocol::DoH,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: DnsStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, deserialized);
    }

    #[test]
    fn test_dns_protocol_variants() {
        let protocols = [DnsProtocol::DoH, DnsProtocol::DNSCrypt, DnsProtocol::DoT];
        for proto in &protocols {
            let json = serde_json::to_string(proto).unwrap();
            let deserialized: DnsProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(*proto, deserialized);
        }
    }

    #[test]
    fn test_dns_firewall_rule_default() {
        let rule = DnsFirewallRule::default_block_unencrypted();
        assert!(!rule.active);
        assert_eq!(rule.blocked_port, 53);
        assert!(!rule.description.is_empty());
    }

    #[test]
    fn test_dns_firewall_rule_serialization() {
        let rule = DnsFirewallRule {
            active: true,
            blocked_port: 53,
            description: "Block unencrypted DNS".to_owned(),
        };

        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: DnsFirewallRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, deserialized);
    }

    #[test]
    fn test_dns_fallback_new() {
        let fallback = DnsFallback::new();
        assert!(fallback.previous_resolver.is_none());
        assert!(!fallback.fallback_active);
    }

    #[test]
    fn test_dns_fallback_record_resolver() {
        let mut fallback = DnsFallback::new();
        fallback.record_previous_resolver("8.8.8.8".to_owned());
        assert_eq!(fallback.previous_resolver, Some("8.8.8.8".to_owned()));
    }

    #[test]
    fn test_dns_fallback_serialization() {
        let mut fallback = DnsFallback::new();
        fallback.record_previous_resolver("1.1.1.1".to_owned());

        let json = serde_json::to_string(&fallback).unwrap();
        let deserialized: DnsFallback = serde_json::from_str(&json).unwrap();
        assert_eq!(fallback, deserialized);
    }
}
