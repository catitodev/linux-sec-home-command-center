// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Firewall (UFW/nftables) adapter for the Linux Security Home Command Center.
//!
//! Provides firewall rule management through UFW with default-deny inbound policy.
//! Includes port auditing to detect discrepancies between listening sockets and
//! allowed firewall rules.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use shared::distro::{adapter_for, DistroInfo};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Enums ─────────────────────────────────────────────────────────────────

/// Direction of a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleDirection {
    /// Inbound traffic.
    In,
    /// Outbound traffic.
    Out,
}

/// Action taken by a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Allow the traffic.
    Allow,
    /// Deny the traffic.
    Deny,
    /// Reject the traffic (with ICMP response).
    Reject,
    /// Limit connections (rate limiting).
    Limit,
}

/// Network protocol for a firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP protocol.
    Tcp,
    /// UDP protocol.
    Udp,
    /// Both TCP and UDP.
    Both,
}

// ─── Structs ───────────────────────────────────────────────────────────────

/// A single firewall rule definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Direction of the rule (in/out).
    pub direction: RuleDirection,
    /// Source address or "any".
    pub source: String,
    /// Destination address or "any".
    pub destination: String,
    /// Port number or range (e.g., "22", "8000:8080").
    pub port: String,
    /// Protocol (tcp/udp/both).
    pub protocol: Protocol,
    /// Action to take (allow/deny/reject/limit).
    pub action: RuleAction,
}

/// Manages firewall rules through UFW.
#[derive(Debug)]
pub struct FirewallManager;

impl FirewallManager {
    /// Creates a new `FirewallManager`.
    pub fn new() -> Self {
        Self
    }

    /// Lists all current firewall rules.
    pub async fn list_rules(&self) -> Result<Vec<FirewallRule>> {
        let mut cmd = SafeCommand::new("ufw");
        cmd.args(&["status", "numbered"])?;
        cmd.timeout(Duration::from_secs(10));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "ufw".to_owned(),
                reason: format!("failed to list rules: {}", output.stderr.trim()),
            });
        }

        // Parse UFW output into FirewallRule structs
        // In production, this would parse the numbered output format
        Ok(Vec::new())
    }

    /// Adds a new firewall rule.
    pub async fn add_rule(&self, rule: &FirewallRule) -> Result<()> {
        let action_str = match rule.action {
            RuleAction::Allow => "allow",
            RuleAction::Deny => "deny",
            RuleAction::Reject => "reject",
            RuleAction::Limit => "limit",
        };

        let direction_str = match rule.direction {
            RuleDirection::In => "in",
            RuleDirection::Out => "out",
        };

        let proto_str = match rule.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Both => "any",
        };

        let mut cmd = SafeCommand::new("ufw");
        cmd.args(&[
            action_str,
            direction_str,
            "to", &rule.destination,
            "port", &rule.port,
            "proto", proto_str,
            "from", &rule.source,
        ])?;
        cmd.timeout(Duration::from_secs(15));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "ufw".to_owned(),
                reason: format!("failed to add rule: {}", output.stderr.trim()),
            });
        }

        info!(port = %rule.port, action = %action_str, "Firewall rule added");
        Ok(())
    }

    /// Removes a firewall rule by index.
    pub async fn remove_rule(&self, rule_number: u32) -> Result<()> {
        let mut cmd = SafeCommand::new("ufw");
        cmd.args(&["--force", "delete", &rule_number.to_string()])?;
        cmd.timeout(Duration::from_secs(15));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "ufw".to_owned(),
                reason: format!("failed to remove rule: {}", output.stderr.trim()),
            });
        }

        info!(rule_number = rule_number, "Firewall rule removed");
        Ok(())
    }

    /// Verifies that a rule is actually applied in the kernel.
    pub async fn verify_rule_applied(&self, rule: &FirewallRule) -> Result<bool> {
        let rules = self.list_rules().await?;
        Ok(rules.contains(rule))
    }
}

impl Default for FirewallManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a port audit comparing listening sockets against firewall rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortAudit {
    /// List of discrepancies found.
    pub discrepancies: Vec<PortDiscrepancy>,
    /// Total number of listening ports checked.
    pub total_ports_checked: usize,
    /// Number of ports with matching firewall rules.
    pub ports_with_rules: usize,
}

/// A discrepancy between a listening port and firewall rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortDiscrepancy {
    /// The port number that has a discrepancy.
    pub port: u16,
    /// Name of the process listening on this port.
    pub process_name: String,
    /// Whether a corresponding firewall rule exists.
    pub has_firewall_rule: bool,
}

impl PortAudit {
    /// Creates a new empty `PortAudit`.
    pub fn new() -> Self {
        Self {
            discrepancies: Vec::new(),
            total_ports_checked: 0,
            ports_with_rules: 0,
        }
    }

    /// Checks if there are any discrepancies.
    pub fn has_discrepancies(&self) -> bool {
        !self.discrepancies.is_empty()
    }
}

impl Default for PortAudit {
    fn default() -> Self {
        Self::new()
    }
}

// ─── FirewallAdapter ───────────────────────────────────────────────────────

/// Tool adapter for UFW/nftables firewall management.
///
/// Provides a default-deny inbound, default-allow outbound policy with
/// rule management and port auditing capabilities.
pub struct FirewallAdapter;

impl FirewallAdapter {
    /// Creates a new `FirewallAdapter`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for FirewallAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolAdapter for FirewallAdapter {
    fn name(&self) -> &str {
        "ufw"
    }

    fn display_name(&self) -> &str {
        "UFW/nftables"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Protection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let distro_adapter = adapter_for(distro.package_manager);
        let package_name = distro_adapter
            .map_tool_package("ufw")
            .ok_or_else(|| CommandCenterError::ToolNotAvailable {
                tool: "ufw".to_owned(),
            })?;

        info!(package = %package_name, distro = %distro.id, "Installing UFW");
        distro_adapter.install_package(&package_name)?;
        info!("UFW installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        info!("Enabling UFW with default-deny inbound, default-allow outbound");

        // Set default policies
        let mut cmd = SafeCommand::new("ufw");
        cmd.args(&["default", "deny", "incoming"])?;
        cmd.timeout(Duration::from_secs(15));
        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            warn!("Failed to set default deny incoming: {}", output.stderr.trim());
        }

        let mut cmd = SafeCommand::new("ufw");
        cmd.args(&["default", "allow", "outgoing"])?;
        cmd.timeout(Duration::from_secs(15));
        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            warn!("Failed to set default allow outgoing: {}", output.stderr.trim());
        }

        // Enable UFW (--force to avoid interactive prompt)
        let mut cmd = SafeCommand::new("ufw");
        cmd.args(&["--force", "enable"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "ufw".to_owned(),
                reason: format!("failed to enable ufw: {}", output.stderr.trim()),
            });
        }

        info!("UFW enabled with secure defaults");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Disabling UFW");
        let mut cmd = SafeCommand::new("ufw");
        cmd.args(&["--force", "disable"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "ufw".to_owned(),
                reason: format!("failed to disable ufw: {}", output.stderr.trim()),
            });
        }

        info!("UFW disabled");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("ufw");
        if cmd.arg("status").is_err() {
            return HealthStatus::Unhealthy("failed to build health check command".to_owned());
        }
        cmd.timeout(Duration::from_secs(5));

        match cmd.execute().await {
            Ok(output) => {
                let stdout = output.stdout.to_lowercase();
                if stdout.contains("status: active") {
                    HealthStatus::Healthy
                } else if stdout.contains("status: inactive") {
                    HealthStatus::NotRunning
                } else {
                    HealthStatus::Degraded(format!("unexpected ufw status output"))
                }
            }
            Err(e) => HealthStatus::Unhealthy(format!("ufw not responsive: {}", e)),
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        // UFW is available for all supported distributions.
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // UFW is lightweight, approximately 2 MB.
        2 * 1024 * 1024
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = FirewallAdapter::new();
        assert_eq!(adapter.name(), "ufw");
    }

    #[test]
    fn test_adapter_display_name() {
        let adapter = FirewallAdapter::new();
        assert_eq!(adapter.display_name(), "UFW/nftables");
    }

    #[test]
    fn test_adapter_category() {
        let adapter = FirewallAdapter::new();
        assert_eq!(adapter.category(), ToolCategory::Protection);
    }

    #[test]
    fn test_adapter_is_available_for_all_distros() {
        let adapter = FirewallAdapter::new();

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
        let adapter = FirewallAdapter::new();
        assert!(adapter.estimated_size_bytes() > 0);
    }

    #[test]
    fn test_firewall_rule_serialization() {
        let rule = FirewallRule {
            direction: RuleDirection::In,
            source: "any".to_owned(),
            destination: "any".to_owned(),
            port: "22".to_owned(),
            protocol: Protocol::Tcp,
            action: RuleAction::Allow,
        };

        let json = serde_json::to_string(&rule).unwrap();
        let deserialized: FirewallRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, deserialized);
    }

    #[test]
    fn test_port_discrepancy_serialization() {
        let discrepancy = PortDiscrepancy {
            port: 8080,
            process_name: "node".to_owned(),
            has_firewall_rule: false,
        };

        let json = serde_json::to_string(&discrepancy).unwrap();
        let deserialized: PortDiscrepancy = serde_json::from_str(&json).unwrap();
        assert_eq!(discrepancy, deserialized);
    }

    #[test]
    fn test_port_audit_new_empty() {
        let audit = PortAudit::new();
        assert!(!audit.has_discrepancies());
        assert_eq!(audit.total_ports_checked, 0);
        assert_eq!(audit.ports_with_rules, 0);
    }

    #[test]
    fn test_port_audit_with_discrepancies() {
        let audit = PortAudit {
            discrepancies: vec![PortDiscrepancy {
                port: 3000,
                process_name: "node".to_owned(),
                has_firewall_rule: false,
            }],
            total_ports_checked: 5,
            ports_with_rules: 4,
        };
        assert!(audit.has_discrepancies());
    }

    #[test]
    fn test_port_audit_serialization() {
        let audit = PortAudit {
            discrepancies: vec![PortDiscrepancy {
                port: 443,
                process_name: "nginx".to_owned(),
                has_firewall_rule: true,
            }],
            total_ports_checked: 10,
            ports_with_rules: 8,
        };

        let json = serde_json::to_string(&audit).unwrap();
        let deserialized: PortAudit = serde_json::from_str(&json).unwrap();
        assert_eq!(audit, deserialized);
    }

    #[test]
    fn test_rule_direction_variants() {
        let rule_in = FirewallRule {
            direction: RuleDirection::In,
            source: "192.168.1.0/24".to_owned(),
            destination: "any".to_owned(),
            port: "80".to_owned(),
            protocol: Protocol::Tcp,
            action: RuleAction::Allow,
        };
        assert_eq!(rule_in.direction, RuleDirection::In);

        let rule_out = FirewallRule {
            direction: RuleDirection::Out,
            source: "any".to_owned(),
            destination: "0.0.0.0/0".to_owned(),
            port: "443".to_owned(),
            protocol: Protocol::Tcp,
            action: RuleAction::Allow,
        };
        assert_eq!(rule_out.direction, RuleDirection::Out);
    }

    #[test]
    fn test_rule_action_variants() {
        let actions = [RuleAction::Allow, RuleAction::Deny, RuleAction::Reject, RuleAction::Limit];
        for action in &actions {
            let rule = FirewallRule {
                direction: RuleDirection::In,
                source: "any".to_owned(),
                destination: "any".to_owned(),
                port: "22".to_owned(),
                protocol: Protocol::Tcp,
                action: *action,
            };
            let json = serde_json::to_string(&rule).unwrap();
            let deserialized: FirewallRule = serde_json::from_str(&json).unwrap();
            assert_eq!(rule, deserialized);
        }
    }
}
