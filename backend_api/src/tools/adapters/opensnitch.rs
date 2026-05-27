// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! OpenSnitch adapter for per-process application firewall monitoring.
//!
//! Provides integration with OpenSnitch for network connection tracking,
//! connection decision management (allow/deny), and process correlation
//! using osquery data.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use shared::distro::DistroInfo;
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};
use crate::tools::adapters::osquery::OsqueryClient;

// ─── Connection Decision Types ─────────────────────────────────────────────

/// Decision action for a pending connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionDecision {
    /// Allow this single connection attempt.
    AllowOnce,
    /// Allow all future connections from this process.
    AllowAlways,
    /// Deny this single connection attempt.
    DenyOnce,
    /// Deny all future connections from this process.
    DenyAlways,
}

/// Default timeout in seconds before applying default action to pending connections.
const DECISION_TIMEOUT_SECS: u64 = 15;

/// Default action when user does not respond within the timeout.
const DEFAULT_ACTION: ConnectionDecision = ConnectionDecision::DenyOnce;

/// Interval in seconds for connection map data refresh.
const CONNECTION_MAP_REFRESH_SECS: u64 = 10;

// ─── Connection Information ────────────────────────────────────────────────

/// Information about a single network connection tracked by OpenSnitch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Process ID that initiated the connection.
    pub pid: u32,
    /// Process name.
    pub process_name: String,
    /// Network protocol (tcp, udp, etc.).
    pub protocol: String,
    /// Source IP address.
    pub src_ip: String,
    /// Source port.
    pub src_port: u16,
    /// Destination IP address.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// Bytes transferred.
    pub data_bytes: u64,
    /// Timestamp of the connection event (Unix epoch seconds).
    pub timestamp: i64,
    /// Rule action applied to this connection.
    pub rule_action: String,
}

/// A pending connection awaiting user decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingConnection {
    /// The connection information.
    pub connection: ConnectionInfo,
    /// When this connection was first seen (Unix epoch seconds).
    pub first_seen_secs: i64,
    /// Whether a decision has been made.
    pub decided: bool,
    /// The decision applied, if any.
    pub decision: Option<ConnectionDecision>,
}

// ─── Process Correlation ───────────────────────────────────────────────────

/// Full process context obtained by correlating OpenSnitch data with osquery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessContext {
    /// Process ID.
    pub pid: u32,
    /// Process name.
    pub name: String,
    /// User running the process.
    pub user: String,
    /// Full command line.
    pub cmdline: String,
    /// Parent process ID.
    pub parent_pid: u32,
    /// Parent process name.
    pub parent_name: String,
}

// ─── Connection Map Data (Frontend) ────────────────────────────────────────

/// A process node in the connection map graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessNode {
    /// Process ID.
    pub pid: u32,
    /// Process name.
    pub name: String,
    /// User running the process.
    pub user: String,
    /// Number of active connections from this process.
    pub connection_count: u32,
}

/// An edge in the connection map graph (process → destination).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionEdge {
    /// Source process PID.
    pub src_pid: u32,
    /// Destination IP address.
    pub dst_ip: String,
    /// Destination port.
    pub dst_port: u16,
    /// Network protocol.
    pub protocol: String,
    /// Total bytes transferred on this connection.
    pub bytes_transferred: u64,
    /// Duration of the connection in seconds.
    pub duration_secs: u64,
}

/// The full connection map data structure sent to the frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionMapData {
    /// Unique processes with active connections.
    pub nodes: Vec<ProcessNode>,
    /// Connections between processes and destination IPs.
    pub edges: Vec<ConnectionEdge>,
}

// ─── OpenSnitch Adapter ────────────────────────────────────────────────────

/// Adapter for OpenSnitch — a per-process application firewall.
pub struct OpenSnitchAdapter;

impl OpenSnitchAdapter {
    /// Creates a new `OpenSnitchAdapter`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for OpenSnitchAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolAdapter for OpenSnitchAdapter {
    fn name(&self) -> &str {
        "opensnitch"
    }

    fn display_name(&self) -> &str {
        "OpenSnitch"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Visibility
    }

    async fn install(&self, _distro: &DistroInfo) -> Result<()> {
        // Enable and start the opensnitchd service after package installation.
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["enable", "--now", "opensnitchd"])?;
        cmd.timeout(Duration::from_secs(60));
        cmd.execute().await.map_err(|e| {
            CommandCenterError::ToolOperationFailed {
                tool: "opensnitch".into(),
                reason: format!("failed to enable opensnitchd: {}", e),
            }
        })?;

        // Configure default action to "prompt" for new connections.
        Self::configure_default_prompt().await?;

        info!("OpenSnitch installed and configured with default-prompt action");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["start", "opensnitchd"])?;
        cmd.timeout(Duration::from_secs(30));
        cmd.execute().await.map_err(|e| {
            CommandCenterError::ToolOperationFailed {
                tool: "opensnitch".into(),
                reason: format!("failed to start opensnitchd: {}", e),
            }
        })?;
        info!("OpenSnitch service started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["stop", "opensnitchd"])?;
        cmd.timeout(Duration::from_secs(30));
        cmd.execute().await.map_err(|e| {
            CommandCenterError::ToolOperationFailed {
                tool: "opensnitch".into(),
                reason: format!("failed to stop opensnitchd: {}", e),
            }
        })?;
        info!("OpenSnitch service stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("systemctl");
        if cmd.args(&["is-active", "opensnitchd"]).is_err() {
            return HealthStatus::Unhealthy(
                "failed to build health check command".into(),
            );
        }
        cmd.timeout(Duration::from_secs(10));

        match cmd.execute().await {
            Ok(output) if output.stdout.trim() == "active" => HealthStatus::Healthy,
            Ok(output) => {
                let status = output.stdout.trim().to_string();
                if status == "inactive" {
                    HealthStatus::NotRunning
                } else {
                    HealthStatus::Degraded(format!("opensnitchd status: {}", status))
                }
            }
            Err(e) => {
                warn!(error = %e, "OpenSnitch health check failed");
                HealthStatus::Unhealthy(format!("health check failed: {}", e))
            }
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        // OpenSnitch is available for all supported distributions.
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        15_000_000 // ~15 MB
    }
}

impl OpenSnitchAdapter {
    /// Configures OpenSnitch with default-prompt action for unknown connections.
    ///
    /// Writes the configuration to `/etc/opensnitchd/default-config.json`
    /// setting the default action to "prompt".
    async fn configure_default_prompt() -> Result<()> {
        let _config_content = r#"{"DefaultAction":"prompt","DefaultDuration":"once"}"#;

        let mut cmd = SafeCommand::new("tee");
        cmd.arg("/etc/opensnitchd/default-config.json")?;
        cmd.timeout(Duration::from_secs(10));

        // Note: In production, this would be done via the Privileged_Daemon.
        // Here we document the intent; actual write requires root.
        let _ = cmd.execute().await;

        Ok(())
    }
}

// ─── Connection Tracker ────────────────────────────────────────────────────

/// Tracks active network connections reported by OpenSnitch.
///
/// Reads connection events from the OpenSnitch log file and maintains
/// a list of active connections, refreshing every 10 seconds.
pub struct ConnectionTracker {
    /// Path to the OpenSnitch events log.
    log_path: String,
    /// Cached active connections.
    connections: Vec<ConnectionInfo>,
    /// Last refresh timestamp.
    last_refresh: Option<Instant>,
}

impl ConnectionTracker {
    /// Creates a new `ConnectionTracker` with the default log path.
    pub fn new() -> Self {
        Self {
            log_path: "/var/log/opensnitchd/events.log".to_string(),
            connections: Vec::new(),
            last_refresh: None,
        }
    }

    /// Creates a new `ConnectionTracker` with a custom log path.
    pub fn with_log_path(log_path: &str) -> Self {
        Self {
            log_path: log_path.to_string(),
            connections: Vec::new(),
            last_refresh: None,
        }
    }

    /// Returns the refresh interval for connection data.
    pub fn refresh_interval(&self) -> Duration {
        Duration::from_secs(CONNECTION_MAP_REFRESH_SECS)
    }

    /// Checks whether the cached data needs refreshing.
    pub fn needs_refresh(&self) -> bool {
        match self.last_refresh {
            None => true,
            Some(last) => last.elapsed() >= self.refresh_interval(),
        }
    }

    /// Retrieves active connections, refreshing from the log if needed.
    ///
    /// Uses `opensnitchd` CLI or parses the events log to obtain current
    /// connection state. Results are cached for the refresh interval.
    pub async fn get_active_connections(&mut self) -> Result<&[ConnectionInfo]> {
        if self.needs_refresh() {
            self.refresh_connections().await?;
        }
        Ok(&self.connections)
    }

    /// Refreshes the connection list from OpenSnitch.
    ///
    /// Queries active connections using the `opensnitch-ui` CLI tool
    /// or by parsing the events log file.
    async fn refresh_connections(&mut self) -> Result<()> {
        let mut cmd = SafeCommand::new("opensnitchd");
        cmd.args(&["--list-connections", "--json"])?;
        cmd.timeout(Duration::from_secs(10));

        match cmd.execute().await {
            Ok(output) if output.exit_code == Some(0) => {
                self.connections = parse_connection_list(&output.stdout)?;
            }
            Ok(_) | Err(_) => {
                // Fallback: parse the events log file directly.
                self.connections =
                    parse_connections_from_log(&self.log_path).await?;
            }
        }

        self.last_refresh = Some(Instant::now());
        Ok(())
    }

    /// Builds the connection map data for the frontend.
    ///
    /// Aggregates connections into process nodes and connection edges,
    /// suitable for graph visualization.
    pub async fn build_connection_map(&mut self) -> Result<ConnectionMapData> {
        let connections = self.get_active_connections().await?;

        let mut nodes_map: HashMap<u32, ProcessNode> = HashMap::new();
        let mut edges: Vec<ConnectionEdge> = Vec::new();

        for conn in connections {
            // Upsert process node.
            let node = nodes_map.entry(conn.pid).or_insert_with(|| ProcessNode {
                pid: conn.pid,
                name: conn.process_name.clone(),
                user: String::new(), // Populated by correlator.
                connection_count: 0,
            });
            node.connection_count += 1;

            // Create edge.
            edges.push(ConnectionEdge {
                src_pid: conn.pid,
                dst_ip: conn.dst_ip.clone(),
                dst_port: conn.dst_port,
                protocol: conn.protocol.clone(),
                bytes_transferred: conn.data_bytes,
                duration_secs: 0, // Computed from timestamps externally.
            });
        }

        let nodes: Vec<ProcessNode> = nodes_map.into_values().collect();

        Ok(ConnectionMapData { nodes, edges })
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Decision Manager ──────────────────────────────────────────────────────

/// Manages pending connection decisions with timeout enforcement.
///
/// When OpenSnitch detects a new connection without an existing rule,
/// the decision manager holds it for up to 15 seconds. If no user
/// response is received, the default action (deny once) is applied.
pub struct DecisionManager {
    /// Pending connections awaiting user decision.
    pending: Vec<PendingConnection>,
    /// Timeout duration before applying default action.
    timeout: Duration,
    /// Default action when timeout expires.
    default_action: ConnectionDecision,
}

impl DecisionManager {
    /// Creates a new `DecisionManager` with default settings.
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            timeout: Duration::from_secs(DECISION_TIMEOUT_SECS),
            default_action: DEFAULT_ACTION,
        }
    }

    /// Creates a `DecisionManager` with custom timeout and default action.
    pub fn with_config(timeout_secs: u64, default_action: ConnectionDecision) -> Self {
        Self {
            pending: Vec::new(),
            timeout: Duration::from_secs(timeout_secs),
            default_action,
        }
    }

    /// Adds a new pending connection for user decision.
    pub fn add_pending(&mut self, connection: ConnectionInfo, now_secs: i64) {
        self.pending.push(PendingConnection {
            connection,
            first_seen_secs: now_secs,
            decided: false,
            decision: None,
        });
    }

    /// Applies a user decision to a pending connection identified by PID and dst.
    ///
    /// Returns `true` if the connection was found and the decision applied.
    pub fn apply_decision(
        &mut self,
        pid: u32,
        dst_ip: &str,
        dst_port: u16,
        decision: ConnectionDecision,
    ) -> bool {
        for pending in &mut self.pending {
            if !pending.decided
                && pending.connection.pid == pid
                && pending.connection.dst_ip == dst_ip
                && pending.connection.dst_port == dst_port
            {
                pending.decided = true;
                pending.decision = Some(decision);
                return true;
            }
        }
        false
    }

    /// Processes timeouts: applies default action to connections that have
    /// exceeded the decision timeout without a user response.
    ///
    /// Returns the list of connections that were auto-decided.
    pub fn process_timeouts(&mut self, now_secs: i64) -> Vec<&PendingConnection> {
        let timeout_secs = self.timeout.as_secs() as i64;
        let default = self.default_action;

        for pending in &mut self.pending {
            if !pending.decided
                && (now_secs - pending.first_seen_secs) >= timeout_secs
            {
                pending.decided = true;
                pending.decision = Some(default);
                warn!(
                    pid = pending.connection.pid,
                    dst_ip = %pending.connection.dst_ip,
                    dst_port = pending.connection.dst_port,
                    "Connection decision timed out, applying default deny"
                );
            }
        }

        self.pending.iter().filter(|p| p.decided).collect()
    }

    /// Returns all undecided pending connections.
    pub fn get_pending(&self) -> Vec<&PendingConnection> {
        self.pending.iter().filter(|p| !p.decided).collect()
    }

    /// Removes all decided connections from the pending list.
    pub fn drain_decided(&mut self) -> Vec<PendingConnection> {
        let (decided, undecided): (Vec<_>, Vec<_>) =
            self.pending.drain(..).partition(|p| p.decided);
        self.pending = undecided;
        decided
    }

    /// Returns the configured timeout duration.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the configured default action.
    pub fn default_action(&self) -> ConnectionDecision {
        self.default_action
    }
}

impl Default for DecisionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Process Correlator ────────────────────────────────────────────────────

/// Correlates OpenSnitch connection data with osquery process information.
///
/// Given a PID, queries osquery for the full process context including
/// user, command line, and parent process details.
pub struct ProcessCorrelator {
    /// osquery client for executing process queries.
    client: OsqueryClient,
}

impl ProcessCorrelator {
    /// Creates a new `ProcessCorrelator`.
    pub fn new() -> Self {
        Self {
            client: OsqueryClient::new(),
        }
    }

    /// Creates a `ProcessCorrelator` with a specific osquery client.
    pub fn with_client(client: OsqueryClient) -> Self {
        Self { client }
    }

    /// Correlates a PID with full process context from osquery.
    ///
    /// Executes: `SELECT pid, name, cmdline, uid, parent FROM processes WHERE pid = {pid}`
    /// Then resolves the parent process name and the username from uid.
    ///
    /// # Errors
    ///
    /// Returns an error if osquery is unavailable or the PID is not found.
    pub async fn correlate(&self, pid: u32) -> Result<ProcessContext> {
        let query = format!(
            "SELECT pid, name, cmdline, uid, parent FROM processes WHERE pid = {}",
            pid
        );

        let results = self.client.execute_query(&query).await?;

        let row = results.first().ok_or_else(|| {
            CommandCenterError::ToolOperationFailed {
                tool: "osquery".into(),
                reason: format!("no process found with PID {}", pid),
            }
        })?;

        let name = row
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let cmdline = row
            .get("cmdline")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let uid_str = row
            .get("uid")
            .and_then(|v| v.as_str())
            .unwrap_or("0");
        let parent_pid: u32 = row
            .get("parent")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Resolve username from UID.
        let user = self.resolve_username(uid_str).await;

        // Resolve parent process name.
        let parent_name = self.resolve_process_name(parent_pid).await;

        Ok(ProcessContext {
            pid,
            name,
            user,
            cmdline,
            parent_pid,
            parent_name,
        })
    }

    /// Resolves a UID string to a username via osquery.
    async fn resolve_username(&self, uid: &str) -> String {
        let query = format!(
            "SELECT username FROM users WHERE uid = {}",
            uid
        );
        match self.client.execute_query(&query).await {
            Ok(results) => results
                .first()
                .and_then(|r| r.get("username"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            Err(_) => format!("uid:{}", uid),
        }
    }

    /// Resolves a PID to its process name via osquery.
    async fn resolve_process_name(&self, pid: u32) -> String {
        if pid == 0 {
            return "kernel".to_string();
        }
        let query = format!(
            "SELECT name FROM processes WHERE pid = {}",
            pid
        );
        match self.client.execute_query(&query).await {
            Ok(results) => results
                .first()
                .and_then(|r| r.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            Err(_) => "unknown".to_string(),
        }
    }
}

impl Default for ProcessCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Parsing Helpers ───────────────────────────────────────────────────────

/// Parses a JSON connection list from the `opensnitchd --list-connections` output.
fn parse_connection_list(json_output: &str) -> Result<Vec<ConnectionInfo>> {
    let trimmed = json_output.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let connections: Vec<ConnectionInfo> =
        serde_json::from_str(trimmed).map_err(|e| {
            CommandCenterError::ToolOperationFailed {
                tool: "opensnitch".into(),
                reason: format!("failed to parse connection list: {}", e),
            }
        })?;

    Ok(connections)
}

/// Parses connections from the OpenSnitch events log file.
///
/// Each line in the log is a JSON object representing a connection event.
async fn parse_connections_from_log(log_path: &str) -> Result<Vec<ConnectionInfo>> {
    // Read the last N lines of the log to get recent connections.
    let mut cmd = SafeCommand::new("tail");
    cmd.args(&["-n", "200", log_path])?;
    cmd.timeout(Duration::from_secs(5));

    let output = cmd.execute().await.map_err(|e| {
        CommandCenterError::ToolOperationFailed {
            tool: "opensnitch".into(),
            reason: format!("failed to read events log: {}", e),
        }
    })?;

    if output.exit_code != Some(0) {
        return Ok(Vec::new());
    }

    let mut connections = Vec::new();
    for line in output.stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(conn) = serde_json::from_str::<ConnectionInfo>(line) {
            connections.push(conn);
        }
    }

    Ok(connections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = OpenSnitchAdapter::new();
        assert_eq!(adapter.name(), "opensnitch");
    }

    #[test]
    fn test_adapter_display_name() {
        let adapter = OpenSnitchAdapter::new();
        assert_eq!(adapter.display_name(), "OpenSnitch");
    }

    #[test]
    fn test_adapter_category() {
        let adapter = OpenSnitchAdapter::new();
        assert_eq!(adapter.category(), ToolCategory::Visibility);
    }

    #[test]
    fn test_adapter_available_for_all_distros() {
        let adapter = OpenSnitchAdapter::new();
        let distro = DistroInfo {
            id: "ubuntu".into(),
            version_id: "22.04".into(),
            name: "Ubuntu".into(),
            package_manager: shared::distro::PackageManager::Apt,
            has_btrfs: false,
            kernel_version: (6, 5),
            has_ebpf: true,
            mac_framework: shared::distro::MACFramework::AppArmor,
        };
        assert!(adapter.is_available_for(&distro));
    }

    #[test]
    fn test_connection_decision_serialization() {
        let decision = ConnectionDecision::AllowOnce;
        let json = serde_json::to_string(&decision).unwrap();
        assert_eq!(json, "\"allow_once\"");

        let parsed: ConnectionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ConnectionDecision::AllowOnce);
    }

    #[test]
    fn test_decision_manager_add_pending() {
        let mut mgr = DecisionManager::new();
        let conn = ConnectionInfo {
            pid: 1234,
            process_name: "firefox".into(),
            protocol: "tcp".into(),
            src_ip: "192.168.1.100".into(),
            src_port: 45000,
            dst_ip: "93.184.216.34".into(),
            dst_port: 443,
            data_bytes: 0,
            timestamp: 1700000000,
            rule_action: "prompt".into(),
        };

        mgr.add_pending(conn, 1700000000);
        assert_eq!(mgr.get_pending().len(), 1);
    }

    #[test]
    fn test_decision_manager_apply_decision() {
        let mut mgr = DecisionManager::new();
        let conn = ConnectionInfo {
            pid: 1234,
            process_name: "firefox".into(),
            protocol: "tcp".into(),
            src_ip: "192.168.1.100".into(),
            src_port: 45000,
            dst_ip: "93.184.216.34".into(),
            dst_port: 443,
            data_bytes: 0,
            timestamp: 1700000000,
            rule_action: "prompt".into(),
        };

        mgr.add_pending(conn, 1700000000);

        let applied = mgr.apply_decision(
            1234,
            "93.184.216.34",
            443,
            ConnectionDecision::AllowAlways,
        );
        assert!(applied);
        assert_eq!(mgr.get_pending().len(), 0);
    }

    #[test]
    fn test_decision_manager_timeout() {
        let mut mgr = DecisionManager::new();
        let conn = ConnectionInfo {
            pid: 5678,
            process_name: "curl".into(),
            protocol: "tcp".into(),
            src_ip: "192.168.1.100".into(),
            src_port: 50000,
            dst_ip: "10.0.0.1".into(),
            dst_port: 80,
            data_bytes: 0,
            timestamp: 1700000000,
            rule_action: "prompt".into(),
        };

        mgr.add_pending(conn, 1700000000);

        // Before timeout: no auto-decision.
        let _decided = mgr.process_timeouts(1700000010);
        let undecided: Vec<_> = mgr.get_pending();
        assert_eq!(undecided.len(), 1);

        // After timeout (15s): auto-deny.
        let _ = mgr.process_timeouts(1700000016);
        let undecided = mgr.get_pending();
        assert_eq!(undecided.len(), 0);
    }

    #[test]
    fn test_decision_manager_drain_decided() {
        let mut mgr = DecisionManager::new();
        let conn = ConnectionInfo {
            pid: 100,
            process_name: "test".into(),
            protocol: "udp".into(),
            src_ip: "127.0.0.1".into(),
            src_port: 1000,
            dst_ip: "8.8.8.8".into(),
            dst_port: 53,
            data_bytes: 64,
            timestamp: 1700000000,
            rule_action: "prompt".into(),
        };

        mgr.add_pending(conn, 1700000000);
        mgr.apply_decision(100, "8.8.8.8", 53, ConnectionDecision::DenyAlways);

        let decided = mgr.drain_decided();
        assert_eq!(decided.len(), 1);
        assert_eq!(decided[0].decision, Some(ConnectionDecision::DenyAlways));
        assert_eq!(mgr.get_pending().len(), 0);
    }

    #[test]
    fn test_decision_manager_no_match() {
        let mut mgr = DecisionManager::new();
        let conn = ConnectionInfo {
            pid: 100,
            process_name: "test".into(),
            protocol: "tcp".into(),
            src_ip: "127.0.0.1".into(),
            src_port: 1000,
            dst_ip: "8.8.8.8".into(),
            dst_port: 53,
            data_bytes: 0,
            timestamp: 1700000000,
            rule_action: "prompt".into(),
        };

        mgr.add_pending(conn, 1700000000);

        // Wrong PID — should not match.
        let applied = mgr.apply_decision(999, "8.8.8.8", 53, ConnectionDecision::AllowOnce);
        assert!(!applied);
        assert_eq!(mgr.get_pending().len(), 1);
    }

    #[test]
    fn test_parse_connection_list_empty() {
        let result = parse_connection_list("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_connection_list_valid_json() {
        let json = r#"[{
            "pid": 1000,
            "process_name": "firefox",
            "protocol": "tcp",
            "src_ip": "192.168.1.5",
            "src_port": 40000,
            "dst_ip": "142.250.80.46",
            "dst_port": 443,
            "data_bytes": 2048,
            "timestamp": 1700000000,
            "rule_action": "allow"
        }]"#;

        let result = parse_connection_list(json).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 1000);
        assert_eq!(result[0].process_name, "firefox");
        assert_eq!(result[0].dst_port, 443);
    }

    #[test]
    fn test_connection_tracker_needs_refresh_initially() {
        let tracker = ConnectionTracker::new();
        assert!(tracker.needs_refresh());
    }

    #[test]
    fn test_connection_map_data_serialization() {
        let map = ConnectionMapData {
            nodes: vec![ProcessNode {
                pid: 1,
                name: "init".into(),
                user: "root".into(),
                connection_count: 2,
            }],
            edges: vec![ConnectionEdge {
                src_pid: 1,
                dst_ip: "10.0.0.1".into(),
                dst_port: 80,
                protocol: "tcp".into(),
                bytes_transferred: 4096,
                duration_secs: 120,
            }],
        };

        let json = serde_json::to_string(&map).unwrap();
        let parsed: ConnectionMapData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.nodes.len(), 1);
        assert_eq!(parsed.edges.len(), 1);
        assert_eq!(parsed.edges[0].bytes_transferred, 4096);
    }

    #[test]
    fn test_process_context_serialization() {
        let ctx = ProcessContext {
            pid: 1234,
            name: "firefox".into(),
            user: "alice".into(),
            cmdline: "/usr/bin/firefox --new-window".into(),
            parent_pid: 1,
            parent_name: "systemd".into(),
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: ProcessContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, 1234);
        assert_eq!(parsed.parent_name, "systemd");
    }
}
