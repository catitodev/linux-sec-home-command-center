// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Auditd adapter: installs, configures, and monitors the Linux audit daemon.
//!
//! Provides audit rule management, log parsing for security-relevant events,
//! and tamper detection for the audit log file.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tracing::{error, info, warn};
use uuid::Uuid;

use shared::distro::{DistroInfo, PackageManager};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;
use shared::types::{Entity, NormalizedEvent, Severity, ToolSource};

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Path where custom audit rules are written.
const AUDIT_RULES_PATH: &str = "/etc/audit/rules.d/scc-security.rules";

/// Path to the audit log file.
const AUDIT_LOG_PATH: &str = "/var/log/audit/audit.log";

/// Maximum auto-restart attempts before entering degraded state.
const MAX_RESTART_ATTEMPTS: u32 = 3;

/// Window in seconds within which restart attempts are counted.
const RESTART_WINDOW_SECS: u64 = 60;

/// Interval in seconds for tamper detection checks.
pub const TAMPER_CHECK_INTERVAL_SECS: u64 = 60;

/// Default audit rules for the Security Command Center.
const SCC_AUDIT_RULES: &str = "\
-w /etc/shadow -p wa -k sensitive_file_access
-w /etc/passwd -p wa -k sensitive_file_access
-w /etc/sudoers -p wa -k sensitive_file_access
-w /etc/ssh/sshd_config -p wa -k sensitive_file_access
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_escalation
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_loading
-a always,exit -F arch=b64 -S mount -S umount2 -k mount_operations
";

/// Keys that the adapter filters for when parsing audit logs.
const MONITORED_KEYS: &[&str] = &[
    "sensitive_file_access",
    "privilege_escalation",
    "module_loading",
    "mount_operations",
];

// ─── AuditdAdapter ─────────────────────────────────────────────────────────

/// Adapter for the Linux audit daemon (auditd).
///
/// Manages installation, service lifecycle, rule loading, log parsing,
/// and tamper detection for the audit subsystem.
pub struct AuditdAdapter;

#[async_trait]
impl ToolAdapter for AuditdAdapter {
    fn name(&self) -> &str {
        "auditd"
    }

    fn display_name(&self) -> &str {
        "auditd"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Visibility
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let pkg = match distro.package_manager {
            PackageManager::Apt => "auditd",
            PackageManager::Dnf => "audit",
            PackageManager::Pacman => "audit",
            PackageManager::Zypper => "audit",
        };

        info!(package = pkg, distro = %distro.id, "Installing auditd");

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
                tool: "auditd".to_string(),
                reason: format!("package install failed: {}", output.stderr),
            });
        }

        info!("auditd package installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        // Write custom audit rules.
        write_audit_rules().await?;

        // Start the auditd service.
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["start", "auditd"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "auditd".to_string(),
                reason: format!("failed to start auditd: {}", output.stderr),
            });
        }

        // Load the custom rules into the running audit system.
        load_audit_rules().await?;

        info!("auditd started and rules loaded");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["stop", "auditd"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "auditd".to_string(),
                reason: format!("failed to stop auditd: {}", output.stderr),
            });
        }

        info!("auditd stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("systemctl");
        if cmd.args(&["is-active", "auditd"]).is_err() {
            return HealthStatus::Unhealthy("failed to build health check command".to_string());
        }
        cmd.timeout(Duration::from_secs(10));

        match cmd.execute().await {
            Ok(output) => {
                let status = output.stdout.trim().to_string();
                match status.as_str() {
                    "active" => HealthStatus::Healthy,
                    "inactive" | "dead" => HealthStatus::NotRunning,
                    _ => HealthStatus::Degraded(format!("auditd status: {}", status)),
                }
            }
            Err(e) => HealthStatus::Unhealthy(format!("health check failed: {}", e)),
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        // auditd is available on all supported Linux distributions.
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // ~2 MB typical install size.
        2_000_000
    }
}

// ─── Audit Rules Management ────────────────────────────────────────────────

/// Writes the SCC audit rules to the rules directory.
async fn write_audit_rules() -> Result<()> {
    // Ensure the rules directory exists.
    let rules_dir = Path::new(AUDIT_RULES_PATH)
        .parent()
        .unwrap_or(Path::new("/etc/audit/rules.d"));

    let mut cmd = SafeCommand::new("mkdir");
    cmd.args(&["-p", &rules_dir.to_string_lossy()])?;
    cmd.timeout(Duration::from_secs(5));
    let _ = cmd.execute().await;

    // Write rules file via tee (requires privilege).
    let mut cmd = SafeCommand::new("tee");
    cmd.arg(AUDIT_RULES_PATH)?;
    cmd.timeout(Duration::from_secs(5));

    // We write the rules content via a separate echo | tee approach using dd.
    // Since SafeCommand doesn't support stdin piping, write via shell-free method.
    let mut write_cmd = SafeCommand::new("dd");
    write_cmd.args(&[
        &format!("of={}", AUDIT_RULES_PATH),
        "status=none",
    ])?;
    write_cmd.timeout(Duration::from_secs(5));

    // Fallback: use std::fs::write (requires privilege at runtime).
    tokio::fs::write(AUDIT_RULES_PATH, SCC_AUDIT_RULES)
        .await
        .map_err(|e| CommandCenterError::ToolOperationFailed {
            tool: "auditd".to_string(),
            reason: format!("failed to write audit rules: {}", e),
        })?;

    info!(path = AUDIT_RULES_PATH, "Audit rules written");
    Ok(())
}

/// Loads audit rules into the running audit system using augenrules.
async fn load_audit_rules() -> Result<()> {
    let mut cmd = SafeCommand::new("augenrules");
    cmd.arg("--load")?;
    cmd.timeout(Duration::from_secs(15));

    let output = cmd.execute().await?;
    if output.exit_code != Some(0) {
        return Err(CommandCenterError::ToolOperationFailed {
            tool: "auditd".to_string(),
            reason: format!("augenrules --load failed: {}", output.stderr),
        });
    }

    info!("Audit rules loaded into running system");
    Ok(())
}

/// Returns the default SCC audit rules content.
pub fn default_audit_rules() -> &'static str {
    SCC_AUDIT_RULES
}

// ─── Audit Log Parser ──────────────────────────────────────────────────────

/// A parsed audit event from the audit log.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEvent {
    /// Timestamp of the event (seconds since epoch with milliseconds).
    pub timestamp: f64,
    /// Audit event type (e.g., "SYSCALL", "PATH", "CWD").
    pub event_type: String,
    /// The audit key that matched (e.g., "sensitive_file_access").
    pub key: Option<String>,
    /// All key=value fields from the log line.
    pub fields: HashMap<String, String>,
}

/// Parser for auditd log files.
///
/// Reads and parses audit log lines in the standard key=value format,
/// filtering for events matching the SCC-configured audit keys.
pub struct AuditLogParser {
    /// Path to the audit log file.
    log_path: String,
}

impl AuditLogParser {
    /// Creates a new parser for the default audit log path.
    pub fn new() -> Self {
        Self {
            log_path: AUDIT_LOG_PATH.to_string(),
        }
    }

    /// Creates a new parser for a custom log path (useful for testing).
    pub fn with_path(log_path: &str) -> Self {
        Self {
            log_path: log_path.to_string(),
        }
    }

    /// Returns the configured log path.
    pub fn log_path(&self) -> &str {
        &self.log_path
    }

    /// Parses a single audit log line into an `AuditEvent`.
    ///
    /// Returns `None` if the line cannot be parsed or does not match
    /// any monitored audit key.
    pub fn parse_line(line: &str) -> Option<AuditEvent> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        let mut fields = HashMap::new();
        let mut event_type = String::new();
        let mut timestamp: f64 = 0.0;

        // Parse the type= prefix: "type=SYSCALL msg=audit(1234567890.123:456): ..."
        if let Some(type_start) = line.find("type=") {
            let after_type = &line[type_start + 5..];
            let type_end = after_type
                .find(|c: char| c.is_whitespace())
                .unwrap_or(after_type.len());
            event_type = after_type[..type_end].to_string();
        }

        // Parse the timestamp from msg=audit(EPOCH.MS:SERIAL):
        if let Some(msg_start) = line.find("msg=audit(") {
            let after_msg = &line[msg_start + 10..];
            if let Some(colon_pos) = after_msg.find(':') {
                let ts_str = &after_msg[..colon_pos];
                timestamp = ts_str.parse::<f64>().unwrap_or(0.0);
            }
        }

        // Parse remaining key=value pairs after the "): " delimiter.
        let kv_section = if let Some(delim_pos) = line.find("): ") {
            &line[delim_pos + 3..]
        } else {
            line
        };

        // Parse key=value pairs (handles quoted values).
        parse_kv_pairs(kv_section, &mut fields);

        // Extract the key field — filter for monitored keys only.
        let key = fields.get("key").cloned().map(|k| {
            // Remove surrounding quotes if present.
            k.trim_matches('"').to_string()
        });

        let is_monitored = match &key {
            Some(k) => MONITORED_KEYS.contains(&k.as_str()),
            None => false,
        };

        if !is_monitored {
            return None;
        }

        Some(AuditEvent {
            timestamp,
            event_type,
            key,
            fields,
        })
    }

    /// Converts a parsed `AuditEvent` into a `NormalizedEvent`.
    pub fn to_normalized_event(event: &AuditEvent) -> NormalizedEvent {
        let severity = match event.key.as_deref() {
            Some("privilege_escalation") => Severity::High,
            Some("module_loading") => Severity::High,
            Some("sensitive_file_access") => Severity::Medium,
            Some("mount_operations") => Severity::Low,
            _ => Severity::Info,
        };

        let summary = format!(
            "auditd: {} [{}]",
            event.key.as_deref().unwrap_or("unknown"),
            event.event_type
        );

        // Build entities from available fields.
        let mut entities = Vec::new();

        if let Some(pid_str) = event.fields.get("pid") {
            if let Ok(pid) = pid_str.parse::<u32>() {
                let name = event.fields.get("comm").cloned().map(|c| {
                    c.trim_matches('"').to_string()
                });
                entities.push(Entity::Process { pid, name });
            }
        }

        if let Some(path) = event.fields.get("name") {
            entities.push(Entity::File {
                path: path.trim_matches('"').to_string(),
            });
        }

        if let Some(uid_str) = event.fields.get("uid") {
            if let Ok(uid) = uid_str.parse::<u32>() {
                let user_name = event
                    .fields
                    .get("auid")
                    .cloned()
                    .unwrap_or_else(|| uid.to_string());
                entities.push(Entity::User {
                    name: user_name,
                    uid: Some(uid),
                });
            }
        }

        // Convert epoch timestamp to DateTime<Utc>.
        let timestamp_dt = if event.timestamp > 0.0 {
            DateTime::from_timestamp(
                event.timestamp as i64,
                ((event.timestamp.fract()) * 1_000_000_000.0) as u32,
            )
            .unwrap_or_else(Utc::now)
        } else {
            Utc::now()
        };

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: timestamp_dt,
            source: ToolSource::Auditd,
            severity,
            summary,
            details: Some(format!("{:?}", event.fields)),
            entities,
            acknowledged: false,
            correlation_id: None,
        }
    }
}

impl Default for AuditLogParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parses key=value pairs from an audit log line section.
///
/// Handles both unquoted values (`key=value`) and quoted values (`key="value with spaces"`).
fn parse_kv_pairs(input: &str, fields: &mut HashMap<String, String>) {
    let mut chars = input.chars().peekable();

    while chars.peek().is_some() {
        // Skip whitespace.
        while chars.peek() == Some(&' ') {
            chars.next();
        }

        // Read key.
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' || c == ' ' {
                break;
            }
            key.push(c);
            chars.next();
        }

        if key.is_empty() {
            break;
        }

        // Expect '='.
        if chars.peek() != Some(&'=') {
            continue;
        }
        chars.next(); // consume '='

        // Read value (quoted or unquoted).
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            // Quoted value — read until closing quote.
            chars.next(); // consume opening quote
            while let Some(&c) = chars.peek() {
                if c == '"' {
                    chars.next(); // consume closing quote
                    break;
                }
                value.push(c);
                chars.next();
            }
        } else {
            // Unquoted value — read until whitespace.
            while let Some(&c) = chars.peek() {
                if c == ' ' {
                    break;
                }
                value.push(c);
                chars.next();
            }
        }

        if !key.is_empty() {
            fields.insert(key, value);
        }
    }
}

// ─── Tamper Detection ──────────────────────────────────────────────────────

/// Result of a tamper detection check on the audit log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperCheckResult {
    /// No tampering detected.
    Ok,
    /// File size decreased (possible log truncation).
    SizeDecreased { previous: u64, current: u64 },
    /// File inode changed (file was replaced).
    InodeChanged { previous: u64, current: u64 },
    /// File was removed or is inaccessible.
    FileRemoved,
}

/// Monitors the audit log file for signs of tampering.
///
/// Tracks the file size and inode number between checks. Any decrease in
/// size, change in inode, or file deletion is reported as potential tampering.
pub struct AuditLogTamperDetector {
    /// Path to the audit log file being monitored.
    log_path: String,
    /// Last known file size in bytes.
    last_size: Option<u64>,
    /// Last known inode number.
    last_inode: Option<u64>,
}

impl AuditLogTamperDetector {
    /// Creates a new tamper detector for the default audit log path.
    pub fn new() -> Self {
        Self {
            log_path: AUDIT_LOG_PATH.to_string(),
            last_size: None,
            last_inode: None,
        }
    }

    /// Creates a new tamper detector for a custom path (useful for testing).
    pub fn with_path(log_path: &str) -> Self {
        Self {
            log_path: log_path.to_string(),
            last_size: None,
            last_inode: None,
        }
    }

    /// Returns the configured log path.
    pub fn log_path(&self) -> &str {
        &self.log_path
    }

    /// Performs a tamper check on the audit log file.
    ///
    /// Compares the current file size and inode against previously stored
    /// values. On the first call, stores the baseline and returns `Ok`.
    pub fn check(&mut self) -> TamperCheckResult {
        let metadata = match std::fs::metadata(&self.log_path) {
            Ok(m) => m,
            Err(_) => {
                // File doesn't exist or is inaccessible.
                if self.last_size.is_some() || self.last_inode.is_some() {
                    // We previously had a baseline — file was removed.
                    return TamperCheckResult::FileRemoved;
                }
                // First check and file doesn't exist — not necessarily tampered.
                return TamperCheckResult::FileRemoved;
            }
        };

        let current_size = metadata.len();
        let current_inode = get_inode(&metadata);

        // First check — establish baseline.
        if self.last_size.is_none() && self.last_inode.is_none() {
            self.last_size = Some(current_size);
            self.last_inode = Some(current_inode);
            return TamperCheckResult::Ok;
        }

        // Check for inode change (file replaced).
        if let Some(prev_inode) = self.last_inode {
            if current_inode != prev_inode {
                let result = TamperCheckResult::InodeChanged {
                    previous: prev_inode,
                    current: current_inode,
                };
                // Update baseline after detection.
                self.last_size = Some(current_size);
                self.last_inode = Some(current_inode);
                return result;
            }
        }

        // Check for size decrease (log truncation).
        if let Some(prev_size) = self.last_size {
            if current_size < prev_size {
                let result = TamperCheckResult::SizeDecreased {
                    previous: prev_size,
                    current: current_size,
                };
                // Update baseline after detection.
                self.last_size = Some(current_size);
                self.last_inode = Some(current_inode);
                return result;
            }
        }

        // No tampering — update baseline.
        self.last_size = Some(current_size);
        self.last_inode = Some(current_inode);
        TamperCheckResult::Ok
    }
}

impl Default for AuditLogTamperDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Extracts the inode number from file metadata (Unix-specific).
#[cfg(unix)]
fn get_inode(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.ino()
}

#[cfg(not(unix))]
fn get_inode(_metadata: &std::fs::Metadata) -> u64 {
    0
}

// ─── Auto-Restart Logic ────────────────────────────────────────────────────

/// Tracks restart attempts for the auditd service.
///
/// Implements the policy: up to 3 restart attempts within a 60-second window.
/// After exhausting attempts, the adapter enters a degraded state and emits
/// a critical alert.
pub struct AuditdRestartTracker {
    /// Timestamps of recent restart attempts.
    attempts: Vec<std::time::Instant>,
    /// Whether the tracker has entered degraded state.
    degraded: bool,
}

impl AuditdRestartTracker {
    /// Creates a new restart tracker.
    pub fn new() -> Self {
        Self {
            attempts: Vec::new(),
            degraded: false,
        }
    }

    /// Returns whether the service is in degraded state (exhausted restarts).
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Attempts a restart. Returns `true` if the restart is allowed,
    /// `false` if the maximum attempts have been exhausted.
    ///
    /// When `false` is returned, the tracker enters degraded state and
    /// the caller should emit a critical alert.
    pub fn attempt_restart(&mut self) -> bool {
        if self.degraded {
            return false;
        }

        let now = std::time::Instant::now();
        let window = Duration::from_secs(RESTART_WINDOW_SECS);

        // Remove attempts outside the window.
        self.attempts.retain(|t| now.duration_since(*t) < window);

        if self.attempts.len() >= MAX_RESTART_ATTEMPTS as usize {
            // Exhausted restart attempts within the window.
            self.degraded = true;
            error!(
                attempts = MAX_RESTART_ATTEMPTS,
                window_secs = RESTART_WINDOW_SECS,
                "auditd restart attempts exhausted — entering degraded state"
            );
            return false;
        }

        self.attempts.push(now);
        warn!(
            attempt = self.attempts.len(),
            max = MAX_RESTART_ATTEMPTS,
            "Attempting auditd restart"
        );
        true
    }

    /// Resets the tracker (e.g., after manual intervention).
    pub fn reset(&mut self) {
        self.attempts.clear();
        self.degraded = false;
    }
}

impl Default for AuditdRestartTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line_syscall_sensitive_file() {
        let line = "type=SYSCALL msg=audit(1700000000.123:1234): arch=c000003e \
                    syscall=257 success=yes exit=3 pid=1001 uid=1000 \
                    comm=\"vim\" key=\"sensitive_file_access\"";

        let event = AuditLogParser::parse_line(line).unwrap();
        assert_eq!(event.event_type, "SYSCALL");
        assert_eq!(event.key.as_deref(), Some("sensitive_file_access"));
        assert!((event.timestamp - 1_700_000_000.123).abs() < 0.001);
        assert_eq!(event.fields.get("pid"), Some(&"1001".to_string()));
        assert_eq!(event.fields.get("comm"), Some(&"vim".to_string()));
    }

    #[test]
    fn test_parse_line_privilege_escalation() {
        let line = "type=SYSCALL msg=audit(1700000001.456:5678): arch=c000003e \
                    syscall=117 success=yes pid=2002 uid=0 \
                    key=\"privilege_escalation\"";

        let event = AuditLogParser::parse_line(line).unwrap();
        assert_eq!(event.key.as_deref(), Some("privilege_escalation"));
        assert_eq!(event.fields.get("uid"), Some(&"0".to_string()));
    }

    #[test]
    fn test_parse_line_module_loading() {
        let line = "type=SYSCALL msg=audit(1700000002.789:9012): arch=c000003e \
                    syscall=175 success=yes pid=3003 uid=0 \
                    comm=\"modprobe\" key=\"module_loading\"";

        let event = AuditLogParser::parse_line(line).unwrap();
        assert_eq!(event.key.as_deref(), Some("module_loading"));
        assert_eq!(event.fields.get("comm"), Some(&"modprobe".to_string()));
    }

    #[test]
    fn test_parse_line_mount_operations() {
        let line = "type=SYSCALL msg=audit(1700000003.000:1111): arch=c000003e \
                    syscall=165 success=yes pid=4004 uid=0 \
                    key=\"mount_operations\"";

        let event = AuditLogParser::parse_line(line).unwrap();
        assert_eq!(event.key.as_deref(), Some("mount_operations"));
    }

    #[test]
    fn test_parse_line_unmonitored_key_returns_none() {
        let line = "type=SYSCALL msg=audit(1700000004.000:2222): arch=c000003e \
                    syscall=59 success=yes pid=5005 uid=1000 \
                    key=\"some_other_key\"";

        assert!(AuditLogParser::parse_line(line).is_none());
    }

    #[test]
    fn test_parse_line_no_key_returns_none() {
        let line = "type=SYSCALL msg=audit(1700000005.000:3333): arch=c000003e \
                    syscall=59 success=yes pid=6006 uid=1000";

        assert!(AuditLogParser::parse_line(line).is_none());
    }

    #[test]
    fn test_parse_line_empty_returns_none() {
        assert!(AuditLogParser::parse_line("").is_none());
        assert!(AuditLogParser::parse_line("   ").is_none());
    }

    #[test]
    fn test_parse_line_quoted_values() {
        let line = "type=PATH msg=audit(1700000006.000:4444): \
                    name=\"/etc/shadow\" inode=12345 \
                    key=\"sensitive_file_access\"";

        let event = AuditLogParser::parse_line(line).unwrap();
        assert_eq!(event.fields.get("name"), Some(&"/etc/shadow".to_string()));
    }

    #[test]
    fn test_to_normalized_event_severity_mapping() {
        let event = AuditEvent {
            timestamp: 1_700_000_000.0,
            event_type: "SYSCALL".to_string(),
            key: Some("privilege_escalation".to_string()),
            fields: HashMap::new(),
        };
        let normalized = AuditLogParser::to_normalized_event(&event);
        assert_eq!(normalized.severity, Severity::High);
        assert_eq!(normalized.source, ToolSource::Auditd);

        let event2 = AuditEvent {
            timestamp: 1_700_000_000.0,
            event_type: "SYSCALL".to_string(),
            key: Some("sensitive_file_access".to_string()),
            fields: HashMap::new(),
        };
        let normalized2 = AuditLogParser::to_normalized_event(&event2);
        assert_eq!(normalized2.severity, Severity::Medium);
    }

    #[test]
    fn test_to_normalized_event_entities() {
        let mut fields = HashMap::new();
        fields.insert("pid".to_string(), "1234".to_string());
        fields.insert("comm".to_string(), "vim".to_string());
        fields.insert("uid".to_string(), "1000".to_string());
        fields.insert("name".to_string(), "/etc/shadow".to_string());

        let event = AuditEvent {
            timestamp: 1_700_000_000.0,
            event_type: "SYSCALL".to_string(),
            key: Some("sensitive_file_access".to_string()),
            fields,
        };

        let normalized = AuditLogParser::to_normalized_event(&event);
        assert!(!normalized.entities.is_empty());
        // Should have process, file, and user entities.
        assert!(normalized.entities.iter().any(|e| matches!(e, Entity::Process { pid: 1234, .. })));
        assert!(normalized.entities.iter().any(|e| matches!(e, Entity::File { path } if path == "/etc/shadow")));
        assert!(normalized.entities.iter().any(|e| matches!(e, Entity::User { uid: Some(1000), .. })));
    }

    #[test]
    fn test_tamper_detector_first_check_establishes_baseline() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_audit_tamper_baseline.log");
        std::fs::write(&path, "initial content").unwrap();

        let mut detector = AuditLogTamperDetector::with_path(path.to_str().unwrap());
        assert_eq!(detector.check(), TamperCheckResult::Ok);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_tamper_detector_size_decrease() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_audit_tamper_size.log");
        std::fs::write(&path, "a]".repeat(100)).unwrap();

        let mut detector = AuditLogTamperDetector::with_path(path.to_str().unwrap());
        assert_eq!(detector.check(), TamperCheckResult::Ok);

        // Truncate the file.
        std::fs::write(&path, "small").unwrap();
        let result = detector.check();
        assert!(matches!(result, TamperCheckResult::SizeDecreased { .. }));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_tamper_detector_file_removed() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_audit_tamper_removed.log");
        std::fs::write(&path, "content").unwrap();

        let mut detector = AuditLogTamperDetector::with_path(path.to_str().unwrap());
        assert_eq!(detector.check(), TamperCheckResult::Ok);

        // Remove the file.
        std::fs::remove_file(&path).unwrap();
        assert_eq!(detector.check(), TamperCheckResult::FileRemoved);
    }

    #[test]
    fn test_tamper_detector_size_increase_is_ok() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_audit_tamper_grow.log");
        std::fs::write(&path, "initial").unwrap();

        let mut detector = AuditLogTamperDetector::with_path(path.to_str().unwrap());
        assert_eq!(detector.check(), TamperCheckResult::Ok);

        // Grow the file.
        std::fs::write(&path, "initial plus more content").unwrap();
        assert_eq!(detector.check(), TamperCheckResult::Ok);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_restart_tracker_allows_up_to_max_attempts() {
        let mut tracker = AuditdRestartTracker::new();
        assert!(!tracker.is_degraded());

        // First 3 attempts should succeed.
        assert!(tracker.attempt_restart());
        assert!(tracker.attempt_restart());
        assert!(tracker.attempt_restart());

        // 4th attempt should fail — degraded.
        assert!(!tracker.attempt_restart());
        assert!(tracker.is_degraded());
    }

    #[test]
    fn test_restart_tracker_reset() {
        let mut tracker = AuditdRestartTracker::new();
        assert!(tracker.attempt_restart());
        assert!(tracker.attempt_restart());
        assert!(tracker.attempt_restart());
        assert!(!tracker.attempt_restart());
        assert!(tracker.is_degraded());

        tracker.reset();
        assert!(!tracker.is_degraded());
        assert!(tracker.attempt_restart());
    }

    #[test]
    fn test_restart_tracker_degraded_always_returns_false() {
        let mut tracker = AuditdRestartTracker::new();
        for _ in 0..3 {
            tracker.attempt_restart();
        }
        assert!(!tracker.attempt_restart());
        assert!(!tracker.attempt_restart());
        assert!(!tracker.attempt_restart());
    }

    #[test]
    fn test_adapter_metadata() {
        let adapter = AuditdAdapter;
        assert_eq!(adapter.name(), "auditd");
        assert_eq!(adapter.display_name(), "auditd");
        assert_eq!(adapter.category(), ToolCategory::Visibility);
    }

    #[test]
    fn test_adapter_available_for_all_distros() {
        let adapter = AuditdAdapter;
        let distro = shared::distro::detect_distro_from_content(
            "ID=ubuntu\nVERSION_ID=\"22.04\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&distro));

        let distro2 = shared::distro::detect_distro_from_content(
            "ID=arch\nNAME=\"Arch Linux\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&distro2));
    }

    #[test]
    fn test_default_audit_rules_content() {
        let rules = default_audit_rules();
        assert!(rules.contains("/etc/shadow"));
        assert!(rules.contains("/etc/passwd"));
        assert!(rules.contains("/etc/sudoers"));
        assert!(rules.contains("/etc/ssh/sshd_config"));
        assert!(rules.contains("privilege_escalation"));
        assert!(rules.contains("module_loading"));
        assert!(rules.contains("mount_operations"));
    }

    #[test]
    fn test_parse_kv_pairs_basic() {
        let mut fields = HashMap::new();
        parse_kv_pairs("arch=c000003e syscall=257 success=yes", &mut fields);
        assert_eq!(fields.get("arch"), Some(&"c000003e".to_string()));
        assert_eq!(fields.get("syscall"), Some(&"257".to_string()));
        assert_eq!(fields.get("success"), Some(&"yes".to_string()));
    }

    #[test]
    fn test_parse_kv_pairs_quoted() {
        let mut fields = HashMap::new();
        parse_kv_pairs("name=\"/etc/shadow\" mode=0644", &mut fields);
        assert_eq!(fields.get("name"), Some(&"/etc/shadow".to_string()));
        assert_eq!(fields.get("mode"), Some(&"0644".to_string()));
    }
}
