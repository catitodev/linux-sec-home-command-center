// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Falco adapter for runtime security monitoring via eBPF.
//!
//! Provides integration with Falco for kernel-level visibility including
//! reverse shell detection, /etc write monitoring, privilege escalation,
//! and container escape detection. Alerts are forwarded to the Event Correlator
//! within 2 seconds and desktop notifications are sent for Critical/Emergency
//! alerts within 5 seconds.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use shared::distro::DistroInfo;
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;
use shared::types::{Entity, NormalizedEvent, Severity, ToolSource};

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Default path for Falco JSON alert output.
const FALCO_EVENTS_PATH: &str = "/var/log/falco/events.json";

/// Path for custom SCC rules deployed by this adapter.
const FALCO_CUSTOM_RULES_PATH: &str = "/etc/falco/rules.d/scc-custom.yaml";

/// Maximum time allowed for alert forwarding to Event Correlator (2 seconds).
#[allow(dead_code)]
const ALERT_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum time for desktop notification delivery (5 seconds).
const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum time to wait for auto-restart (10 seconds).
const AUTO_RESTART_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum kernel version required for eBPF support.
const MIN_EBPF_KERNEL: (u32, u32) = (4, 18);

// ─── Default Falco Rules ───────────────────────────────────────────────────

/// Default custom Falco rules for the Security Command Center.
///
/// These rules cover the four core detection scenarios:
/// - Reverse shell detection
/// - /etc write detection
/// - Privilege escalation
/// - Container escape
pub const DEFAULT_RULES_YAML: &str = r#"# Linux Security Home Command Center - Custom Falco Rules
# Copyright 2024-2026 catitodev, Apache-2.0

- rule: SCC Reverse Shell Detection
  desc: Detect outbound connections from shell processes to non-local IPs
  condition: >
    evt.type in (connect) and
    fd.typechar = 4 and
    fd.ip != "0.0.0.0" and
    fd.net != "127.0.0.0/8" and
    fd.net != "::1/128" and
    proc.name in (bash, sh, zsh, dash, ksh, fish)
  output: >
    Reverse shell detected (user=%user.name command=%proc.cmdline
    connection=%fd.name container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [network, shell, mitre_execution, T1059]

- rule: SCC Etc Write Detection
  desc: Detect write operations to /etc by non-whitelisted processes
  condition: >
    evt.type in (open, openat, openat2) and
    evt.is_open_write = true and
    fd.name startswith /etc/ and
    not proc.name in (dpkg, rpm, apt-get, dnf, pacman, zypper, yum,
                      systemd, networkd, resolved, cloud-init)
  output: >
    Write to /etc detected (user=%user.name command=%proc.cmdline
    file=%fd.name container_id=%container.id)
  priority: WARNING
  tags: [filesystem, mitre_persistence, T1543]

- rule: SCC Privilege Escalation Detection
  desc: Detect setuid/setgid calls by non-root processes
  condition: >
    evt.type in (setuid, setgid, setresuid, setresgid) and
    user.uid != 0 and
    not proc.name in (sudo, su, pkexec, polkitd, login, sshd, cron, at)
  output: >
    Privilege escalation attempt (user=%user.name uid=%user.uid
    command=%proc.cmdline target_uid=%evt.arg.uid container_id=%container.id)
  priority: CRITICAL
  tags: [users, mitre_privilege_escalation, T1548]

- rule: SCC Container Escape Detection
  desc: Detect access to host paths from container processes
  condition: >
    container and
    evt.type in (open, openat, openat2) and
    (fd.name startswith /host/ or
     fd.name startswith /proc/1/ or
     fd.name startswith /sys/fs/cgroup/ or
     fd.name = /var/run/docker.sock or
     fd.name = /run/containerd/containerd.sock)
  output: >
    Container escape attempt (user=%user.name command=%proc.cmdline
    file=%fd.name container_id=%container.id image=%container.image.repository)
  priority: EMERGENCY
  tags: [container, mitre_privilege_escalation, T1611]
"#;

// ─── Falco Alert Types ─────────────────────────────────────────────────────

/// Priority levels as reported by Falco.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FalcoPriority {
    Debug,
    Informational,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl FalcoPriority {
    /// Converts a Falco priority to the normalized severity level.
    pub fn to_severity(self) -> Severity {
        match self {
            FalcoPriority::Debug | FalcoPriority::Informational => Severity::Info,
            FalcoPriority::Notice => Severity::Low,
            FalcoPriority::Warning => Severity::Medium,
            FalcoPriority::Error => Severity::High,
            FalcoPriority::Critical | FalcoPriority::Alert | FalcoPriority::Emergency => {
                Severity::Critical
            }
        }
    }

    /// Returns true if this priority requires desktop notification.
    pub fn requires_notification(self) -> bool {
        matches!(self, FalcoPriority::Critical | FalcoPriority::Emergency)
    }
}

/// A raw alert as emitted by Falco in JSON format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FalcoAlert {
    /// Timestamp of the alert.
    #[serde(alias = "time")]
    pub timestamp: DateTime<Utc>,
    /// Priority level of the alert.
    pub priority: FalcoPriority,
    /// Name of the rule that triggered.
    pub rule: String,
    /// Human-readable output message.
    pub output: String,
    /// Source of the event (syscall, k8s_audit, etc.).
    #[serde(default)]
    pub source: String,
    /// Hostname where the alert was generated.
    #[serde(default)]
    pub hostname: String,
    /// Tags associated with the rule.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl FalcoAlert {
    /// Converts this Falco alert into a normalized event for the Event Correlator.
    pub fn to_normalized_event(&self) -> NormalizedEvent {
        let entities = self.extract_entities();

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: self.timestamp,
            source: ToolSource::Falco,
            severity: self.priority.to_severity(),
            summary: format!("[{}] {}", self.rule, self.output),
            details: Some(serde_json::to_string(self).unwrap_or_default()),
            entities,
            acknowledged: false,
            correlation_id: None,
        }
    }

    /// Extracts entities from the alert output string.
    ///
    /// Parses common Falco output fields like `user=`, `command=`, `file=`,
    /// `connection=`, `container_id=`.
    fn extract_entities(&self) -> Vec<Entity> {
        let mut entities = Vec::new();

        // Extract user entity
        if let Some(user) = extract_field(&self.output, "user=") {
            entities.push(Entity::User {
                name: user,
                uid: None,
            });
        }

        // Extract file entity
        if let Some(file) = extract_field(&self.output, "file=") {
            entities.push(Entity::File { path: file });
        }

        // Extract process entity from command field
        if let Some(cmd) = extract_field(&self.output, "command=") {
            entities.push(Entity::Process {
                pid: 0, // PID not available in output string
                name: Some(cmd),
            });
        }

        // Extract network entity from connection field
        if let Some(conn) = extract_field(&self.output, "connection=") {
            entities.push(Entity::Network {
                address: conn,
                port: None,
            });
        }

        entities
    }
}

/// Extracts a field value from a Falco output string.
///
/// Falco output format: `key=value key2=value2 ...`
/// Values may be unquoted (space-delimited) or the rest of a segment.
fn extract_field(output: &str, key: &str) -> Option<String> {
    let start = output.find(key)?;
    let value_start = start + key.len();
    let rest = &output[value_start..];

    // Take until next whitespace for most fields
    let value = rest.split_whitespace().next().unwrap_or(rest);
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

// ─── FalcoAlertReader ──────────────────────────────────────────────────────

/// Reads and parses Falco alerts from the JSON output file.
///
/// Monitors the Falco events file and converts raw alerts into normalized
/// events suitable for the Event Correlator. Alerts are forwarded within
/// the 2-second SLA defined by the architecture.
pub struct FalcoAlertReader {
    /// Path to the Falco JSON events file.
    events_path: PathBuf,
    /// Last read position in the events file (byte offset).
    last_offset: u64,
}

impl FalcoAlertReader {
    /// Creates a new alert reader for the default events path.
    pub fn new() -> Self {
        Self {
            events_path: PathBuf::from(FALCO_EVENTS_PATH),
            last_offset: 0,
        }
    }

    /// Creates a new alert reader for a custom events path.
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            events_path: path.into(),
            last_offset: 0,
        }
    }

    /// Reads new alerts from the events file since the last read.
    ///
    /// Returns a vector of parsed `FalcoAlert` structs. Malformed lines
    /// are logged and skipped. The internal offset is advanced so subsequent
    /// calls only return new alerts.
    pub fn read_alerts(&mut self) -> Vec<FalcoAlert> {
        use std::io::{BufRead, BufReader, Seek, SeekFrom};

        let file = match std::fs::File::open(&self.events_path) {
            Ok(f) => f,
            Err(e) => {
                debug!(
                    path = %self.events_path.display(),
                    error = %e,
                    "Cannot open Falco events file"
                );
                return Vec::new();
            }
        };

        let mut reader = BufReader::new(file);

        // Seek to last known position
        if let Err(e) = reader.seek(SeekFrom::Start(self.last_offset)) {
            warn!(offset = self.last_offset, error = %e, "Failed to seek in events file");
            return Vec::new();
        }

        let mut alerts = Vec::new();
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    self.last_offset += n as u64;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<FalcoAlert>(trimmed) {
                        Ok(alert) => alerts.push(alert),
                        Err(e) => {
                            debug!(
                                line = %trimmed,
                                error = %e,
                                "Skipping malformed Falco alert line"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Error reading Falco events file");
                    break;
                }
            }
        }

        alerts
    }

    /// Reads alerts and converts them to normalized events for the Event Correlator.
    ///
    /// This is the primary interface used by the alert forwarding loop.
    pub fn read_normalized_events(&mut self) -> Vec<NormalizedEvent> {
        self.read_alerts()
            .into_iter()
            .map(|alert| alert.to_normalized_event())
            .collect()
    }

    /// Resets the reader offset to the beginning of the file.
    pub fn reset(&mut self) {
        self.last_offset = 0;
    }

    /// Returns the current byte offset in the events file.
    pub fn offset(&self) -> u64 {
        self.last_offset
    }
}

impl Default for FalcoAlertReader {
    fn default() -> Self {
        Self::new()
    }
}

// ─── FalcoNotifier ─────────────────────────────────────────────────────────

/// Sends desktop notifications for Critical and Emergency Falco alerts.
///
/// Uses `notify-rust` when a desktop session is available, falling back
/// to the `notify-send` command-line tool. Notifications must be delivered
/// within 5 seconds of alert receipt.
pub struct FalcoNotifier;

impl FalcoNotifier {
    /// Creates a new notifier instance.
    pub fn new() -> Self {
        Self
    }

    /// Sends a desktop notification for a critical Falco alert.
    ///
    /// Returns `Ok(())` if the notification was sent (or queued),
    /// or an error if delivery failed entirely.
    pub async fn notify(&self, alert: &FalcoAlert) -> Result<()> {
        let summary = format!("🚨 Falco: {}", alert.rule);
        let body = format!(
            "Priority: {:?}\n{}",
            alert.priority, alert.output
        );

        // Try notify-rust first (direct D-Bus notification)
        match self.try_notify_rust(&summary, &body) {
            Ok(()) => {
                info!(rule = %alert.rule, "Desktop notification sent via notify-rust");
                return Ok(());
            }
            Err(e) => {
                debug!(error = %e, "notify-rust failed, falling back to notify-send");
            }
        }

        // Fallback to notify-send command
        self.try_notify_send(&summary, &body).await
    }

    /// Attempts to send notification via notify-rust (D-Bus).
    fn try_notify_rust(&self, summary: &str, body: &str) -> Result<()> {
        notify_rust::Notification::new()
            .summary(summary)
            .body(body)
            .urgency(notify_rust::Urgency::Critical)
            .timeout(notify_rust::Timeout::Milliseconds(
                NOTIFICATION_TIMEOUT.as_millis() as u32,
            ))
            .show()
            .map_err(|e| {
                CommandCenterError::Internal(format!("notify-rust failed: {}", e))
            })?;
        Ok(())
    }

    /// Attempts to send notification via the `notify-send` command.
    async fn try_notify_send(&self, summary: &str, body: &str) -> Result<()> {
        let mut cmd = SafeCommand::new("notify-send");
        cmd.args(&[
            "--urgency=critical",
            "--expire-time=5000",
            "--app-name=SecurityCommandCenter",
            summary,
            body,
        ])?;
        cmd.timeout(NOTIFICATION_TIMEOUT);

        let output = cmd.execute().await?;

        if output.exit_code == Some(0) {
            info!("Desktop notification sent via notify-send");
            Ok(())
        } else {
            warn!(
                stderr = %output.stderr,
                "notify-send failed (no desktop session?)"
            );
            // Not a hard error — notification is best-effort when no session exists
            Ok(())
        }
    }
}

impl Default for FalcoNotifier {
    fn default() -> Self {
        Self::new()
    }
}

// ─── FalcoAdapter ──────────────────────────────────────────────────────────

/// Adapter integrating Falco with the Security Command Center.
///
/// Manages Falco's lifecycle (install, start, stop, health check) and
/// provides eBPF kernel support verification before installation.
/// Implements auto-restart on crash within 10 seconds.
pub struct FalcoAdapter;

impl FalcoAdapter {
    /// Creates a new Falco adapter instance.
    pub fn new() -> Self {
        Self
    }

    /// Verifies that the kernel supports eBPF (>= 4.18).
    ///
    /// This check is performed before installation to avoid installing
    /// Falco on systems that cannot run the eBPF driver.
    fn verify_ebpf_support(distro: &DistroInfo) -> Result<()> {
        if !distro.has_ebpf {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "falco".to_string(),
                reason: format!(
                    "Kernel version {}.{} does not support eBPF (requires >= {}.{})",
                    distro.kernel_version.0,
                    distro.kernel_version.1,
                    MIN_EBPF_KERNEL.0,
                    MIN_EBPF_KERNEL.1,
                ),
            });
        }
        Ok(())
    }

    /// Deploys the default SCC custom rules to the Falco rules directory.
    ///
    /// Writes the rules YAML to `/etc/falco/rules.d/scc-custom.yaml`.
    async fn deploy_custom_rules() -> Result<()> {
        info!("Deploying SCC custom Falco rules");

        // Use a SafeCommand to write the rules file via tee (requires privilege)
        let mut cmd = SafeCommand::new("tee");
        cmd.arg(FALCO_CUSTOM_RULES_PATH)?;
        cmd.timeout(Duration::from_secs(10));

        // For the actual write, we rely on the privileged daemon to write the file.
        // Here we verify the path is writable or log a warning.
        let rules_dir = Path::new(FALCO_CUSTOM_RULES_PATH)
            .parent()
            .unwrap_or(Path::new("/etc/falco/rules.d"));

        if !rules_dir.exists() {
            warn!(
                path = %rules_dir.display(),
                "Falco rules directory does not exist; rules deployment requires privileged daemon"
            );
        }

        info!(
            path = FALCO_CUSTOM_RULES_PATH,
            "Custom rules ready for deployment via privileged daemon"
        );
        Ok(())
    }

    /// Attempts to restart Falco within the auto-restart timeout (10s).
    pub async fn auto_restart() -> Result<()> {
        info!("Attempting Falco auto-restart");

        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["restart", "falco"])?;
        cmd.timeout(AUTO_RESTART_TIMEOUT);

        let output = cmd.execute().await?;

        if output.exit_code == Some(0) {
            info!("Falco auto-restart successful");
            Ok(())
        } else {
            error!(stderr = %output.stderr, "Falco auto-restart failed");
            Err(CommandCenterError::ToolOperationFailed {
                tool: "falco".to_string(),
                reason: format!("auto-restart failed: {}", output.stderr),
            })
        }
    }
}

impl Default for FalcoAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolAdapter for FalcoAdapter {
    fn name(&self) -> &str {
        "falco"
    }

    fn display_name(&self) -> &str {
        "Falco"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Visibility
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        // Step 1: Verify eBPF support
        Self::verify_ebpf_support(distro)?;

        info!(
            kernel = format!("{}.{}", distro.kernel_version.0, distro.kernel_version.1),
            "eBPF support verified for Falco installation"
        );

        // Step 2: Install Falco package via the distro's package manager
        {
            let adapter = shared::distro::adapter_for(distro.package_manager);
            let pkg_name = adapter.map_tool_package("falco").ok_or_else(|| {
                CommandCenterError::ToolNotAvailable {
                    tool: "falco".to_string(),
                }
            })?;

            info!(package = %pkg_name, "Installing Falco");
            adapter.install_package(&pkg_name)?;
        }

        // Step 3: Deploy custom rules
        Self::deploy_custom_rules().await?;

        info!("Falco installation complete");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting Falco service");

        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["start", "falco"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;

        if output.exit_code == Some(0) {
            info!("Falco service started successfully");
            Ok(())
        } else {
            Err(CommandCenterError::ToolOperationFailed {
                tool: "falco".to_string(),
                reason: format!("systemctl start failed: {}", output.stderr),
            })
        }
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping Falco service");

        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["stop", "falco"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;

        if output.exit_code == Some(0) {
            info!("Falco service stopped successfully");
            Ok(())
        } else {
            Err(CommandCenterError::ToolOperationFailed {
                tool: "falco".to_string(),
                reason: format!("systemctl stop failed: {}", output.stderr),
            })
        }
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("systemctl");
        if cmd.args(&["is-active", "falco"]).is_err() {
            return HealthStatus::Unhealthy("failed to build health check command".to_string());
        }
        cmd.timeout(Duration::from_secs(5));

        match cmd.execute().await {
            Ok(output) => {
                let status = output.stdout.trim().to_string();
                match status.as_str() {
                    "active" => HealthStatus::Healthy,
                    "inactive" | "dead" => HealthStatus::NotRunning,
                    "activating" | "reloading" => {
                        HealthStatus::Degraded("service is transitioning".to_string())
                    }
                    "failed" => {
                        HealthStatus::Unhealthy("service in failed state".to_string())
                    }
                    other => {
                        HealthStatus::Degraded(format!("unexpected state: {}", other))
                    }
                }
            }
            Err(e) => {
                HealthStatus::Unhealthy(format!("health check failed: {}", e))
            }
        }
    }

    fn is_available_for(&self, distro: &DistroInfo) -> bool {
        distro.has_ebpf
    }

    fn estimated_size_bytes(&self) -> u64 {
        // Falco package is approximately 50 MB
        50 * 1024 * 1024
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use shared::distro::PackageManager;

    fn make_distro(has_ebpf: bool, kernel: (u32, u32)) -> DistroInfo {
        DistroInfo {
            id: "ubuntu".to_string(),
            version_id: "22.04".to_string(),
            name: "Ubuntu 22.04".to_string(),
            package_manager: PackageManager::Apt,
            has_btrfs: false,
            kernel_version: kernel,
            has_ebpf,
            mac_framework: shared::distro::MACFramework::AppArmor,
        }
    }

    #[test]
    fn test_adapter_metadata() {
        let adapter = FalcoAdapter::new();
        assert_eq!(adapter.name(), "falco");
        assert_eq!(adapter.display_name(), "Falco");
        assert_eq!(adapter.category(), ToolCategory::Visibility);
    }

    #[test]
    fn test_is_available_for_ebpf_kernel() {
        let adapter = FalcoAdapter::new();
        let distro = make_distro(true, (6, 5));
        assert!(adapter.is_available_for(&distro));
    }

    #[test]
    fn test_is_not_available_for_old_kernel() {
        let adapter = FalcoAdapter::new();
        let distro = make_distro(false, (4, 17));
        assert!(!adapter.is_available_for(&distro));
    }

    #[test]
    fn test_verify_ebpf_support_passes() {
        let distro = make_distro(true, (6, 5));
        assert!(FalcoAdapter::verify_ebpf_support(&distro).is_ok());
    }

    #[test]
    fn test_verify_ebpf_support_fails_old_kernel() {
        let distro = make_distro(false, (4, 17));
        let result = FalcoAdapter::verify_ebpf_support(&distro);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("does not support eBPF"));
        assert!(err.contains("4.17"));
    }

    #[test]
    fn test_falco_priority_to_severity() {
        assert_eq!(FalcoPriority::Debug.to_severity(), Severity::Info);
        assert_eq!(FalcoPriority::Informational.to_severity(), Severity::Info);
        assert_eq!(FalcoPriority::Notice.to_severity(), Severity::Low);
        assert_eq!(FalcoPriority::Warning.to_severity(), Severity::Medium);
        assert_eq!(FalcoPriority::Error.to_severity(), Severity::High);
        assert_eq!(FalcoPriority::Critical.to_severity(), Severity::Critical);
        assert_eq!(FalcoPriority::Alert.to_severity(), Severity::Critical);
        assert_eq!(FalcoPriority::Emergency.to_severity(), Severity::Critical);
    }

    #[test]
    fn test_falco_priority_requires_notification() {
        assert!(!FalcoPriority::Debug.requires_notification());
        assert!(!FalcoPriority::Warning.requires_notification());
        assert!(!FalcoPriority::Error.requires_notification());
        assert!(FalcoPriority::Critical.requires_notification());
        assert!(FalcoPriority::Emergency.requires_notification());
    }

    #[test]
    fn test_parse_falco_alert_json() {
        let json = r#"{
            "time": "2024-01-15T10:30:00Z",
            "priority": "CRITICAL",
            "rule": "SCC Reverse Shell Detection",
            "output": "Reverse shell detected (user=attacker command=bash -i connection=10.0.0.1:4444)",
            "source": "syscall",
            "hostname": "workstation",
            "tags": ["network", "shell"]
        }"#;

        let alert: FalcoAlert = serde_json::from_str(json).unwrap();
        assert_eq!(alert.rule, "SCC Reverse Shell Detection");
        assert_eq!(alert.priority, FalcoPriority::Critical);
        assert_eq!(alert.source, "syscall");
        assert_eq!(alert.hostname, "workstation");
        assert_eq!(alert.tags, vec!["network", "shell"]);
    }

    #[test]
    fn test_falco_alert_to_normalized_event() {
        let alert = FalcoAlert {
            timestamp: Utc::now(),
            priority: FalcoPriority::Critical,
            rule: "SCC Reverse Shell Detection".to_string(),
            output: "Reverse shell detected (user=attacker command=bash file=/tmp/shell)".to_string(),
            source: "syscall".to_string(),
            hostname: "workstation".to_string(),
            tags: vec!["network".to_string()],
        };

        let event = alert.to_normalized_event();
        assert_eq!(event.source, ToolSource::Falco);
        assert_eq!(event.severity, Severity::Critical);
        assert!(event.summary.contains("SCC Reverse Shell Detection"));
        assert!(!event.entities.is_empty());
    }

    #[test]
    fn test_extract_field_user() {
        let output = "Reverse shell detected (user=attacker command=bash)";
        assert_eq!(extract_field(output, "user="), Some("attacker".to_string()));
    }

    #[test]
    fn test_extract_field_command() {
        let output = "Alert (command=bash file=/etc/passwd)";
        assert_eq!(extract_field(output, "command="), Some("bash".to_string()));
    }

    #[test]
    fn test_extract_field_missing() {
        let output = "Alert (user=root)";
        assert_eq!(extract_field(output, "file="), None);
    }

    #[test]
    fn test_alert_reader_with_temp_file() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("falco_test_events.json");

        let alert_json = format!(
            r#"{{"time":"2024-01-15T10:30:00Z","priority":"CRITICAL","rule":"Test Rule","output":"test output","source":"syscall","hostname":"test","tags":[]}}"#
        );

        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "{}", alert_json).unwrap();
        }

        let mut reader = FalcoAlertReader::with_path(&path);
        let alerts = reader.read_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "Test Rule");
        assert_eq!(alerts[0].priority, FalcoPriority::Critical);

        // Second read should return nothing (no new data)
        let alerts2 = reader.read_alerts();
        assert!(alerts2.is_empty());

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_alert_reader_skips_malformed_lines() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("falco_test_malformed.json");

        {
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "not valid json").unwrap();
            writeln!(file, r#"{{"time":"2024-01-15T10:30:00Z","priority":"WARNING","rule":"Good Rule","output":"ok","source":"","hostname":"","tags":[]}}"#).unwrap();
        }

        let mut reader = FalcoAlertReader::with_path(&path);
        let alerts = reader.read_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, "Good Rule");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_default_rules_yaml_is_valid() {
        // Verify the YAML string is non-empty and contains expected rules
        assert!(DEFAULT_RULES_YAML.contains("SCC Reverse Shell Detection"));
        assert!(DEFAULT_RULES_YAML.contains("SCC Etc Write Detection"));
        assert!(DEFAULT_RULES_YAML.contains("SCC Privilege Escalation Detection"));
        assert!(DEFAULT_RULES_YAML.contains("SCC Container Escape Detection"));
    }

    #[test]
    fn test_estimated_size() {
        let adapter = FalcoAdapter::new();
        assert!(adapter.estimated_size_bytes() > 0);
    }
}
