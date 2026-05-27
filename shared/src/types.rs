// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Common types used across the Linux Security Home Command Center.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severity levels for security events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational event, no action required.
    Info,
    /// Low severity, minor concern.
    Low,
    /// Medium severity, should be investigated.
    Medium,
    /// High severity, requires prompt attention.
    High,
    /// Critical severity, immediate action required.
    Critical,
}

/// Source tool that generated an event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSource {
    Falco,
    Auditd,
    OpenSnitch,
    CrowdSec,
    Aide,
    Osquery,
    ClamAv,
    Yara,
    Chkrootkit,
    Rkhunter,
    Lynis,
    UsbGuard,
    CanaryToken,
    System,
}

/// An entity involved in a security event (process, file, network address, user, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
#[serde(rename_all = "snake_case")]
pub enum Entity {
    /// A process identified by PID and optional name.
    Process { pid: u32, name: Option<String> },
    /// A file path.
    File { path: String },
    /// A network address (IP and optional port).
    Network { address: String, port: Option<u16> },
    /// A system user.
    User { name: String, uid: Option<u32> },
    /// A USB device.
    UsbDevice { device_id: String, name: Option<String> },
}

/// A normalized security event from any integrated tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedEvent {
    /// Unique event identifier.
    pub id: Uuid,
    /// Timestamp when the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Source tool that generated this event.
    pub source: ToolSource,
    /// Event severity level.
    pub severity: Severity,
    /// Short summary of the event.
    pub summary: String,
    /// Detailed description or raw event data.
    pub details: Option<String>,
    /// Entities involved in this event.
    pub entities: Vec<Entity>,
    /// Whether this event has been acknowledged by the user.
    pub acknowledged: bool,
    /// Correlation ID linking related events.
    pub correlation_id: Option<Uuid>,
}

/// Status of an integrated security tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    /// Tool is not installed.
    NotInstalled,
    /// Tool is currently being installed.
    Installing,
    /// Tool is installed but not running.
    Stopped,
    /// Tool is starting up.
    Starting,
    /// Tool is running normally.
    Running,
    /// Tool encountered an error.
    Error,
    /// Tool is degraded (failed auto-restart attempts, requires manual intervention).
    Degraded,
    /// Tool is being updated.
    Updating,
}

/// Information about an integrated security tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool identifier (e.g., "falco", "clamav").
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Current status.
    pub status: ToolStatus,
    /// Version string if available.
    pub version: Option<String>,
    /// Last time the tool reported activity.
    pub last_active: Option<DateTime<Utc>>,
}

/// Result of a privileged operation executed by the daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OperationResult {
    /// Whether the operation succeeded.
    pub success: bool,
    /// Human-readable message describing the outcome.
    pub message: String,
    /// Optional additional data (JSON-encoded).
    pub data: Option<String>,
}
