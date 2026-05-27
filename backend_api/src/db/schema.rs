// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! SQL schema definitions for the Command Center database.
//!
//! All CREATE TABLE statements are defined here as constants for use
//! by the migration system.

/// Schema version tracking table.
pub const CREATE_SCHEMA_VERSION: &str = "
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
";

/// Security events table — normalized events from all integrated tools.
pub const CREATE_SECURITY_EVENTS: &str = "
CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    details TEXT,
    entities TEXT NOT NULL DEFAULT '[]',
    acknowledged INTEGER NOT NULL DEFAULT 0,
    correlation_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
";

/// Index on security_events for timestamp-based queries.
pub const CREATE_EVENTS_TIMESTAMP_INDEX: &str = "
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events (timestamp DESC);
";

/// Index on security_events for source tool filtering.
pub const CREATE_EVENTS_SOURCE_INDEX: &str = "
CREATE INDEX IF NOT EXISTS idx_events_source ON security_events (source_tool);
";

/// Index on security_events for severity filtering.
pub const CREATE_EVENTS_SEVERITY_INDEX: &str = "
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events (severity);
";

/// Index on security_events for correlation lookups.
pub const CREATE_EVENTS_CORRELATION_INDEX: &str = "
CREATE INDEX IF NOT EXISTS idx_events_correlation ON security_events (correlation_id);
";

/// Tools table — status and configuration of integrated security tools.
pub const CREATE_TOOLS: &str = "
CREATE TABLE IF NOT EXISTS tools (
    name TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'not_installed',
    version TEXT,
    last_active TEXT,
    config TEXT NOT NULL DEFAULT '{}'
);
";

/// Scan results table — records of completed security scans.
pub const CREATE_SCAN_RESULTS: &str = "
CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    scope TEXT NOT NULL DEFAULT '{}',
    findings_count INTEGER NOT NULL DEFAULT 0,
    findings TEXT NOT NULL DEFAULT '[]'
);
";

/// Quarantined files table — files isolated in the Quarantine Vault.
pub const CREATE_QUARANTINED_FILES: &str = "
CREATE TABLE IF NOT EXISTS quarantined_files (
    id TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    permissions INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    mtime TEXT NOT NULL,
    detection_reason TEXT NOT NULL,
    detection_engine TEXT NOT NULL,
    quarantined_at TEXT NOT NULL DEFAULT (datetime('now')),
    file_size INTEGER NOT NULL DEFAULT 0
);
";

/// Response rules table — automated response rule definitions.
pub const CREATE_RESPONSE_RULES: &str = "
CREATE TABLE IF NOT EXISTS response_rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    condition_expression TEXT NOT NULL,
    actions TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_triggered TEXT,
    trigger_count INTEGER NOT NULL DEFAULT 0
);
";

/// Response actions table — log of executed automated response actions.
pub const CREATE_RESPONSE_ACTIONS: &str = "
CREATE TABLE IF NOT EXISTS response_actions (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    incident_id TEXT,
    executed_at TEXT NOT NULL DEFAULT (datetime('now')),
    action_type TEXT NOT NULL,
    parameters TEXT NOT NULL DEFAULT '{}',
    result TEXT NOT NULL DEFAULT 'pending',
    failure_reason TEXT,
    reversal_procedure TEXT,
    reversal_expires_at TEXT,
    FOREIGN KEY (rule_id) REFERENCES response_rules(id)
);
";

/// Index on response_actions for rule lookups.
pub const CREATE_ACTIONS_RULE_INDEX: &str = "
CREATE INDEX IF NOT EXISTS idx_actions_rule ON response_actions (rule_id);
";

/// Index on response_actions for incident lookups.
pub const CREATE_ACTIONS_INCIDENT_INDEX: &str = "
CREATE INDEX IF NOT EXISTS idx_actions_incident ON response_actions (incident_id);
";
