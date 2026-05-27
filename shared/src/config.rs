// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Configuration structures for the Linux Security Home Command Center.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for the Backend_API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Path to the Unix domain socket for the HTTP server.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// Database configuration.
    pub database: DatabaseConfig,

    /// Session configuration.
    #[serde(default)]
    pub session: SessionConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Path to the SQLCipher database file.
    pub path: PathBuf,

    /// Path to the file containing the database encryption key.
    /// The key file should have restrictive permissions (0600).
    pub key_file: PathBuf,
}

/// Session management configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session expiration time in minutes (5–1440, default 30).
    #[serde(default = "default_session_expiry_minutes")]
    pub expiry_minutes: u32,

    /// Maximum failed login attempts before lockout.
    #[serde(default = "default_max_failed_attempts")]
    pub max_failed_attempts: u32,

    /// Lockout duration in minutes after exceeding failed attempts.
    #[serde(default = "default_lockout_duration_minutes")]
    pub lockout_duration_minutes: u32,

    /// Window in minutes for counting failed attempts.
    #[serde(default = "default_failed_attempt_window_minutes")]
    pub failed_attempt_window_minutes: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            expiry_minutes: default_session_expiry_minutes(),
            max_failed_attempts: default_max_failed_attempts(),
            lockout_duration_minutes: default_lockout_duration_minutes(),
            failed_attempt_window_minutes: default_failed_attempt_window_minutes(),
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level filter (e.g., "info", "debug", "trace").
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Whether to log to journald.
    #[serde(default = "default_true")]
    pub journald: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            journald: true,
        }
    }
}

/// Configuration for the Privileged Daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Path to the operation whitelist file.
    #[serde(default = "default_whitelist_path")]
    pub whitelist_path: PathBuf,

    /// Path to the AIDE database for integrity verification.
    #[serde(default = "default_aide_db_path")]
    pub aide_db_path: PathBuf,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Operation whitelist configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistConfig {
    /// List of allowed operations.
    pub operations: Vec<WhitelistedOperation>,
}

/// A single whitelisted operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhitelistedOperation {
    /// Operation name (must match D-Bus method name).
    pub name: String,

    /// Optional description of what this operation does.
    pub description: Option<String>,

    /// Whether this operation requires additional Polkit confirmation.
    #[serde(default)]
    pub requires_confirmation: bool,
}

// ─── Default value functions ───────────────────────────────────────────────

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/security-command-center/api.sock")
}

fn default_session_expiry_minutes() -> u32 {
    30
}

fn default_max_failed_attempts() -> u32 {
    5
}

fn default_lockout_duration_minutes() -> u32 {
    15
}

fn default_failed_attempt_window_minutes() -> u32 {
    5
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

fn default_whitelist_path() -> PathBuf {
    PathBuf::from("/etc/security-command-center/whitelist.toml")
}

fn default_aide_db_path() -> PathBuf {
    PathBuf::from("/var/lib/aide/aide.db")
}
