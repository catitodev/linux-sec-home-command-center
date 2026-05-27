// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Error definitions for the Linux Security Home Command Center.

use thiserror::Error;

/// Top-level error type for the Command Center.
#[derive(Debug, Error)]
pub enum CommandCenterError {
    /// Authentication failed (uniform error — does not reveal which field was wrong).
    #[error("authentication failed: invalid credentials")]
    AuthenticationFailed,

    /// Session has expired or is invalid.
    #[error("session expired or invalid")]
    SessionInvalid,

    /// Account is locked due to too many failed attempts.
    #[error("account locked: too many failed attempts")]
    AccountLocked,

    /// The requested operation is not in the privilege whitelist.
    #[error("operation not permitted: '{operation}' is not whitelisted")]
    OperationNotWhitelisted { operation: String },

    /// Polkit authorization was denied.
    #[error("authorization denied by Polkit")]
    AuthorizationDenied,

    /// D-Bus communication error.
    #[error("D-Bus error: {0}")]
    DBus(String),

    /// Database error.
    #[error("database error: {0}")]
    Database(String),

    /// Tool is not available or not installed.
    #[error("tool not available: {tool}")]
    ToolNotAvailable { tool: String },

    /// Tool operation failed.
    #[error("tool operation failed: {tool} — {reason}")]
    ToolOperationFailed { tool: String, reason: String },

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Integrity verification failed.
    #[error("integrity verification failed: {0}")]
    IntegrityFailed(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Convenience type alias for Results using CommandCenterError.
pub type Result<T> = std::result::Result<T, CommandCenterError>;
