// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Authentication, session management, and rate limiting for the Backend_API.
//!
//! This module provides:
//! - PAM-based local authentication (username/password)
//! - Session token generation and validation with configurable expiration
//! - Account lockout after repeated failed attempts (rate limiting)
//! - Auth middleware for protecting API endpoints
//!
//! All error responses are uniform to prevent information leakage about
//! which credential field was incorrect.

pub mod middleware;
pub mod pam_auth;
pub mod rate_limit;
pub mod session;

pub use middleware::AuthMiddleware;
pub use pam_auth::{Authenticator, PamAuthenticator};
pub use rate_limit::RateLimiter;
pub use session::{SessionInfo, SessionManager, SessionToken};

use serde::Serialize;

/// Uniform authentication error responses.
///
/// These responses intentionally do not reveal which field was incorrect
/// to prevent username enumeration attacks.
#[derive(Debug, Clone, Serialize)]
pub struct AuthErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

impl AuthErrorResponse {
    /// Invalid credentials error (same for wrong user OR wrong password).
    pub fn invalid_credentials() -> Self {
        Self {
            error: "authentication_failed".to_string(),
            message: "Invalid credentials".to_string(),
            retry_after_seconds: None,
        }
    }

    /// Session expired error.
    pub fn session_expired() -> Self {
        Self {
            error: "session_expired".to_string(),
            message: "Session expired, please re-authenticate".to_string(),
            retry_after_seconds: None,
        }
    }

    /// Account locked error with remaining lockout duration.
    pub fn account_locked(remaining_seconds: u64) -> Self {
        Self {
            error: "account_locked".to_string(),
            message: "Account temporarily locked".to_string(),
            retry_after_seconds: Some(remaining_seconds),
        }
    }
}
