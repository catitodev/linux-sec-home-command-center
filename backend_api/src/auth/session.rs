// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Session management for the Backend_API.
//!
//! Generates UUID v4 session tokens with configurable expiration.
//! Sessions are stored in-memory for fast validation.

use chrono::{DateTime, Duration, Utc};
use shared::config::SessionConfig;
use shared::errors::CommandCenterError;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// A session token string (UUID v4 format).
pub type SessionToken = String;

/// Information about an active session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// The authenticated username.
    pub username: String,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the session expires.
    pub expires_at: DateTime<Utc>,
}

impl SessionInfo {
    /// Check if this session has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Get the remaining time until expiration.
    pub fn remaining(&self) -> Duration {
        self.expires_at - Utc::now()
    }
}

/// Manages session creation, validation, and invalidation.
///
/// Thread-safe via `Arc<RwLock<...>>` for concurrent access from
/// multiple request handlers.
#[derive(Debug, Clone)]
pub struct SessionManager {
    /// Active sessions indexed by token.
    sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
    /// Session expiration time in minutes.
    expiry_minutes: u32,
}

impl SessionManager {
    /// Create a new SessionManager with the given configuration.
    ///
    /// The expiry_minutes value is clamped to the valid range [5, 1440].
    pub fn new(config: &SessionConfig) -> Self {
        let expiry_minutes = config.expiry_minutes.clamp(5, 1440);
        if expiry_minutes != config.expiry_minutes {
            warn!(
                configured = config.expiry_minutes,
                clamped = expiry_minutes,
                "Session expiry clamped to valid range [5, 1440] minutes"
            );
        }

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            expiry_minutes,
        }
    }

    /// Create a new session for the given username.
    ///
    /// Returns a UUID v4 session token.
    pub fn create_session(&self, username: &str) -> SessionToken {
        let token = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::minutes(i64::from(self.expiry_minutes));

        let session_info = SessionInfo {
            username: username.to_string(),
            created_at: now,
            expires_at,
        };

        let mut sessions = self.sessions.write().expect("session lock poisoned");
        sessions.insert(token.clone(), session_info);

        info!(
            user = %username,
            expiry_minutes = self.expiry_minutes,
            "Session created"
        );

        token
    }

    /// Validate a session token.
    ///
    /// Returns the session info if the token is valid and not expired.
    /// Returns `Err(CommandCenterError::SessionInvalid)` if the token
    /// is unknown or expired.
    pub fn validate_session(&self, token: &str) -> Result<SessionInfo, CommandCenterError> {
        let sessions = self.sessions.read().expect("session lock poisoned");

        match sessions.get(token) {
            Some(info) => {
                if info.is_expired() {
                    debug!(user = %info.username, "Session expired");
                    // Drop read lock before acquiring write lock
                    drop(sessions);
                    // Clean up expired session
                    self.invalidate_session(token);
                    Err(CommandCenterError::SessionInvalid)
                } else {
                    Ok(info.clone())
                }
            }
            None => {
                debug!("Session token not found");
                Err(CommandCenterError::SessionInvalid)
            }
        }
    }

    /// Invalidate (logout) a session by token.
    pub fn invalidate_session(&self, token: &str) {
        let mut sessions = self.sessions.write().expect("session lock poisoned");
        if let Some(info) = sessions.remove(token) {
            info!(user = %info.username, "Session invalidated");
        }
    }

    /// Get the number of active (non-expired) sessions.
    pub fn active_session_count(&self) -> usize {
        let sessions = self.sessions.read().expect("session lock poisoned");
        sessions.values().filter(|s| !s.is_expired()).count()
    }

    /// Remove all expired sessions (housekeeping).
    pub fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().expect("session lock poisoned");
        let before = sessions.len();
        sessions.retain(|_, info| !info.is_expired());
        let removed = before - sessions.len();
        if removed > 0 {
            debug!(removed, "Cleaned up expired sessions");
        }
        removed
    }

    /// Get the configured expiry in minutes.
    pub fn expiry_minutes(&self) -> u32 {
        self.expiry_minutes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> SessionConfig {
        SessionConfig::default()
    }

    fn config_with_expiry(minutes: u32) -> SessionConfig {
        SessionConfig {
            expiry_minutes: minutes,
            ..Default::default()
        }
    }

    #[test]
    fn test_create_session_returns_uuid_format() {
        let mgr = SessionManager::new(&default_config());
        let token = mgr.create_session("testuser");

        // UUID v4 format: 8-4-4-4-12 hex chars
        assert!(Uuid::parse_str(&token).is_ok());
    }

    #[test]
    fn test_validate_session_returns_correct_username() {
        let mgr = SessionManager::new(&default_config());
        let token = mgr.create_session("alice");

        let info = mgr.validate_session(&token).unwrap();
        assert_eq!(info.username, "alice");
    }

    #[test]
    fn test_validate_unknown_token_fails() {
        let mgr = SessionManager::new(&default_config());
        let result = mgr.validate_session("nonexistent-token");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalidate_session_removes_it() {
        let mgr = SessionManager::new(&default_config());
        let token = mgr.create_session("bob");

        mgr.invalidate_session(&token);
        let result = mgr.validate_session(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_expiry_clamped_minimum() {
        let config = config_with_expiry(1); // Below minimum of 5
        let mgr = SessionManager::new(&config);
        assert_eq!(mgr.expiry_minutes(), 5);
    }

    #[test]
    fn test_session_expiry_clamped_maximum() {
        let config = config_with_expiry(2000); // Above maximum of 1440
        let mgr = SessionManager::new(&config);
        assert_eq!(mgr.expiry_minutes(), 1440);
    }

    #[test]
    fn test_session_expiry_within_range() {
        let config = config_with_expiry(60);
        let mgr = SessionManager::new(&config);
        assert_eq!(mgr.expiry_minutes(), 60);
    }

    #[test]
    fn test_active_session_count() {
        let mgr = SessionManager::new(&default_config());
        assert_eq!(mgr.active_session_count(), 0);

        mgr.create_session("user1");
        mgr.create_session("user2");
        assert_eq!(mgr.active_session_count(), 2);
    }

    #[test]
    fn test_multiple_sessions_for_same_user() {
        let mgr = SessionManager::new(&default_config());
        let token1 = mgr.create_session("alice");
        let token2 = mgr.create_session("alice");

        // Both tokens should be valid and different
        assert_ne!(token1, token2);
        assert!(mgr.validate_session(&token1).is_ok());
        assert!(mgr.validate_session(&token2).is_ok());
    }

    #[test]
    fn test_session_has_correct_expiry_time() {
        let config = config_with_expiry(30);
        let mgr = SessionManager::new(&config);
        let token = mgr.create_session("user");

        let info = mgr.validate_session(&token).unwrap();
        let expected_duration = Duration::minutes(30);
        let actual_duration = info.expires_at - info.created_at;

        // Allow 1 second tolerance for test execution time
        assert!((actual_duration - expected_duration).num_seconds().abs() <= 1);
    }
}
