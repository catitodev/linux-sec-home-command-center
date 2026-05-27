// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Rate limiting and account lockout for the Backend_API.
//!
//! Implements account lockout after N failed authentication attempts
//! within a configurable time window. Uses a sliding window of timestamps
//! per user to track failures.

use chrono::{DateTime, Duration, Utc};
use shared::config::SessionConfig;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

/// Tracks failed login attempts and enforces account lockout.
///
/// Thread-safe via `Arc<RwLock<...>>` for concurrent access.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Per-user tracking of failed attempts and lockout state.
    state: Arc<RwLock<HashMap<String, UserLockState>>>,
    /// Maximum failed attempts before lockout.
    max_failed_attempts: u32,
    /// Duration of lockout in minutes.
    lockout_duration_minutes: u32,
    /// Window in minutes for counting failed attempts.
    failed_attempt_window_minutes: u32,
}

/// Per-user lockout state.
#[derive(Debug, Clone)]
struct UserLockState {
    /// Timestamps of failed attempts within the sliding window.
    failed_attempts: Vec<DateTime<Utc>>,
    /// If locked, when the lockout expires.
    locked_until: Option<DateTime<Utc>>,
}

impl UserLockState {
    fn new() -> Self {
        Self {
            failed_attempts: Vec::new(),
            locked_until: None,
        }
    }
}

impl RateLimiter {
    /// Create a new RateLimiter with the given configuration.
    pub fn new(config: &SessionConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(HashMap::new())),
            max_failed_attempts: config.max_failed_attempts,
            lockout_duration_minutes: config.lockout_duration_minutes,
            failed_attempt_window_minutes: config.failed_attempt_window_minutes,
        }
    }

    /// Create a RateLimiter with default settings (5 attempts, 5-min window, 15-min lock).
    pub fn with_defaults() -> Self {
        Self::new(&SessionConfig::default())
    }

    /// Record a failed authentication attempt for the given username.
    ///
    /// If this causes the failure count to reach the threshold within
    /// the sliding window, the account will be locked.
    pub fn record_failure(&self, username: &str) {
        let now = Utc::now();
        let window_start = now - Duration::minutes(i64::from(self.failed_attempt_window_minutes));

        let mut state = self.state.write().expect("rate limiter lock poisoned");
        let user_state = state
            .entry(username.to_string())
            .or_insert_with(UserLockState::new);

        // Remove attempts outside the sliding window
        user_state
            .failed_attempts
            .retain(|t| *t >= window_start);

        // Record this failure
        user_state.failed_attempts.push(now);

        // Check if threshold reached
        if user_state.failed_attempts.len() >= self.max_failed_attempts as usize {
            let locked_until =
                now + Duration::minutes(i64::from(self.lockout_duration_minutes));
            user_state.locked_until = Some(locked_until);

            warn!(
                user = %username,
                attempts = user_state.failed_attempts.len(),
                locked_until = %locked_until,
                "Account locked due to too many failed attempts"
            );
        }
    }

    /// Check if an account is currently locked.
    ///
    /// Returns `Some(remaining_duration)` if locked, or `None` if not locked.
    pub fn is_locked(&self, username: &str) -> Option<std::time::Duration> {
        let now = Utc::now();

        let state = self.state.read().expect("rate limiter lock poisoned");
        if let Some(user_state) = state.get(username) {
            if let Some(locked_until) = user_state.locked_until {
                if now < locked_until {
                    let remaining = locked_until - now;
                    return Some(remaining.to_std().unwrap_or(std::time::Duration::ZERO));
                }
            }
        }
        None
    }

    /// Reset the failure count for a user (called on successful login).
    pub fn reset(&self, username: &str) {
        let mut state = self.state.write().expect("rate limiter lock poisoned");
        if state.remove(username).is_some() {
            info!(user = %username, "Rate limiter state reset after successful login");
        }
    }

    /// Get the number of recent failed attempts for a user within the window.
    pub fn failed_attempt_count(&self, username: &str) -> usize {
        let now = Utc::now();
        let window_start = now - Duration::minutes(i64::from(self.failed_attempt_window_minutes));

        let state = self.state.read().expect("rate limiter lock poisoned");
        if let Some(user_state) = state.get(username) {
            user_state
                .failed_attempts
                .iter()
                .filter(|t| **t >= window_start)
                .count()
        } else {
            0
        }
    }

    /// Get the configured maximum failed attempts.
    pub fn max_failed_attempts(&self) -> u32 {
        self.max_failed_attempts
    }

    /// Get the configured lockout duration in minutes.
    pub fn lockout_duration_minutes(&self) -> u32 {
        self.lockout_duration_minutes
    }

    /// Get the configured failed attempt window in minutes.
    pub fn failed_attempt_window_minutes(&self) -> u32 {
        self.failed_attempt_window_minutes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> SessionConfig {
        SessionConfig {
            expiry_minutes: 30,
            max_failed_attempts: 5,
            lockout_duration_minutes: 15,
            failed_attempt_window_minutes: 5,
        }
    }

    #[test]
    fn test_no_lockout_initially() {
        let limiter = RateLimiter::new(&default_config());
        assert!(limiter.is_locked("testuser").is_none());
    }

    #[test]
    fn test_no_lockout_below_threshold() {
        let limiter = RateLimiter::new(&default_config());

        // 4 failures should not trigger lockout (threshold is 5)
        for _ in 0..4 {
            limiter.record_failure("testuser");
        }

        assert!(limiter.is_locked("testuser").is_none());
    }

    #[test]
    fn test_lockout_at_threshold() {
        let limiter = RateLimiter::new(&default_config());

        // 5 failures should trigger lockout
        for _ in 0..5 {
            limiter.record_failure("testuser");
        }

        let locked = limiter.is_locked("testuser");
        assert!(locked.is_some());

        // Remaining time should be approximately 15 minutes
        let remaining = locked.unwrap();
        assert!(remaining.as_secs() > 14 * 60); // At least 14 minutes
        assert!(remaining.as_secs() <= 15 * 60); // At most 15 minutes
    }

    #[test]
    fn test_lockout_above_threshold() {
        let limiter = RateLimiter::new(&default_config());

        // More than 5 failures should still be locked
        for _ in 0..10 {
            limiter.record_failure("testuser");
        }

        assert!(limiter.is_locked("testuser").is_some());
    }

    #[test]
    fn test_reset_clears_lockout() {
        let limiter = RateLimiter::new(&default_config());

        // Trigger lockout
        for _ in 0..5 {
            limiter.record_failure("testuser");
        }
        assert!(limiter.is_locked("testuser").is_some());

        // Reset should clear it
        limiter.reset("testuser");
        assert!(limiter.is_locked("testuser").is_none());
    }

    #[test]
    fn test_different_users_independent() {
        let limiter = RateLimiter::new(&default_config());

        // Lock user1
        for _ in 0..5 {
            limiter.record_failure("user1");
        }

        // user2 should not be affected
        assert!(limiter.is_locked("user1").is_some());
        assert!(limiter.is_locked("user2").is_none());
    }

    #[test]
    fn test_failed_attempt_count() {
        let limiter = RateLimiter::new(&default_config());

        assert_eq!(limiter.failed_attempt_count("testuser"), 0);

        limiter.record_failure("testuser");
        assert_eq!(limiter.failed_attempt_count("testuser"), 1);

        limiter.record_failure("testuser");
        assert_eq!(limiter.failed_attempt_count("testuser"), 2);
    }

    #[test]
    fn test_reset_clears_attempt_count() {
        let limiter = RateLimiter::new(&default_config());

        limiter.record_failure("testuser");
        limiter.record_failure("testuser");
        assert_eq!(limiter.failed_attempt_count("testuser"), 2);

        limiter.reset("testuser");
        assert_eq!(limiter.failed_attempt_count("testuser"), 0);
    }

    #[test]
    fn test_custom_config() {
        let config = SessionConfig {
            expiry_minutes: 30,
            max_failed_attempts: 3,
            lockout_duration_minutes: 10,
            failed_attempt_window_minutes: 2,
        };
        let limiter = RateLimiter::new(&config);

        // 3 failures should trigger lockout with custom config
        for _ in 0..3 {
            limiter.record_failure("testuser");
        }

        let locked = limiter.is_locked("testuser");
        assert!(locked.is_some());

        // Remaining time should be approximately 10 minutes
        let remaining = locked.unwrap();
        assert!(remaining.as_secs() > 9 * 60);
        assert!(remaining.as_secs() <= 10 * 60);
    }
}
