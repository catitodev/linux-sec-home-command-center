// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Tool lifecycle state machine.
//!
//! Enforces valid state transitions for security tools and manages
//! automatic restart logic when tools enter the Error state.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use shared::errors::{CommandCenterError, Result};
use shared::types::ToolStatus;
use tracing::{info, warn};

/// Maximum number of automatic restart attempts before transitioning to Degraded.
const MAX_RESTART_ATTEMPTS: u32 = 3;

/// Delay between automatic restart attempts.
const RESTART_INTERVAL: Duration = Duration::from_secs(10);

/// Tracks restart attempt state for a single tool.
#[derive(Debug, Clone)]
pub struct RestartState {
    /// Number of restart attempts made since entering Error state.
    pub attempts: u32,
    /// Timestamp of the last restart attempt.
    pub last_attempt: Option<Instant>,
}

impl RestartState {
    /// Creates a new restart state with zero attempts.
    pub fn new() -> Self {
        Self {
            attempts: 0,
            last_attempt: None,
        }
    }

    /// Resets the restart state (e.g., when tool successfully starts).
    pub fn reset(&mut self) {
        self.attempts = 0;
        self.last_attempt = None;
    }

    /// Records a restart attempt.
    pub fn record_attempt(&mut self) {
        self.attempts += 1;
        self.last_attempt = Some(Instant::now());
    }

    /// Returns whether the maximum restart attempts have been exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.attempts >= MAX_RESTART_ATTEMPTS
    }

    /// Returns whether enough time has passed since the last attempt
    /// to try another restart.
    pub fn can_retry(&self) -> bool {
        match self.last_attempt {
            Some(last) => last.elapsed() >= RESTART_INTERVAL,
            None => true,
        }
    }
}

impl Default for RestartState {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages lifecycle state transitions and restart logic for all tools.
#[derive(Debug)]
pub struct LifecycleManager {
    /// Current status of each tool by name.
    states: HashMap<String, ToolStatus>,
    /// Restart tracking state for each tool.
    restart_states: HashMap<String, RestartState>,
}

impl LifecycleManager {
    /// Creates a new lifecycle manager with no registered tools.
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            restart_states: HashMap::new(),
        }
    }

    /// Registers a tool with an initial status of `NotInstalled`.
    pub fn register(&mut self, name: &str) {
        self.states
            .entry(name.to_string())
            .or_insert(ToolStatus::NotInstalled);
        self.restart_states
            .entry(name.to_string())
            .or_insert_with(RestartState::new);
    }

    /// Forces a tool back to `NotInstalled` state.
    ///
    /// Used when installation fails and the state needs to be reverted.
    /// This bypasses normal transition validation.
    pub fn force_not_installed(&mut self, name: &str) {
        self.states.insert(name.to_string(), ToolStatus::NotInstalled);
        if let Some(rs) = self.restart_states.get_mut(name) {
            rs.reset();
        }
    }

    /// Returns the current status of a tool, or `None` if not registered.
    pub fn get_status(&self, name: &str) -> Option<ToolStatus> {
        self.states.get(name).copied()
    }

    /// Returns all tool states as a reference to the internal map.
    pub fn all_states(&self) -> &HashMap<String, ToolStatus> {
        &self.states
    }

    /// Attempts to transition a tool to the `Installing` state.
    ///
    /// Valid from: `NotInstalled`
    pub fn transition_to_installing(&mut self, name: &str) -> Result<()> {
        self.validate_transition(name, &[ToolStatus::NotInstalled], ToolStatus::Installing)
    }

    /// Attempts to transition a tool to the `Stopped` state (installation complete).
    ///
    /// Valid from: `Installing`, `Running`, `Starting`
    pub fn transition_to_stopped(&mut self, name: &str) -> Result<()> {
        self.validate_transition(
            name,
            &[ToolStatus::Installing, ToolStatus::Running, ToolStatus::Starting],
            ToolStatus::Stopped,
        )
    }

    /// Attempts to transition a tool to the `Starting` state.
    ///
    /// Valid from: `Stopped`, `Error`
    pub fn transition_to_starting(&mut self, name: &str) -> Result<()> {
        self.validate_transition(
            name,
            &[ToolStatus::Stopped, ToolStatus::Error],
            ToolStatus::Starting,
        )
    }

    /// Attempts to transition a tool to the `Running` state.
    ///
    /// Valid from: `Starting`
    pub fn transition_to_running(&mut self, name: &str) -> Result<()> {
        let result = self.validate_transition(name, &[ToolStatus::Starting], ToolStatus::Running);
        if result.is_ok() {
            // Successful start resets restart counter
            if let Some(rs) = self.restart_states.get_mut(name) {
                rs.reset();
            }
        }
        result
    }

    /// Attempts to transition a tool to the `Error` state.
    ///
    /// Valid from: `Running`, `Starting`
    pub fn transition_to_error(&mut self, name: &str) -> Result<()> {
        self.validate_transition(
            name,
            &[ToolStatus::Running, ToolStatus::Starting],
            ToolStatus::Error,
        )
    }

    /// Attempts to transition a tool to the `Degraded` state.
    ///
    /// Valid from: `Error`, `Running`
    /// This is a terminal state requiring manual intervention.
    pub fn transition_to_degraded(&mut self, name: &str) -> Result<()> {
        self.validate_transition(
            name,
            &[ToolStatus::Error, ToolStatus::Running],
            ToolStatus::Degraded,
        )
    }

    /// Determines whether an automatic restart should be attempted for a tool.
    ///
    /// Returns `true` if:
    /// - The tool is in `Error` state
    /// - Restart attempts have not been exhausted (< 3)
    /// - Enough time has passed since the last attempt (10s)
    pub fn should_auto_restart(&self, name: &str) -> bool {
        let status = match self.states.get(name) {
            Some(s) => *s,
            None => return false,
        };

        if status != ToolStatus::Error {
            return false;
        }

        match self.restart_states.get(name) {
            Some(rs) => !rs.is_exhausted() && rs.can_retry(),
            None => false,
        }
    }

    /// Records a restart attempt for a tool.
    ///
    /// If the maximum attempts are reached, transitions the tool to `Degraded`.
    pub fn record_restart_attempt(&mut self, name: &str) -> Result<()> {
        if let Some(rs) = self.restart_states.get_mut(name) {
            rs.record_attempt();
            info!(
                tool = name,
                attempt = rs.attempts,
                max = MAX_RESTART_ATTEMPTS,
                "Recorded restart attempt"
            );

            if rs.is_exhausted() {
                warn!(
                    tool = name,
                    "Maximum restart attempts exhausted, transitioning to Degraded"
                );
                // Force transition to Degraded
                self.states.insert(name.to_string(), ToolStatus::Degraded);
            }
        }
        Ok(())
    }

    /// Returns the restart state for a tool.
    pub fn get_restart_state(&self, name: &str) -> Option<&RestartState> {
        self.restart_states.get(name)
    }

    /// Resets a tool from `Degraded` back to `Stopped` for manual intervention.
    ///
    /// This allows the user to manually retry starting the tool.
    pub fn reset_from_degraded(&mut self, name: &str) -> Result<()> {
        let current = self.states.get(name).copied();
        match current {
            Some(ToolStatus::Degraded) => {
                self.states.insert(name.to_string(), ToolStatus::Stopped);
                if let Some(rs) = self.restart_states.get_mut(name) {
                    rs.reset();
                }
                info!(tool = name, "Reset from Degraded to Stopped for manual retry");
                Ok(())
            }
            Some(status) => Err(CommandCenterError::ToolOperationFailed {
                tool: name.to_string(),
                reason: format!(
                    "Cannot reset from {:?}, tool must be in Degraded state",
                    status
                ),
            }),
            None => Err(CommandCenterError::ToolNotAvailable {
                tool: name.to_string(),
            }),
        }
    }

    /// Validates and applies a state transition.
    fn validate_transition(
        &mut self,
        name: &str,
        valid_from: &[ToolStatus],
        target: ToolStatus,
    ) -> Result<()> {
        let current = match self.states.get(name) {
            Some(s) => *s,
            None => {
                return Err(CommandCenterError::ToolNotAvailable {
                    tool: name.to_string(),
                });
            }
        };

        if valid_from.contains(&current) {
            self.states.insert(name.to_string(), target);
            info!(
                tool = name,
                from = ?current,
                to = ?target,
                "Tool state transition"
            );
            Ok(())
        } else {
            Err(CommandCenterError::ToolOperationFailed {
                tool: name.to_string(),
                reason: format!(
                    "Invalid state transition: cannot move from {:?} to {:?} (valid from: {:?})",
                    current, target, valid_from
                ),
            })
        }
    }
}

impl Default for LifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_tool_starts_as_not_installed() {
        let mut lm = LifecycleManager::new();
        lm.register("falco");
        assert_eq!(lm.get_status("falco"), Some(ToolStatus::NotInstalled));
    }

    #[test]
    fn test_valid_install_transition() {
        let mut lm = LifecycleManager::new();
        lm.register("falco");
        assert!(lm.transition_to_installing("falco").is_ok());
        assert_eq!(lm.get_status("falco"), Some(ToolStatus::Installing));
    }

    #[test]
    fn test_invalid_install_transition_from_running() {
        let mut lm = LifecycleManager::new();
        lm.register("falco");
        lm.transition_to_installing("falco").unwrap();
        lm.transition_to_stopped("falco").unwrap();
        lm.transition_to_starting("falco").unwrap();
        lm.transition_to_running("falco").unwrap();

        // Cannot install a running tool
        assert!(lm.transition_to_installing("falco").is_err());
    }

    #[test]
    fn test_full_lifecycle_happy_path() {
        let mut lm = LifecycleManager::new();
        lm.register("clamav");

        // NotInstalled → Installing → Stopped → Starting → Running
        assert!(lm.transition_to_installing("clamav").is_ok());
        assert!(lm.transition_to_stopped("clamav").is_ok());
        assert!(lm.transition_to_starting("clamav").is_ok());
        assert!(lm.transition_to_running("clamav").is_ok());
        assert_eq!(lm.get_status("clamav"), Some(ToolStatus::Running));
    }

    #[test]
    fn test_error_transition_from_running() {
        let mut lm = LifecycleManager::new();
        lm.register("falco");
        lm.transition_to_installing("falco").unwrap();
        lm.transition_to_stopped("falco").unwrap();
        lm.transition_to_starting("falco").unwrap();
        lm.transition_to_running("falco").unwrap();

        assert!(lm.transition_to_error("falco").is_ok());
        assert_eq!(lm.get_status("falco"), Some(ToolStatus::Error));
    }

    #[test]
    fn test_auto_restart_logic() {
        let mut lm = LifecycleManager::new();
        lm.register("falco");
        lm.transition_to_installing("falco").unwrap();
        lm.transition_to_stopped("falco").unwrap();
        lm.transition_to_starting("falco").unwrap();
        lm.transition_to_running("falco").unwrap();
        lm.transition_to_error("falco").unwrap();

        // Should allow restart (0 attempts, no time constraint)
        assert!(lm.should_auto_restart("falco"));

        // Record attempts until exhausted
        lm.record_restart_attempt("falco").unwrap();
        lm.record_restart_attempt("falco").unwrap();
        lm.record_restart_attempt("falco").unwrap();

        // After 3 attempts, tool should be Degraded
        assert_eq!(lm.get_status("falco"), Some(ToolStatus::Degraded));
        assert!(!lm.should_auto_restart("falco"));
    }

    #[test]
    fn test_reset_from_degraded() {
        let mut lm = LifecycleManager::new();
        lm.register("falco");
        lm.transition_to_installing("falco").unwrap();
        lm.transition_to_stopped("falco").unwrap();
        lm.transition_to_starting("falco").unwrap();
        lm.transition_to_running("falco").unwrap();
        lm.transition_to_error("falco").unwrap();

        // Exhaust restart attempts
        lm.record_restart_attempt("falco").unwrap();
        lm.record_restart_attempt("falco").unwrap();
        lm.record_restart_attempt("falco").unwrap();
        assert_eq!(lm.get_status("falco"), Some(ToolStatus::Degraded));

        // Manual reset
        assert!(lm.reset_from_degraded("falco").is_ok());
        assert_eq!(lm.get_status("falco"), Some(ToolStatus::Stopped));

        // Restart state should be reset
        let rs = lm.get_restart_state("falco").unwrap();
        assert_eq!(rs.attempts, 0);
    }

    #[test]
    fn test_cannot_reset_non_degraded_tool() {
        let mut lm = LifecycleManager::new();
        lm.register("falco");
        lm.transition_to_installing("falco").unwrap();
        lm.transition_to_stopped("falco").unwrap();

        assert!(lm.reset_from_degraded("falco").is_err());
    }

    #[test]
    fn test_unregistered_tool_returns_none() {
        let lm = LifecycleManager::new();
        assert_eq!(lm.get_status("nonexistent"), None);
    }

    #[test]
    fn test_transition_unregistered_tool_errors() {
        let mut lm = LifecycleManager::new();
        assert!(lm.transition_to_installing("nonexistent").is_err());
    }

    #[test]
    fn test_successful_start_resets_restart_counter() {
        let mut lm = LifecycleManager::new();
        lm.register("falco");
        lm.transition_to_installing("falco").unwrap();
        lm.transition_to_stopped("falco").unwrap();
        lm.transition_to_starting("falco").unwrap();
        lm.transition_to_running("falco").unwrap();
        lm.transition_to_error("falco").unwrap();

        // Record one attempt
        lm.record_restart_attempt("falco").unwrap();
        assert_eq!(lm.get_restart_state("falco").unwrap().attempts, 1);

        // Simulate successful restart
        lm.transition_to_starting("falco").unwrap();
        lm.transition_to_running("falco").unwrap();

        // Counter should be reset
        assert_eq!(lm.get_restart_state("falco").unwrap().attempts, 0);
    }
}
