// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Health monitoring loop for integrated security tools.
//!
//! Periodically checks the health of all running tools and triggers
//! state transitions and automatic restarts when tools become unhealthy.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio::time;
use tracing::{error, info, warn};

use shared::types::ToolStatus;

use super::adapter::{HealthStatus, ToolAdapter};
use super::lifecycle::LifecycleManager;

/// Default interval between health check cycles.
const DEFAULT_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Configuration for the health monitor.
#[derive(Debug, Clone)]
pub struct HealthMonitorConfig {
    /// Interval between health check cycles.
    pub check_interval: Duration,
}

impl Default for HealthMonitorConfig {
    fn default() -> Self {
        Self {
            check_interval: DEFAULT_HEALTH_CHECK_INTERVAL,
        }
    }
}

/// Health monitor that periodically checks tool health and manages restarts.
///
/// The monitor runs as a background task, iterating over all registered tools
/// that are in the `Running` state. When a tool reports unhealthy status, the
/// monitor transitions it to `Error` and triggers the auto-restart logic.
pub struct HealthMonitor {
    /// Shared lifecycle manager for state transitions.
    lifecycle: Arc<RwLock<LifecycleManager>>,
    /// Configuration for the monitor.
    config: HealthMonitorConfig,
}

impl HealthMonitor {
    /// Creates a new health monitor with the given lifecycle manager and config.
    pub fn new(lifecycle: Arc<RwLock<LifecycleManager>>, config: HealthMonitorConfig) -> Self {
        Self { lifecycle, config }
    }

    /// Creates a new health monitor with default configuration.
    pub fn with_defaults(lifecycle: Arc<RwLock<LifecycleManager>>) -> Self {
        Self {
            lifecycle,
            config: HealthMonitorConfig::default(),
        }
    }

    /// Runs the health check loop as a background task.
    ///
    /// This method runs indefinitely, checking tool health at the configured
    /// interval. It should be spawned as a tokio task.
    ///
    /// The `adapters` parameter provides access to the tool adapters for
    /// performing health checks and restart operations.
    pub async fn run(
        &self,
        adapters: Arc<HashMap<String, Box<dyn ToolAdapter>>>,
    ) {
        info!(
            interval_secs = self.config.check_interval.as_secs(),
            "Starting health monitor loop"
        );

        let mut interval = time::interval(self.config.check_interval);

        loop {
            interval.tick().await;
            self.check_all_tools(&adapters).await;
        }
    }

    /// Performs a single health check cycle across all tools.
    ///
    /// For each tool in `Running` state, calls its health check and handles
    /// the result. For tools in `Error` state, attempts auto-restart if eligible.
    pub async fn check_all_tools(
        &self,
        adapters: &HashMap<String, Box<dyn ToolAdapter>>,
    ) {
        let states = {
            let lm = self.lifecycle.read().await;
            lm.all_states().clone()
        };

        for (name, status) in &states {
            match status {
                ToolStatus::Running => {
                    if let Some(adapter) = adapters.get(name) {
                        self.check_tool_health(name, adapter.as_ref()).await;
                    }
                }
                ToolStatus::Error => {
                    self.attempt_auto_restart(name, adapters).await;
                }
                _ => {}
            }
        }
    }

    /// Checks the health of a single running tool and updates state accordingly.
    async fn check_tool_health(&self, name: &str, adapter: &dyn ToolAdapter) {
        let health = adapter.health_check().await;

        match health {
            HealthStatus::Healthy => {
                // Tool is fine, nothing to do
            }
            HealthStatus::Degraded(ref reason) => {
                warn!(tool = name, reason = %reason, "Tool health degraded");
                // Transition Running → Degraded
                let mut lm = self.lifecycle.write().await;
                if let Err(e) = lm.transition_to_degraded(name) {
                    error!(tool = name, error = %e, "Failed to transition to Degraded");
                }
            }
            HealthStatus::Unhealthy(ref reason) => {
                error!(tool = name, reason = %reason, "Tool health check failed");
                // Transition Running → Error (triggers auto-restart on next cycle)
                let mut lm = self.lifecycle.write().await;
                if let Err(e) = lm.transition_to_error(name) {
                    error!(tool = name, error = %e, "Failed to transition to Error");
                }
            }
            HealthStatus::NotRunning => {
                warn!(tool = name, "Tool reported as not running during health check");
                let mut lm = self.lifecycle.write().await;
                if let Err(e) = lm.transition_to_error(name) {
                    error!(tool = name, error = %e, "Failed to transition to Error");
                }
            }
        }
    }

    /// Attempts to automatically restart a tool in Error state.
    ///
    /// Checks whether the tool is eligible for auto-restart (< 3 attempts,
    /// 10s since last attempt). If eligible, attempts to start the tool.
    /// If all attempts are exhausted, the lifecycle manager transitions
    /// the tool to Degraded.
    async fn attempt_auto_restart(
        &self,
        name: &str,
        adapters: &HashMap<String, Box<dyn ToolAdapter>>,
    ) {
        let should_restart = {
            let lm = self.lifecycle.read().await;
            lm.should_auto_restart(name)
        };

        if !should_restart {
            return;
        }

        info!(tool = name, "Attempting automatic restart");

        // Record the attempt (may transition to Degraded if exhausted)
        {
            let mut lm = self.lifecycle.write().await;
            if let Err(e) = lm.record_restart_attempt(name) {
                error!(tool = name, error = %e, "Failed to record restart attempt");
                return;
            }

            // Check if we just transitioned to Degraded
            if lm.get_status(name) == Some(ToolStatus::Degraded) {
                warn!(
                    tool = name,
                    "Auto-restart attempts exhausted, tool is now Degraded"
                );
                return;
            }

            // Transition to Starting
            if let Err(e) = lm.transition_to_starting(name) {
                error!(tool = name, error = %e, "Failed to transition to Starting for restart");
                return;
            }
        }

        // Attempt the actual start
        if let Some(adapter) = adapters.get(name) {
            match adapter.start().await {
                Ok(()) => {
                    let mut lm = self.lifecycle.write().await;
                    if let Err(e) = lm.transition_to_running(name) {
                        error!(tool = name, error = %e, "Failed to transition to Running after restart");
                    } else {
                        info!(tool = name, "Automatic restart successful");
                    }
                }
                Err(e) => {
                    error!(tool = name, error = %e, "Automatic restart failed");
                    let mut lm = self.lifecycle.write().await;
                    if let Err(te) = lm.transition_to_error(name) {
                        error!(tool = name, error = %te, "Failed to transition back to Error");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::adapter::ToolCategory;
    use async_trait::async_trait;
    use shared::distro::DistroInfo;
    use shared::errors::Result;

    struct HealthyMockAdapter;

    #[async_trait]
    impl ToolAdapter for HealthyMockAdapter {
        fn name(&self) -> &str { "healthy-tool" }
        fn display_name(&self) -> &str { "Healthy Tool" }
        fn category(&self) -> ToolCategory { ToolCategory::Visibility }
        async fn install(&self, _distro: &DistroInfo) -> Result<()> { Ok(()) }
        async fn start(&self) -> Result<()> { Ok(()) }
        async fn stop(&self) -> Result<()> { Ok(()) }
        async fn health_check(&self) -> HealthStatus { HealthStatus::Healthy }
        fn is_available_for(&self, _distro: &DistroInfo) -> bool { true }
    }

    struct UnhealthyMockAdapter;

    #[async_trait]
    impl ToolAdapter for UnhealthyMockAdapter {
        fn name(&self) -> &str { "unhealthy-tool" }
        fn display_name(&self) -> &str { "Unhealthy Tool" }
        fn category(&self) -> ToolCategory { ToolCategory::Visibility }
        async fn install(&self, _distro: &DistroInfo) -> Result<()> { Ok(()) }
        async fn start(&self) -> Result<()> { Ok(()) }
        async fn stop(&self) -> Result<()> { Ok(()) }
        async fn health_check(&self) -> HealthStatus {
            HealthStatus::Unhealthy("process crashed".to_string())
        }
        fn is_available_for(&self, _distro: &DistroInfo) -> bool { true }
    }

    #[tokio::test]
    async fn test_healthy_tool_stays_running() {
        let mut lm = LifecycleManager::new();
        lm.register("healthy-tool");
        lm.transition_to_installing("healthy-tool").unwrap();
        lm.transition_to_stopped("healthy-tool").unwrap();
        lm.transition_to_starting("healthy-tool").unwrap();
        lm.transition_to_running("healthy-tool").unwrap();

        let lifecycle = Arc::new(RwLock::new(lm));
        let monitor = HealthMonitor::with_defaults(Arc::clone(&lifecycle));

        let mut adapters: HashMap<String, Box<dyn ToolAdapter>> = HashMap::new();
        adapters.insert("healthy-tool".to_string(), Box::new(HealthyMockAdapter));

        monitor.check_all_tools(&adapters).await;

        let lm = lifecycle.read().await;
        assert_eq!(lm.get_status("healthy-tool"), Some(ToolStatus::Running));
    }

    #[tokio::test]
    async fn test_unhealthy_tool_transitions_to_error() {
        let mut lm = LifecycleManager::new();
        lm.register("unhealthy-tool");
        lm.transition_to_installing("unhealthy-tool").unwrap();
        lm.transition_to_stopped("unhealthy-tool").unwrap();
        lm.transition_to_starting("unhealthy-tool").unwrap();
        lm.transition_to_running("unhealthy-tool").unwrap();

        let lifecycle = Arc::new(RwLock::new(lm));
        let monitor = HealthMonitor::with_defaults(Arc::clone(&lifecycle));

        let mut adapters: HashMap<String, Box<dyn ToolAdapter>> = HashMap::new();
        adapters.insert("unhealthy-tool".to_string(), Box::new(UnhealthyMockAdapter));

        monitor.check_all_tools(&adapters).await;

        let lm = lifecycle.read().await;
        assert_eq!(lm.get_status("unhealthy-tool"), Some(ToolStatus::Error));
    }

    #[tokio::test]
    async fn test_auto_restart_exhaustion_leads_to_degraded() {
        let mut lm = LifecycleManager::new();
        lm.register("restart-counter");
        lm.transition_to_installing("restart-counter").unwrap();
        lm.transition_to_stopped("restart-counter").unwrap();
        lm.transition_to_starting("restart-counter").unwrap();
        lm.transition_to_running("restart-counter").unwrap();
        lm.transition_to_error("restart-counter").unwrap();

        // Pre-exhaust 2 attempts via lifecycle manager to simulate time passing
        lm.record_restart_attempt("restart-counter").unwrap();
        lm.record_restart_attempt("restart-counter").unwrap();

        // Tool is still in Error with 2 attempts recorded.
        assert_eq!(lm.get_status("restart-counter"), Some(ToolStatus::Error));

        let lifecycle = Arc::new(RwLock::new(lm));

        // The 3rd attempt triggers transition to Degraded.
        // In production, 10s would pass between attempts.
        // For testing, we verify the lifecycle manager behavior directly.
        {
            let mut lm = lifecycle.write().await;
            lm.record_restart_attempt("restart-counter").unwrap();
        }

        let lm = lifecycle.read().await;
        assert_eq!(lm.get_status("restart-counter"), Some(ToolStatus::Degraded));
    }

    #[tokio::test]
    async fn test_auto_restart_triggered_on_first_error() {
        // A tool that succeeds on restart
        struct RecoverableAdapter;

        #[async_trait]
        impl ToolAdapter for RecoverableAdapter {
            fn name(&self) -> &str { "recoverable" }
            fn display_name(&self) -> &str { "Recoverable" }
            fn category(&self) -> ToolCategory { ToolCategory::Visibility }
            async fn install(&self, _distro: &DistroInfo) -> Result<()> { Ok(()) }
            async fn start(&self) -> Result<()> { Ok(()) }
            async fn stop(&self) -> Result<()> { Ok(()) }
            async fn health_check(&self) -> HealthStatus { HealthStatus::Healthy }
            fn is_available_for(&self, _distro: &DistroInfo) -> bool { true }
        }

        let mut lm = LifecycleManager::new();
        lm.register("recoverable");
        lm.transition_to_installing("recoverable").unwrap();
        lm.transition_to_stopped("recoverable").unwrap();
        lm.transition_to_starting("recoverable").unwrap();
        lm.transition_to_running("recoverable").unwrap();
        lm.transition_to_error("recoverable").unwrap();

        // No prior attempts, so can_retry() returns true immediately
        let lifecycle = Arc::new(RwLock::new(lm));
        let monitor = HealthMonitor::with_defaults(Arc::clone(&lifecycle));

        let mut adapters: HashMap<String, Box<dyn ToolAdapter>> = HashMap::new();
        adapters.insert("recoverable".to_string(), Box::new(RecoverableAdapter));

        // First check cycle should trigger auto-restart and succeed
        monitor.check_all_tools(&adapters).await;

        let lm = lifecycle.read().await;
        assert_eq!(lm.get_status("recoverable"), Some(ToolStatus::Running));
    }
}
