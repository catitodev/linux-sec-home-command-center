// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Tool adapter trait defining the interface for security tool integrations.
//!
//! Each security tool (Falco, ClamAV, osquery, etc.) implements this trait
//! to provide a uniform lifecycle management interface to the orchestrator.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use shared::distro::DistroInfo;
use shared::errors::Result;

/// Category of a security tool within the three-pillar architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCategory {
    /// Visibility tools: know everything happening on the system.
    Visibility,
    /// Protection tools: block, prevent, isolate threats.
    Protection,
    /// Detection tools: find threats, scan for malware, audit hardening.
    Detection,
    /// Git security tools: secrets scanning and pre-commit hooks.
    GitSecurity,
}

/// Health status reported by a tool's health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// Tool is operating normally.
    Healthy,
    /// Tool is running but experiencing issues.
    Degraded(String),
    /// Tool is not healthy and likely needs restart.
    Unhealthy(String),
    /// Tool is not currently running.
    NotRunning,
}

/// Trait defining the interface for a security tool adapter.
///
/// Each integrated security tool implements this trait to allow the
/// [`ToolOrchestrator`](super::orchestrator::ToolOrchestrator) to manage
/// its lifecycle uniformly.
#[async_trait]
pub trait ToolAdapter: Send + Sync {
    /// Returns the internal identifier for this tool (e.g., "falco", "clamav").
    fn name(&self) -> &str;

    /// Returns the human-readable display name (e.g., "Falco", "ClamAV").
    fn display_name(&self) -> &str;

    /// Returns the category this tool belongs to.
    fn category(&self) -> ToolCategory;

    /// Installs the tool using the appropriate package manager for the distro.
    ///
    /// # Errors
    ///
    /// Returns an error if installation fails (package not found, network issue, etc.).
    async fn install(&self, distro: &DistroInfo) -> Result<()>;

    /// Starts the tool (e.g., enables and starts its systemd service).
    ///
    /// # Errors
    ///
    /// Returns an error if the tool fails to start.
    async fn start(&self) -> Result<()>;

    /// Stops the tool gracefully.
    ///
    /// # Errors
    ///
    /// Returns an error if the tool fails to stop.
    async fn stop(&self) -> Result<()>;

    /// Performs a health check on the tool.
    ///
    /// Returns the current health status without modifying tool state.
    async fn health_check(&self) -> HealthStatus;

    /// Checks whether this tool is available for the given distribution.
    ///
    /// Some tools may not have packages for certain distributions or may
    /// require specific kernel features (e.g., Falco requires eBPF).
    fn is_available_for(&self, distro: &DistroInfo) -> bool;

    /// Returns the estimated download size in bytes for this tool's package.
    ///
    /// This is an approximation used for installation plan display.
    fn estimated_size_bytes(&self) -> u64 {
        0
    }
}

impl std::fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolCategory::Visibility => write!(f, "Visibility"),
            ToolCategory::Protection => write!(f, "Protection"),
            ToolCategory::Detection => write!(f, "Detection"),
            ToolCategory::GitSecurity => write!(f, "Git Security"),
        }
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "Healthy"),
            HealthStatus::Degraded(msg) => write!(f, "Degraded: {}", msg),
            HealthStatus::Unhealthy(msg) => write!(f, "Unhealthy: {}", msg),
            HealthStatus::NotRunning => write!(f, "Not Running"),
        }
    }
}
