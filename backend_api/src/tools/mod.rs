// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Tool orchestration module for the Linux Security Home Command Center.
//!
//! Manages the lifecycle of integrated security tools: installation, startup,
//! health monitoring, automatic restart on failure, and installation planning.

pub mod adapter;
pub mod adapters;
pub mod health;
pub mod lifecycle;
pub mod orchestrator;
pub mod plan;

pub use adapter::{HealthStatus, ToolAdapter, ToolCategory};
pub use health::HealthMonitor;
pub use lifecycle::LifecycleManager;
pub use orchestrator::ToolOrchestrator;
pub use plan::{InstallPlan, InstallPhase, PlanEntry};
