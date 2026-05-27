// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Tool orchestrator managing the lifecycle of all integrated security tools.
//!
//! The orchestrator is the central coordination point for installing, starting,
//! stopping, and monitoring security tools. It delegates state management to the
//! [`LifecycleManager`] and health monitoring to the [`HealthMonitor`].

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{error, info, warn};

use shared::distro::DistroInfo;
use shared::errors::{CommandCenterError, Result};
use shared::types::{ToolInfo, ToolStatus};

use super::adapter::ToolAdapter;
use super::lifecycle::LifecycleManager;
use super::plan::{InstallPlan, InstallPhase, PlanEntry};

/// Central orchestrator managing all registered security tool adapters.
///
/// Provides a unified interface for tool lifecycle operations and delegates
/// state tracking to the internal [`LifecycleManager`].
pub struct ToolOrchestrator {
    /// Registered tool adapters keyed by tool name.
    adapters: HashMap<String, Box<dyn ToolAdapter>>,
    /// Lifecycle state machine managing tool states.
    lifecycle: Arc<RwLock<LifecycleManager>>,
}

impl ToolOrchestrator {
    /// Creates a new orchestrator with no registered tools.
    pub fn new() -> Self {
        Self {
            adapters: HashMap::new(),
            lifecycle: Arc::new(RwLock::new(LifecycleManager::new())),
        }
    }

    /// Returns a shared reference to the lifecycle manager.
    ///
    /// Used by the [`HealthMonitor`](super::health::HealthMonitor) to update
    /// tool states based on health check results.
    pub fn lifecycle(&self) -> Arc<RwLock<LifecycleManager>> {
        Arc::clone(&self.lifecycle)
    }

    /// Registers a tool adapter with the orchestrator.
    ///
    /// The tool is initially registered in the `NotInstalled` state.
    pub async fn register_tool(&mut self, adapter: Box<dyn ToolAdapter>) {
        let name = adapter.name().to_string();
        info!(tool = %name, "Registering tool adapter");
        self.lifecycle.write().await.register(&name);
        self.adapters.insert(name, adapter);
    }

    /// Installs a tool using its adapter, transitioning through the state machine.
    ///
    /// State transitions: `NotInstalled` → `Installing` → `Stopped`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tool is not registered
    /// - The state transition is invalid (tool already installed)
    /// - The installation itself fails
    pub async fn install_tool(&self, name: &str, distro: &DistroInfo) -> Result<()> {
        let adapter = self.adapters.get(name).ok_or_else(|| {
            CommandCenterError::ToolNotAvailable {
                tool: name.to_string(),
            }
        })?;

        if !adapter.is_available_for(distro) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: name.to_string(),
                reason: format!(
                    "Tool is not available for distribution '{}' ({})",
                    distro.name, distro.id
                ),
            });
        }

        // Transition to Installing
        self.lifecycle.write().await.transition_to_installing(name)?;
        info!(tool = name, "Starting installation");

        // Perform installation
        match adapter.install(distro).await {
            Ok(()) => {
                self.lifecycle.write().await.transition_to_stopped(name)?;
                info!(tool = name, "Installation completed successfully");
                Ok(())
            }
            Err(e) => {
                // Revert to NotInstalled on failure
                warn!(tool = name, error = %e, "Installation failed, reverting state");
                let mut lm = self.lifecycle.write().await;
                lm.force_not_installed(name);
                Err(e)
            }
        }
    }

    /// Starts a tool using its adapter, transitioning through the state machine.
    ///
    /// State transitions: `Stopped`/`Error` → `Starting` → `Running`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tool is not registered
    /// - The state transition is invalid (e.g., tool not installed)
    /// - The tool fails to start
    pub async fn start_tool(&self, name: &str) -> Result<()> {
        let adapter = self.adapters.get(name).ok_or_else(|| {
            CommandCenterError::ToolNotAvailable {
                tool: name.to_string(),
            }
        })?;

        // Transition to Starting
        self.lifecycle.write().await.transition_to_starting(name)?;
        info!(tool = name, "Starting tool");

        // Perform start
        match adapter.start().await {
            Ok(()) => {
                self.lifecycle.write().await.transition_to_running(name)?;
                info!(tool = name, "Tool started successfully");
                Ok(())
            }
            Err(e) => {
                error!(tool = name, error = %e, "Tool failed to start");
                self.lifecycle.write().await.transition_to_error(name)?;
                Err(e)
            }
        }
    }

    /// Stops a tool using its adapter.
    ///
    /// State transitions: `Running`/`Starting` → `Stopped`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tool is not registered
    /// - The state transition is invalid
    /// - The tool fails to stop
    pub async fn stop_tool(&self, name: &str) -> Result<()> {
        let adapter = self.adapters.get(name).ok_or_else(|| {
            CommandCenterError::ToolNotAvailable {
                tool: name.to_string(),
            }
        })?;

        info!(tool = name, "Stopping tool");

        // Perform stop
        match adapter.stop().await {
            Ok(()) => {
                self.lifecycle.write().await.transition_to_stopped(name)?;
                info!(tool = name, "Tool stopped successfully");
                Ok(())
            }
            Err(e) => {
                error!(tool = name, error = %e, "Tool failed to stop");
                Err(e)
            }
        }
    }

    /// Returns the current status of a tool.
    pub async fn get_status(&self, name: &str) -> Option<ToolStatus> {
        self.lifecycle.read().await.get_status(name)
    }

    /// Returns information about all registered tools.
    pub async fn list_tools(&self) -> Vec<ToolInfo> {
        let lm = self.lifecycle.read().await;
        self.adapters
            .values()
            .map(|adapter| {
                let name = adapter.name().to_string();
                let status = lm.get_status(&name).unwrap_or(ToolStatus::NotInstalled);
                ToolInfo {
                    name,
                    display_name: adapter.display_name().to_string(),
                    status,
                    version: None,
                    last_active: None,
                }
            })
            .collect()
    }

    /// Generates an installation plan for the given distribution.
    ///
    /// The plan groups tools into phases (Foundation, Detection, Runtime,
    /// GitSecurity) and indicates which tools are available for the distro.
    pub fn generate_install_plan(&self, distro: &DistroInfo) -> InstallPlan {
        use super::adapter::ToolCategory;

        let mut foundation_entries = Vec::new();
        let mut detection_entries = Vec::new();
        let mut runtime_entries = Vec::new();
        let mut git_entries = Vec::new();

        for adapter in self.adapters.values() {
            let available = adapter.is_available_for(distro);
            let entry = PlanEntry {
                name: adapter.name().to_string(),
                display_name: adapter.display_name().to_string(),
                package_name: shared::distro::adapter_for(distro.package_manager)
                    .map_tool_package(adapter.name()),
                estimated_size_bytes: adapter.estimated_size_bytes(),
                available_for_distro: available,
            };

            match adapter.category() {
                ToolCategory::Visibility => foundation_entries.push(entry),
                ToolCategory::Protection => runtime_entries.push(entry),
                ToolCategory::Detection => detection_entries.push(entry),
                ToolCategory::GitSecurity => git_entries.push(entry),
            }
        }

        InstallPlan {
            distro_name: distro.name.clone(),
            package_manager: distro.package_manager,
            phases: vec![
                InstallPhase {
                    name: "Foundation (Visibility)".to_string(),
                    description: "Core visibility tools for system state awareness".to_string(),
                    entries: foundation_entries,
                },
                InstallPhase {
                    name: "Detection".to_string(),
                    description: "Malware scanning, rootkit detection, and integrity monitoring"
                        .to_string(),
                    entries: detection_entries,
                },
                InstallPhase {
                    name: "Runtime (Protection)".to_string(),
                    description: "Active protection tools: firewall, USB control, sandboxing"
                        .to_string(),
                    entries: runtime_entries,
                },
                InstallPhase {
                    name: "Git Security".to_string(),
                    description: "Secrets scanning for git repositories".to_string(),
                    entries: git_entries,
                },
            ],
        }
    }

    /// Returns a reference to a registered adapter by name.
    pub fn get_adapter(&self, name: &str) -> Option<&dyn ToolAdapter> {
        self.adapters.get(name).map(|a| a.as_ref())
    }
}

impl Default for ToolOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::adapter::{HealthStatus, ToolCategory};
    use async_trait::async_trait;
    use shared::distro::{MACFramework, PackageManager};

    /// A mock tool adapter for testing.
    struct MockAdapter {
        tool_name: &'static str,
        display: &'static str,
        category: ToolCategory,
        available: bool,
        install_fails: bool,
        start_fails: bool,
    }

    impl MockAdapter {
        fn new(name: &'static str) -> Self {
            Self {
                tool_name: name,
                display: name,
                category: ToolCategory::Visibility,
                available: true,
                install_fails: false,
                start_fails: false,
            }
        }

        fn with_category(mut self, cat: ToolCategory) -> Self {
            self.category = cat;
            self
        }

        fn unavailable(mut self) -> Self {
            self.available = false;
            self
        }

        fn failing_install(mut self) -> Self {
            self.install_fails = true;
            self
        }

        fn failing_start(mut self) -> Self {
            self.start_fails = true;
            self
        }
    }

    #[async_trait]
    impl ToolAdapter for MockAdapter {
        fn name(&self) -> &str {
            self.tool_name
        }
        fn display_name(&self) -> &str {
            self.display
        }
        fn category(&self) -> ToolCategory {
            self.category
        }
        async fn install(&self, _distro: &DistroInfo) -> Result<()> {
            if self.install_fails {
                Err(CommandCenterError::ToolOperationFailed {
                    tool: self.tool_name.to_string(),
                    reason: "mock install failure".to_string(),
                })
            } else {
                Ok(())
            }
        }
        async fn start(&self) -> Result<()> {
            if self.start_fails {
                Err(CommandCenterError::ToolOperationFailed {
                    tool: self.tool_name.to_string(),
                    reason: "mock start failure".to_string(),
                })
            } else {
                Ok(())
            }
        }
        async fn stop(&self) -> Result<()> {
            Ok(())
        }
        async fn health_check(&self) -> HealthStatus {
            HealthStatus::Healthy
        }
        fn is_available_for(&self, _distro: &DistroInfo) -> bool {
            self.available
        }
    }

    fn test_distro() -> DistroInfo {
        DistroInfo {
            id: "ubuntu".to_string(),
            version_id: "22.04".to_string(),
            name: "Ubuntu 22.04".to_string(),
            package_manager: PackageManager::Apt,
            has_btrfs: false,
            kernel_version: (6, 5),
            has_ebpf: true,
            mac_framework: MACFramework::AppArmor,
        }
    }

    #[tokio::test]
    async fn test_register_and_list_tools() {
        let mut orch = ToolOrchestrator::new();
        orch.register_tool(Box::new(MockAdapter::new("falco"))).await;
        orch.register_tool(Box::new(MockAdapter::new("clamav").with_category(ToolCategory::Detection))).await;

        let tools = orch.list_tools().await;
        assert_eq!(tools.len(), 2);
        assert!(tools.iter().all(|t| t.status == ToolStatus::NotInstalled));
    }

    #[tokio::test]
    async fn test_install_and_start_tool() {
        let mut orch = ToolOrchestrator::new();
        orch.register_tool(Box::new(MockAdapter::new("falco"))).await;

        let distro = test_distro();
        assert!(orch.install_tool("falco", &distro).await.is_ok());
        assert_eq!(orch.get_status("falco").await, Some(ToolStatus::Stopped));

        assert!(orch.start_tool("falco").await.is_ok());
        assert_eq!(orch.get_status("falco").await, Some(ToolStatus::Running));
    }

    #[tokio::test]
    async fn test_install_unavailable_tool_fails() {
        let mut orch = ToolOrchestrator::new();
        orch.register_tool(Box::new(MockAdapter::new("falco").unavailable())).await;

        let distro = test_distro();
        let result = orch.install_tool("falco", &distro).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_install_failure_reverts_state() {
        let mut orch = ToolOrchestrator::new();
        orch.register_tool(Box::new(MockAdapter::new("falco").failing_install())).await;

        let distro = test_distro();
        let result = orch.install_tool("falco", &distro).await;
        assert!(result.is_err());
        // State should be reverted to NotInstalled
        assert_eq!(orch.get_status("falco").await, Some(ToolStatus::NotInstalled));
    }

    #[tokio::test]
    async fn test_start_failure_transitions_to_error() {
        let mut orch = ToolOrchestrator::new();
        orch.register_tool(Box::new(MockAdapter::new("falco").failing_start())).await;

        let distro = test_distro();
        orch.install_tool("falco", &distro).await.unwrap();

        let result = orch.start_tool("falco").await;
        assert!(result.is_err());
        assert_eq!(orch.get_status("falco").await, Some(ToolStatus::Error));
    }

    #[tokio::test]
    async fn test_stop_tool() {
        let mut orch = ToolOrchestrator::new();
        orch.register_tool(Box::new(MockAdapter::new("falco"))).await;

        let distro = test_distro();
        orch.install_tool("falco", &distro).await.unwrap();
        orch.start_tool("falco").await.unwrap();

        assert!(orch.stop_tool("falco").await.is_ok());
        assert_eq!(orch.get_status("falco").await, Some(ToolStatus::Stopped));
    }

    #[tokio::test]
    async fn test_generate_install_plan() {
        let mut orch = ToolOrchestrator::new();
        orch.register_tool(Box::new(MockAdapter::new("osquery").with_category(ToolCategory::Visibility))).await;
        orch.register_tool(Box::new(MockAdapter::new("clamav").with_category(ToolCategory::Detection))).await;
        orch.register_tool(Box::new(MockAdapter::new("ufw").with_category(ToolCategory::Protection))).await;
        orch.register_tool(Box::new(MockAdapter::new("gitleaks").with_category(ToolCategory::GitSecurity))).await;

        let distro = test_distro();
        let plan = orch.generate_install_plan(&distro);

        assert_eq!(plan.phases.len(), 4);
        assert_eq!(plan.distro_name, "Ubuntu 22.04");
        // Foundation phase should have osquery
        assert!(plan.phases[0].entries.iter().any(|e| e.name == "osquery"));
        // Detection phase should have clamav
        assert!(plan.phases[1].entries.iter().any(|e| e.name == "clamav"));
        // Runtime phase should have ufw
        assert!(plan.phases[2].entries.iter().any(|e| e.name == "ufw"));
        // Git phase should have gitleaks
        assert!(plan.phases[3].entries.iter().any(|e| e.name == "gitleaks"));
    }

    #[tokio::test]
    async fn test_unregistered_tool_operations_fail() {
        let orch = ToolOrchestrator::new();
        let distro = test_distro();

        assert!(orch.install_tool("nonexistent", &distro).await.is_err());
        assert!(orch.start_tool("nonexistent").await.is_err());
        assert!(orch.stop_tool("nonexistent").await.is_err());
        assert_eq!(orch.get_status("nonexistent").await, None);
    }
}
