// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! System context assembler for IronClaw.
//!
//! Gathers current system state and formats it as a context prefix
//! for LLM prompts, enabling context-aware responses.

use serde::{Deserialize, Serialize};

/// Assembled system context for LLM prompt enrichment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemContext {
    /// Overall system health score (0-100).
    pub health_score: u8,
    /// Number of currently active alerts.
    pub active_alerts: u32,
    /// Status summary of monitored tools.
    pub tool_statuses: Vec<ToolStatusSummary>,
    /// Recent security events (last 5).
    pub recent_events: Vec<RecentEvent>,
    /// Whether paranoia mode is active.
    pub paranoia_mode: bool,
    /// Whether the system is in offline mode.
    pub offline_mode: bool,
}

/// Summary of a tool's status for context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolStatusSummary {
    /// Tool name.
    pub name: String,
    /// Current status as a string.
    pub status: String,
}

/// A recent event summary for context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentEvent {
    /// Event summary text.
    pub summary: String,
    /// Severity level.
    pub severity: String,
    /// Source tool.
    pub source: String,
    /// Timestamp as ISO 8601 string.
    pub timestamp: String,
}

/// Assembles system context from application state.
pub struct ContextAssembler;

impl ContextAssembler {
    /// Assembles a `SystemContext` from the current application state.
    ///
    /// In production, this reads from the shared AppState stores.
    /// For now, provides a default context that can be populated.
    pub fn assemble(
        health_score: u8,
        active_alerts: u32,
        tool_statuses: Vec<ToolStatusSummary>,
        recent_events: Vec<RecentEvent>,
        paranoia_mode: bool,
        offline_mode: bool,
    ) -> SystemContext {
        SystemContext {
            health_score,
            active_alerts,
            tool_statuses,
            recent_events,
            paranoia_mode,
            offline_mode,
        }
    }

    /// Formats the system context as a system prompt prefix for the LLM.
    pub fn format_as_prompt(ctx: &SystemContext) -> String {
        let mut prompt = String::new();

        prompt.push_str("[SYSTEM CONTEXT]\n");
        prompt.push_str(&format!("Health Score: {}/100\n", ctx.health_score));
        prompt.push_str(&format!("Active Alerts: {}\n", ctx.active_alerts));
        prompt.push_str(&format!(
            "Paranoia Mode: {}\n",
            if ctx.paranoia_mode { "ACTIVE" } else { "inactive" }
        ));
        prompt.push_str(&format!(
            "Offline Mode: {}\n",
            if ctx.offline_mode { "YES" } else { "no" }
        ));

        if !ctx.tool_statuses.is_empty() {
            prompt.push_str("\nTool Statuses:\n");
            for tool in &ctx.tool_statuses {
                prompt.push_str(&format!("  - {}: {}\n", tool.name, tool.status));
            }
        }

        if !ctx.recent_events.is_empty() {
            prompt.push_str("\nRecent Events:\n");
            for event in &ctx.recent_events {
                prompt.push_str(&format!(
                    "  - [{}] {} ({}): {}\n",
                    event.timestamp, event.source, event.severity, event.summary
                ));
            }
        }

        prompt.push_str("[END CONTEXT]\n\n");
        prompt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_default_context() {
        let ctx = ContextAssembler::assemble(85, 2, vec![], vec![], false, false);
        assert_eq!(ctx.health_score, 85);
        assert_eq!(ctx.active_alerts, 2);
        assert!(!ctx.paranoia_mode);
        assert!(!ctx.offline_mode);
    }

    #[test]
    fn test_format_as_prompt_basic() {
        let ctx = ContextAssembler::assemble(92, 0, vec![], vec![], false, false);
        let prompt = ContextAssembler::format_as_prompt(&ctx);
        assert!(prompt.contains("Health Score: 92/100"));
        assert!(prompt.contains("Active Alerts: 0"));
        assert!(prompt.contains("[SYSTEM CONTEXT]"));
        assert!(prompt.contains("[END CONTEXT]"));
    }

    #[test]
    fn test_format_as_prompt_with_tools_and_events() {
        let tools = vec![
            ToolStatusSummary {
                name: "falco".to_string(),
                status: "running".to_string(),
            },
            ToolStatusSummary {
                name: "clamav".to_string(),
                status: "stopped".to_string(),
            },
        ];
        let events = vec![RecentEvent {
            summary: "Suspicious process detected".to_string(),
            severity: "high".to_string(),
            source: "falco".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
        }];

        let ctx = ContextAssembler::assemble(75, 3, tools, events, true, false);
        let prompt = ContextAssembler::format_as_prompt(&ctx);

        assert!(prompt.contains("Paranoia Mode: ACTIVE"));
        assert!(prompt.contains("falco: running"));
        assert!(prompt.contains("clamav: stopped"));
        assert!(prompt.contains("Suspicious process detected"));
    }
}
