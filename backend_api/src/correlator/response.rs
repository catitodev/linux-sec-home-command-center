// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Automated Response Engine.
//!
//! Evaluates correlated incidents against response rules and executes
//! automated actions with rate limiting, queuing, and reversal recording.

use std::collections::VecDeque;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use shared::types::ToolSource;

use super::engine::CorrelatedIncident;

/// Maximum number of response rules allowed.
const MAX_RULES: usize = 50;

/// Maximum actions per rule.
const MAX_ACTIONS_PER_RULE: usize = 5;

/// Maximum actions per rate-limit window (60 seconds).
const RATE_LIMIT_MAX_ACTIONS: usize = 10;

/// Rate limit window duration in seconds.
const RATE_LIMIT_WINDOW_SECS: i64 = 60;

/// Reversal record retention period in hours.
const REVERSAL_RETENTION_HOURS: i64 = 72;

/// Type of automated response action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    /// Kill a process by PID.
    KillProcess { pid: u32 },
    /// Block an IP address via firewall.
    BlockIp { address: String },
    /// Disable a network interface.
    DisableInterface { interface: String },
    /// Send an alert notification.
    Alert { message: String },
    /// Quarantine a file.
    QuarantineFile { path: String },
    /// Custom command execution.
    CustomCommand { command: String },
}

/// Condition that must be met for a rule to trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    /// Minimum severity score to trigger (1-10).
    pub severity_threshold: u8,
    /// Optional: only trigger if specific tools are involved.
    pub tool_match: Option<Vec<ToolSource>>,
    /// Optional: keyword match in incident summary.
    pub keyword_match: Option<Vec<String>>,
}

/// A response rule defining when and what actions to take.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRule {
    /// Unique rule identifier.
    pub id: Uuid,
    /// Human-readable rule name.
    pub name: String,
    /// Condition that triggers this rule.
    pub condition: RuleCondition,
    /// Actions to execute when triggered (max 5).
    pub actions: Vec<ResponseAction>,
    /// Whether this rule is currently enabled.
    pub enabled: bool,
}

/// Result of executing a response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// The action that was executed.
    pub action: ResponseAction,
    /// Whether execution succeeded.
    pub success: bool,
    /// Timestamp of execution.
    pub executed_at: DateTime<Utc>,
    /// Error message if failed.
    pub error: Option<String>,
}

/// A pending action waiting in the queue (rate-limited).
#[derive(Debug, Clone)]
pub struct PendingAction {
    /// The action to execute.
    pub action: ResponseAction,
    /// When it was queued.
    pub queued_at: DateTime<Utc>,
    /// The incident that triggered this action.
    pub incident_id: Uuid,
}

/// Record of a reversal procedure for a destructive action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReversalRecord {
    /// The original action that was taken.
    pub original_action: ResponseAction,
    /// Description of how to reverse the action.
    pub reversal_procedure: String,
    /// When the action was executed.
    pub executed_at: DateTime<Utc>,
    /// When this record expires (72 hours after execution).
    pub expires_at: DateTime<Utc>,
    /// Whether the reversal has been applied.
    pub reversed: bool,
}

/// Rate limiting window tracker.
#[derive(Debug, Clone)]
pub struct RateWindow {
    /// Timestamps of actions executed in the current window.
    pub action_timestamps: VecDeque<DateTime<Utc>>,
}

impl RateWindow {
    /// Creates a new empty rate window.
    fn new() -> Self {
        Self {
            action_timestamps: VecDeque::new(),
        }
    }

    /// Checks if an action can be executed within rate limits.
    fn can_execute(&mut self, now: DateTime<Utc>) -> bool {
        let cutoff = now - Duration::seconds(RATE_LIMIT_WINDOW_SECS);
        // Remove timestamps outside the window
        while let Some(front) = self.action_timestamps.front() {
            if *front < cutoff {
                self.action_timestamps.pop_front();
            } else {
                break;
            }
        }
        self.action_timestamps.len() < RATE_LIMIT_MAX_ACTIONS
    }

    /// Records an action execution.
    fn record_action(&mut self, now: DateTime<Utc>) {
        self.action_timestamps.push_back(now);
    }
}

/// The automated response engine.
pub struct ResponseEngine {
    /// Active response rules (max 50).
    pub rules: Vec<ResponseRule>,
    /// Rate limiter for action execution.
    pub rate_limiter: RateWindow,
    /// Queue of actions waiting to be executed.
    pub action_queue: VecDeque<PendingAction>,
    /// Records of reversible actions.
    pub reversal_records: Vec<ReversalRecord>,
    /// Whether paranoia mode is enabled (lower severity threshold).
    pub paranoia_mode: bool,
}

impl ResponseEngine {
    /// Creates a new response engine with default rules.
    pub fn new() -> Self {
        let mut engine = Self {
            rules: Vec::new(),
            rate_limiter: RateWindow::new(),
            action_queue: VecDeque::new(),
            reversal_records: Vec::new(),
            paranoia_mode: false,
        };
        engine.load_default_rules();
        engine
    }

    /// Creates a response engine with paranoia mode enabled.
    pub fn with_paranoia_mode() -> Self {
        let mut engine = Self::new();
        engine.paranoia_mode = true;
        engine
    }

    /// Adds a response rule. Returns false if max rules reached or max actions exceeded.
    pub fn add_rule(&mut self, rule: ResponseRule) -> bool {
        if self.rules.len() >= MAX_RULES {
            return false;
        }
        if rule.actions.len() > MAX_ACTIONS_PER_RULE {
            return false;
        }
        self.rules.push(rule);
        true
    }

    /// Evaluates an incident against all enabled rules and returns matching actions.
    pub fn evaluate(&self, incident: &CorrelatedIncident) -> Vec<ResponseAction> {
        let severity_threshold = if self.paranoia_mode { 5 } else { 8 };

        if incident.severity_score < severity_threshold {
            return Vec::new();
        }

        let mut actions = Vec::new();
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if self.rule_matches(rule, incident) {
                actions.extend(rule.actions.iter().cloned());
            }
        }
        actions
    }

    /// Executes a response action, respecting rate limits.
    ///
    /// If rate-limited, the action is queued for later execution.
    /// Returns `Ok(ActionResult)` on success, or queues the action.
    pub fn execute_action(
        &mut self,
        action: &ResponseAction,
        incident_id: Uuid,
    ) -> Result<ActionResult, String> {
        let now = Utc::now();

        if !self.rate_limiter.can_execute(now) {
            // Queue the action for later
            self.action_queue.push_back(PendingAction {
                action: action.clone(),
                queued_at: now,
                incident_id,
            });
            return Err("Rate limited: action queued for next window".to_string());
        }

        self.rate_limiter.record_action(now);

        // Record reversal for destructive actions
        if self.is_destructive(action) {
            self.record_reversal(action, now);
        }

        // Execute the action (in production this would call system commands)
        let result = ActionResult {
            action: action.clone(),
            success: true,
            executed_at: now,
            error: None,
        };

        Ok(result)
    }

    /// Processes queued actions that were rate-limited.
    /// Returns results for actions that could be executed.
    pub fn process_queue(&mut self) -> Vec<Result<ActionResult, String>> {
        let mut results = Vec::new();
        let now = Utc::now();

        while let Some(_pending) = self.action_queue.front() {
            if !self.rate_limiter.can_execute(now) {
                break;
            }
            let pending = self.action_queue.pop_front().unwrap();
            self.rate_limiter.record_action(now);

            if self.is_destructive(&pending.action) {
                self.record_reversal(&pending.action, now);
            }

            results.push(Ok(ActionResult {
                action: pending.action,
                success: true,
                executed_at: now,
                error: None,
            }));
        }
        results
    }

    /// Cleans up expired reversal records (older than 72 hours).
    pub fn cleanup_reversals(&mut self) {
        let now = Utc::now();
        self.reversal_records.retain(|r| r.expires_at > now);
    }

    /// Loads default response rules for common threat scenarios.
    fn load_default_rules(&mut self) {
        // Rule: Reverse shell detection
        self.rules.push(ResponseRule {
            id: Uuid::new_v4(),
            name: "reverse_shell".to_string(),
            condition: RuleCondition {
                severity_threshold: 8,
                tool_match: Some(vec![ToolSource::Falco, ToolSource::Auditd]),
                keyword_match: Some(vec!["reverse".to_string(), "shell".to_string()]),
            },
            actions: vec![
                ResponseAction::KillProcess { pid: 0 }, // PID filled at runtime
                ResponseAction::BlockIp {
                    address: "0.0.0.0".to_string(), // IP filled at runtime
                },
            ],
            enabled: true,
        });

        // Rule: Brute force detection
        self.rules.push(ResponseRule {
            id: Uuid::new_v4(),
            name: "brute_force".to_string(),
            condition: RuleCondition {
                severity_threshold: 7,
                tool_match: Some(vec![ToolSource::CrowdSec]),
                keyword_match: Some(vec!["brute".to_string(), "force".to_string()]),
            },
            actions: vec![ResponseAction::BlockIp {
                address: "0.0.0.0".to_string(),
            }],
            enabled: true,
        });

        // Rule: Rootkit detection
        self.rules.push(ResponseRule {
            id: Uuid::new_v4(),
            name: "rootkit".to_string(),
            condition: RuleCondition {
                severity_threshold: 9,
                tool_match: None,
                keyword_match: Some(vec!["rootkit".to_string()]),
            },
            actions: vec![
                ResponseAction::DisableInterface {
                    interface: "eth0".to_string(),
                },
                ResponseAction::Alert {
                    message: "CRITICAL: Rootkit detected - network interfaces disabled"
                        .to_string(),
                },
            ],
            enabled: true,
        });
    }

    /// Checks if a rule matches the given incident.
    fn rule_matches(&self, rule: &ResponseRule, incident: &CorrelatedIncident) -> bool {
        // Check severity threshold (in paranoia mode, use the lower of rule threshold or 5)
        let effective_threshold = if self.paranoia_mode {
            rule.condition.severity_threshold.min(5)
        } else {
            rule.condition.severity_threshold
        };
        if incident.severity_score < effective_threshold {
            return false;
        }

        // Check tool match if specified
        if let Some(ref required_tools) = rule.condition.tool_match {
            let incident_tools: std::collections::HashSet<&ToolSource> = incident
                .contributing_events
                .iter()
                .map(|e| &e.source)
                .collect();
            let has_tool_match = required_tools.iter().any(|t| incident_tools.contains(t));
            if !has_tool_match {
                return false;
            }
        }

        // Check keyword match if specified
        if let Some(ref keywords) = rule.condition.keyword_match {
            let summary_lower = incident.summary.to_lowercase();
            let has_keyword = keywords
                .iter()
                .any(|kw| summary_lower.contains(&kw.to_lowercase()));
            if !has_keyword {
                return false;
            }
        }

        true
    }

    /// Checks if an action is destructive (requires reversal recording).
    fn is_destructive(&self, action: &ResponseAction) -> bool {
        matches!(
            action,
            ResponseAction::KillProcess { .. }
                | ResponseAction::BlockIp { .. }
                | ResponseAction::DisableInterface { .. }
                | ResponseAction::QuarantineFile { .. }
        )
    }

    /// Records a reversal procedure for a destructive action.
    fn record_reversal(&mut self, action: &ResponseAction, executed_at: DateTime<Utc>) {
        let reversal_procedure = match action {
            ResponseAction::KillProcess { pid } => {
                format!("Process {} was killed. Manual restart may be required.", pid)
            }
            ResponseAction::BlockIp { address } => {
                format!("Unblock IP {} from firewall rules.", address)
            }
            ResponseAction::DisableInterface { interface } => {
                format!("Re-enable network interface: ip link set {} up", interface)
            }
            ResponseAction::QuarantineFile { path } => {
                format!("Restore file from quarantine: {}", path)
            }
            _ => return, // Non-destructive actions don't need reversal
        };

        self.reversal_records.push(ReversalRecord {
            original_action: action.clone(),
            reversal_procedure,
            executed_at,
            expires_at: executed_at + Duration::hours(REVERSAL_RETENTION_HOURS),
            reversed: false,
        });
    }
}

impl Default for ResponseEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlator::engine::IncidentStatus;
    use shared::types::{NormalizedEvent, Severity};

    fn make_incident(severity: u8, tools: Vec<ToolSource>, summary: &str) -> CorrelatedIncident {
        let events: Vec<NormalizedEvent> = tools
            .iter()
            .map(|t| NormalizedEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                source: t.clone(),
                severity: Severity::High,
                summary: summary.to_string(),
                details: None,
                entities: Vec::new(),
                acknowledged: false,
                correlation_id: None,
            })
            .collect();

        CorrelatedIncident {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            severity_score: severity,
            confidence_score: 0.5,
            contributing_tool_count: tools.len(),
            status: IncidentStatus::Open,
            contributing_events: events,
            summary: summary.to_string(),
        }
    }

    #[test]
    fn test_evaluate_below_threshold_no_actions() {
        let engine = ResponseEngine::new();
        let incident = make_incident(5, vec![ToolSource::Falco], "low severity event");
        let actions = engine.evaluate(&incident);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_evaluate_reverse_shell_rule() {
        let engine = ResponseEngine::new();
        let incident = make_incident(
            9,
            vec![ToolSource::Falco, ToolSource::Auditd],
            "Reverse shell detected from 10.0.0.1",
        );
        let actions = engine.evaluate(&incident);
        assert!(!actions.is_empty());
        // Should have kill + block actions
        assert!(actions.iter().any(|a| matches!(a, ResponseAction::KillProcess { .. })));
        assert!(actions.iter().any(|a| matches!(a, ResponseAction::BlockIp { .. })));
    }

    #[test]
    fn test_rate_limiting() {
        let mut engine = ResponseEngine::new();
        let incident_id = Uuid::new_v4();
        let action = ResponseAction::Alert {
            message: "test".to_string(),
        };

        // Execute 10 actions (should all succeed)
        for _ in 0..RATE_LIMIT_MAX_ACTIONS {
            let result = engine.execute_action(&action, incident_id);
            assert!(result.is_ok());
        }

        // 11th action should be rate-limited
        let result = engine.execute_action(&action, incident_id);
        assert!(result.is_err());
        assert_eq!(engine.action_queue.len(), 1);
    }

    #[test]
    fn test_reversal_recording() {
        let mut engine = ResponseEngine::new();
        let incident_id = Uuid::new_v4();
        let action = ResponseAction::BlockIp {
            address: "192.168.1.100".to_string(),
        };

        engine.execute_action(&action, incident_id).unwrap();
        assert_eq!(engine.reversal_records.len(), 1);
        assert!(engine.reversal_records[0]
            .reversal_procedure
            .contains("192.168.1.100"));
        assert!(!engine.reversal_records[0].reversed);
    }

    #[test]
    fn test_max_rules_limit() {
        let mut engine = ResponseEngine::new();
        // Engine starts with 3 default rules, fill up to MAX_RULES
        let remaining = MAX_RULES - engine.rules.len();
        for i in 0..remaining {
            let rule = ResponseRule {
                id: Uuid::new_v4(),
                name: format!("rule_{}", i),
                condition: RuleCondition {
                    severity_threshold: 8,
                    tool_match: None,
                    keyword_match: None,
                },
                actions: vec![ResponseAction::Alert {
                    message: "test".to_string(),
                }],
                enabled: true,
            };
            assert!(engine.add_rule(rule));
        }
        // Next rule should fail
        let extra_rule = ResponseRule {
            id: Uuid::new_v4(),
            name: "overflow".to_string(),
            condition: RuleCondition {
                severity_threshold: 8,
                tool_match: None,
                keyword_match: None,
            },
            actions: vec![ResponseAction::Alert {
                message: "test".to_string(),
            }],
            enabled: true,
        };
        assert!(!engine.add_rule(extra_rule));
    }

    #[test]
    fn test_paranoia_mode_lower_threshold() {
        let engine = ResponseEngine::with_paranoia_mode();
        let incident = make_incident(
            6,
            vec![ToolSource::Falco, ToolSource::Auditd],
            "Reverse shell attempt",
        );
        let actions = engine.evaluate(&incident);
        // In paranoia mode, threshold is 5, so severity 6 should trigger
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_disabled_rule_not_triggered() {
        let mut engine = ResponseEngine::new();
        // Disable all rules
        for rule in &mut engine.rules {
            rule.enabled = false;
        }
        let incident = make_incident(
            10,
            vec![ToolSource::Falco, ToolSource::Auditd],
            "Reverse shell critical",
        );
        let actions = engine.evaluate(&incident);
        assert!(actions.is_empty());
    }
}
