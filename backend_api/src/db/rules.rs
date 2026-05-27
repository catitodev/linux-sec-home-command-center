// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! ResponseRule and ResponseAction CRUD operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared::errors::{CommandCenterError, Result};
use uuid::Uuid;

use super::Database;

/// A response rule defining automated actions for threat conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRule {
    pub id: Uuid,
    pub name: String,
    pub condition_expression: String,
    pub actions: serde_json::Value,
    pub enabled: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub last_triggered: Option<DateTime<Utc>>,
    pub trigger_count: u32,
}

/// A recorded response action execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub incident_id: Option<Uuid>,
    pub executed_at: DateTime<Utc>,
    pub action_type: String,
    pub parameters: serde_json::Value,
    pub result: String,
    pub failure_reason: Option<String>,
    pub reversal_procedure: Option<serde_json::Value>,
    pub reversal_expires_at: Option<DateTime<Utc>>,
}

impl Database {
    /// Inserts a new response rule.
    pub fn insert_rule(&self, rule: &ResponseRule) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let actions_str = serde_json::to_string(&rule.actions).map_err(|e| {
            CommandCenterError::Database(format!("failed to serialize actions: {e}"))
        })?;

        conn.execute(
            "INSERT INTO response_rules (id, name, condition_expression, actions, enabled, priority, created_at, last_triggered, trigger_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                rule.id.to_string(),
                rule.name,
                rule.condition_expression,
                actions_str,
                rule.enabled as i32,
                rule.priority,
                rule.created_at.to_rfc3339(),
                rule.last_triggered.map(|dt| dt.to_rfc3339()),
                rule.trigger_count,
            ],
        )
        .map_err(|e| {
            CommandCenterError::Database(format!("failed to insert rule: {e}"))
        })?;

        Ok(())
    }

    /// Updates an existing response rule.
    pub fn update_rule(&self, rule: &ResponseRule) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let actions_str = serde_json::to_string(&rule.actions).map_err(|e| {
            CommandCenterError::Database(format!("failed to serialize actions: {e}"))
        })?;

        let rows = conn
            .execute(
                "UPDATE response_rules SET name = ?1, condition_expression = ?2, actions = ?3, enabled = ?4, priority = ?5, last_triggered = ?6, trigger_count = ?7 WHERE id = ?8",
                rusqlite::params![
                    rule.name,
                    rule.condition_expression,
                    actions_str,
                    rule.enabled as i32,
                    rule.priority,
                    rule.last_triggered.map(|dt| dt.to_rfc3339()),
                    rule.trigger_count,
                    rule.id.to_string(),
                ],
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to update rule: {e}"))
            })?;

        if rows == 0 {
            return Err(CommandCenterError::Database(format!(
                "rule not found: {}",
                rule.id
            )));
        }

        Ok(())
    }

    /// Deletes a response rule by ID.
    pub fn delete_rule(&self, id: &Uuid) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let rows = conn
            .execute(
                "DELETE FROM response_rules WHERE id = ?1",
                [id.to_string()],
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to delete rule: {e}"))
            })?;

        if rows == 0 {
            return Err(CommandCenterError::Database(format!(
                "rule not found: {id}"
            )));
        }

        Ok(())
    }

    /// Retrieves a response rule by ID.
    pub fn get_rule(&self, id: &Uuid) -> Result<Option<ResponseRule>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, condition_expression, actions, enabled, priority, created_at, last_triggered, trigger_count
                 FROM response_rules WHERE id = ?1",
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to prepare query: {e}"))
            })?;

        let result = stmt
            .query_row([id.to_string()], |row| row_to_rule(row))
            .optional()
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query rule: {e}"))
            })?;

        Ok(result)
    }

    /// Lists all response rules ordered by priority (highest first).
    pub fn list_rules(&self) -> Result<Vec<ResponseRule>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, condition_expression, actions, enabled, priority, created_at, last_triggered, trigger_count
                 FROM response_rules
                 ORDER BY priority DESC, created_at ASC",
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to prepare query: {e}"))
            })?;

        let rules = stmt
            .query_map([], |row| row_to_rule(row))
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query rules: {e}"))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rules)
    }

    /// Lists only enabled response rules ordered by priority.
    pub fn list_enabled_rules(&self) -> Result<Vec<ResponseRule>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, condition_expression, actions, enabled, priority, created_at, last_triggered, trigger_count
                 FROM response_rules
                 WHERE enabled = 1
                 ORDER BY priority DESC, created_at ASC",
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to prepare query: {e}"))
            })?;

        let rules = stmt
            .query_map([], |row| row_to_rule(row))
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query enabled rules: {e}"))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rules)
    }

    /// Inserts a response action record.
    pub fn insert_response_action(&self, action: &ResponseAction) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let params_str = serde_json::to_string(&action.parameters).map_err(|e| {
            CommandCenterError::Database(format!("failed to serialize parameters: {e}"))
        })?;

        let reversal_str = action
            .reversal_procedure
            .as_ref()
            .map(|v| serde_json::to_string(v))
            .transpose()
            .map_err(|e| {
                CommandCenterError::Database(format!(
                    "failed to serialize reversal_procedure: {e}"
                ))
            })?;

        conn.execute(
            "INSERT INTO response_actions (id, rule_id, incident_id, executed_at, action_type, parameters, result, failure_reason, reversal_procedure, reversal_expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                action.id.to_string(),
                action.rule_id.to_string(),
                action.incident_id.map(|id| id.to_string()),
                action.executed_at.to_rfc3339(),
                action.action_type,
                params_str,
                action.result,
                action.failure_reason,
                reversal_str,
                action.reversal_expires_at.map(|dt| dt.to_rfc3339()),
            ],
        )
        .map_err(|e| {
            CommandCenterError::Database(format!("failed to insert response action: {e}"))
        })?;

        Ok(())
    }

    /// Lists response actions for a given rule, ordered by execution time (newest first).
    pub fn list_actions_for_rule(&self, rule_id: &Uuid) -> Result<Vec<ResponseAction>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT id, rule_id, incident_id, executed_at, action_type, parameters, result, failure_reason, reversal_procedure, reversal_expires_at
                 FROM response_actions
                 WHERE rule_id = ?1
                 ORDER BY executed_at DESC",
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to prepare query: {e}"))
            })?;

        let actions = stmt
            .query_map([rule_id.to_string()], |row| row_to_action(row))
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query actions: {e}"))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(actions)
    }

    /// Lists all response actions ordered by execution time (newest first), with pagination.
    pub fn list_response_actions(&self, page: u32, per_page: u32) -> Result<Vec<ResponseAction>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let offset = page.saturating_sub(1) * per_page;

        let mut stmt = conn
            .prepare(
                "SELECT id, rule_id, incident_id, executed_at, action_type, parameters, result, failure_reason, reversal_procedure, reversal_expires_at
                 FROM response_actions
                 ORDER BY executed_at DESC
                 LIMIT ?1 OFFSET ?2",
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to prepare query: {e}"))
            })?;

        let actions = stmt
            .query_map(rusqlite::params![per_page, offset], |row| {
                row_to_action(row)
            })
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query actions: {e}"))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(actions)
    }
}

/// Converts a database row into a ResponseRule.
fn row_to_rule(row: &rusqlite::Row<'_>) -> rusqlite::Result<ResponseRule> {
    let id_str: String = row.get(0)?;
    let name: String = row.get(1)?;
    let condition_expression: String = row.get(2)?;
    let actions_str: String = row.get(3)?;
    let enabled_int: i32 = row.get(4)?;
    let priority: i32 = row.get(5)?;
    let created_at_str: String = row.get(6)?;
    let last_triggered_str: Option<String> = row.get(7)?;
    let trigger_count: u32 = row.get(8)?;

    let id = Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4());

    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let last_triggered = last_triggered_str
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let actions: serde_json::Value =
        serde_json::from_str(&actions_str).unwrap_or(serde_json::Value::Array(Default::default()));

    Ok(ResponseRule {
        id,
        name,
        condition_expression,
        actions,
        enabled: enabled_int != 0,
        priority,
        created_at,
        last_triggered,
        trigger_count,
    })
}

/// Converts a database row into a ResponseAction.
fn row_to_action(row: &rusqlite::Row<'_>) -> rusqlite::Result<ResponseAction> {
    let id_str: String = row.get(0)?;
    let rule_id_str: String = row.get(1)?;
    let incident_id_str: Option<String> = row.get(2)?;
    let executed_at_str: String = row.get(3)?;
    let action_type: String = row.get(4)?;
    let parameters_str: String = row.get(5)?;
    let result: String = row.get(6)?;
    let failure_reason: Option<String> = row.get(7)?;
    let reversal_str: Option<String> = row.get(8)?;
    let reversal_expires_str: Option<String> = row.get(9)?;

    let id = Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4());
    let rule_id = Uuid::parse_str(&rule_id_str).unwrap_or_else(|_| Uuid::new_v4());
    let incident_id = incident_id_str.and_then(|s| Uuid::parse_str(&s).ok());

    let executed_at = DateTime::parse_from_rfc3339(&executed_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let parameters: serde_json::Value = serde_json::from_str(&parameters_str)
        .unwrap_or(serde_json::Value::Object(Default::default()));

    let reversal_procedure: Option<serde_json::Value> =
        reversal_str.and_then(|s| serde_json::from_str(&s).ok());

    let reversal_expires_at = reversal_expires_str
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    Ok(ResponseAction {
        id,
        rule_id,
        incident_id,
        executed_at,
        action_type,
        parameters,
        result,
        failure_reason,
        reversal_procedure,
        reversal_expires_at,
    })
}

/// Extension trait for optional query results.
trait OptionalExt<T> {
    fn optional(self) -> std::result::Result<Option<T>, rusqlite::Error>;
}

impl<T> OptionalExt<T> for rusqlite::Result<T> {
    fn optional(self) -> std::result::Result<Option<T>, rusqlite::Error> {
        match self {
            Ok(val) => Ok(Some(val)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
