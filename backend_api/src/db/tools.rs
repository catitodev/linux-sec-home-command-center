// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Tool status persistence — CRUD operations for integrated security tools.

use chrono::{DateTime, Utc};
use shared::errors::{CommandCenterError, Result};
use shared::types::{ToolInfo, ToolStatus};

use super::Database;

impl Database {
    /// Inserts or updates a tool record in the database.
    pub fn upsert_tool(&self, tool: &ToolInfo, config: &serde_json::Value) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let status_str = serde_json::to_value(&tool.status)
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to serialize status: {e}"))
            })?
            .as_str()
            .unwrap_or("stopped")
            .to_string();

        let config_str = serde_json::to_string(config).map_err(|e| {
            CommandCenterError::Database(format!("failed to serialize config: {e}"))
        })?;

        conn.execute(
            "INSERT INTO tools (name, display_name, status, version, last_active, config)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(name) DO UPDATE SET
                display_name = excluded.display_name,
                status = excluded.status,
                version = excluded.version,
                last_active = excluded.last_active,
                config = excluded.config",
            rusqlite::params![
                tool.name,
                tool.display_name,
                status_str,
                tool.version,
                tool.last_active.map(|dt| dt.to_rfc3339()),
                config_str,
            ],
        )
        .map_err(|e| {
            CommandCenterError::Database(format!("failed to upsert tool: {e}"))
        })?;

        Ok(())
    }

    /// Retrieves a tool record by name.
    pub fn get_tool(&self, name: &str) -> Result<Option<ToolInfo>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT name, display_name, status, version, last_active FROM tools WHERE name = ?1",
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to prepare query: {e}"))
            })?;

        let result = stmt
            .query_row([name], |row| row_to_tool_info(row))
            .optional()
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query tool: {e}"))
            })?;

        Ok(result)
    }

    /// Lists all registered tools.
    pub fn list_tools(&self) -> Result<Vec<ToolInfo>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let mut stmt = conn
            .prepare("SELECT name, display_name, status, version, last_active FROM tools ORDER BY name")
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to prepare query: {e}"))
            })?;

        let tools = stmt
            .query_map([], |row| row_to_tool_info(row))
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query tools: {e}"))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(tools)
    }

    /// Updates the status of a tool.
    pub fn update_tool_status(&self, name: &str, status: ToolStatus) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let status_str = serde_json::to_value(&status)
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to serialize status: {e}"))
            })?
            .as_str()
            .unwrap_or("stopped")
            .to_string();

        let rows = conn
            .execute(
                "UPDATE tools SET status = ?1, last_active = ?2 WHERE name = ?3",
                rusqlite::params![status_str, Utc::now().to_rfc3339(), name],
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to update tool status: {e}"))
            })?;

        if rows == 0 {
            return Err(CommandCenterError::Database(format!(
                "tool not found: {name}"
            )));
        }

        Ok(())
    }
}

/// Converts a database row into a ToolInfo struct.
fn row_to_tool_info(row: &rusqlite::Row<'_>) -> rusqlite::Result<ToolInfo> {
    let name: String = row.get(0)?;
    let display_name: String = row.get(1)?;
    let status_str: String = row.get(2)?;
    let version: Option<String> = row.get(3)?;
    let last_active_str: Option<String> = row.get(4)?;

    let status: ToolStatus = serde_json::from_value(
        serde_json::Value::String(status_str),
    )
    .unwrap_or(ToolStatus::Stopped);

    let last_active: Option<DateTime<Utc>> = last_active_str
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    Ok(ToolInfo {
        name,
        display_name,
        status,
        version,
        last_active,
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
