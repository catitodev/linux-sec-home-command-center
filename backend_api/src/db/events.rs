// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! SecurityEvent CRUD operations — persistence and querying with pagination.

use chrono::{DateTime, Utc};
use shared::errors::{CommandCenterError, Result};
use shared::types::{NormalizedEvent, Severity, ToolSource};
use uuid::Uuid;

use super::Database;

/// Filters for querying security events.
#[derive(Debug, Clone, Default)]
pub struct EventFilters {
    /// Filter by source tool.
    pub source: Option<ToolSource>,
    /// Filter by minimum severity.
    pub min_severity: Option<Severity>,
    /// Filter events after this timestamp.
    pub after: Option<DateTime<Utc>>,
    /// Filter events before this timestamp.
    pub before: Option<DateTime<Utc>>,
    /// Filter by acknowledged status.
    pub acknowledged: Option<bool>,
    /// Filter by correlation ID.
    pub correlation_id: Option<Uuid>,
}

impl Database {
    /// Inserts a normalized security event into the database.
    pub fn insert_event(&self, event: &NormalizedEvent) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let entities_json = serde_json::to_string(&event.entities).map_err(|e| {
            CommandCenterError::Database(format!("failed to serialize entities: {e}"))
        })?;

        let source_str = serde_json::to_value(&event.source)
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to serialize source: {e}"))
            })?
            .as_str()
            .unwrap_or("system")
            .to_string();

        let severity_str = serde_json::to_value(&event.severity)
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to serialize severity: {e}"))
            })?
            .as_str()
            .unwrap_or("info")
            .to_string();

        conn.execute(
            "INSERT INTO security_events (id, timestamp, source_tool, severity, summary, details, entities, acknowledged, correlation_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                event.id.to_string(),
                event.timestamp.to_rfc3339(),
                source_str,
                severity_str,
                event.summary,
                event.details,
                entities_json,
                event.acknowledged as i32,
                event.correlation_id.map(|id| id.to_string()),
            ],
        )
        .map_err(|e| {
            CommandCenterError::Database(format!("failed to insert event: {e}"))
        })?;

        Ok(())
    }

    /// Lists security events with optional filters and pagination.
    ///
    /// Returns events ordered by timestamp descending (newest first).
    pub fn list_events(
        &self,
        filters: &EventFilters,
        page: u32,
        per_page: u32,
    ) -> Result<Vec<NormalizedEvent>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let (where_clause, params) = build_filter_clause(filters)?;
        let offset = page.saturating_sub(1) * per_page;

        let sql = format!(
            "SELECT id, timestamp, source_tool, severity, summary, details, entities, acknowledged, correlation_id
             FROM security_events
             {where_clause}
             ORDER BY timestamp DESC
             LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2,
        );

        let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> =
            params.into_iter().map(|p| p as Box<dyn rusqlite::types::ToSql>).collect();
        all_params.push(Box::new(per_page));
        all_params.push(Box::new(offset));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            all_params.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql).map_err(|e| {
            CommandCenterError::Database(format!("failed to prepare query: {e}"))
        })?;

        let events = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok(row_to_event(row))
            })
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query events: {e}"))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|r| r.ok())
            .collect();

        Ok(events)
    }

    /// Counts events matching the given filters.
    pub fn count_events(&self, filters: &EventFilters) -> Result<u64> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let (where_clause, params) = build_filter_clause(filters)?;

        let sql = format!(
            "SELECT COUNT(*) FROM security_events {where_clause}"
        );

        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref() as &dyn rusqlite::types::ToSql).collect();

        let count: u64 = conn
            .query_row(&sql, param_refs.as_slice(), |row| row.get(0))
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to count events: {e}"))
            })?;

        Ok(count)
    }

    /// Marks an event as acknowledged.
    pub fn acknowledge_event(&self, event_id: &Uuid) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let rows = conn
            .execute(
                "UPDATE security_events SET acknowledged = 1 WHERE id = ?1",
                [event_id.to_string()],
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to acknowledge event: {e}"))
            })?;

        if rows == 0 {
            return Err(CommandCenterError::Database(format!(
                "event not found: {event_id}"
            )));
        }

        Ok(())
    }
}

/// Builds a WHERE clause and parameter list from the given filters.
fn build_filter_clause(
    filters: &EventFilters,
) -> Result<(String, Vec<Box<dyn rusqlite::types::ToSql>>)> {
    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    if let Some(ref source) = filters.source {
        let source_str = serde_json::to_value(source)
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to serialize source filter: {e}"))
            })?
            .as_str()
            .unwrap_or("system")
            .to_string();
        conditions.push(format!("source_tool = ?{idx}"));
        params.push(Box::new(source_str));
        idx += 1;
    }

    if let Some(ref severity) = filters.min_severity {
        let severity_str = serde_json::to_value(severity)
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to serialize severity filter: {e}"))
            })?
            .as_str()
            .unwrap_or("info")
            .to_string();
        // Use severity ordering via CASE expression
        conditions.push(format!(
            "CASE severity \
             WHEN 'critical' THEN 5 \
             WHEN 'high' THEN 4 \
             WHEN 'medium' THEN 3 \
             WHEN 'low' THEN 2 \
             WHEN 'info' THEN 1 \
             ELSE 0 END >= \
             CASE ?{idx} \
             WHEN 'critical' THEN 5 \
             WHEN 'high' THEN 4 \
             WHEN 'medium' THEN 3 \
             WHEN 'low' THEN 2 \
             WHEN 'info' THEN 1 \
             ELSE 0 END"
        ));
        params.push(Box::new(severity_str));
        idx += 1;
    }

    if let Some(ref after) = filters.after {
        conditions.push(format!("timestamp >= ?{idx}"));
        params.push(Box::new(after.to_rfc3339()));
        idx += 1;
    }

    if let Some(ref before) = filters.before {
        conditions.push(format!("timestamp <= ?{idx}"));
        params.push(Box::new(before.to_rfc3339()));
        idx += 1;
    }

    if let Some(acknowledged) = filters.acknowledged {
        conditions.push(format!("acknowledged = ?{idx}"));
        params.push(Box::new(acknowledged as i32));
        idx += 1;
    }

    if let Some(ref correlation_id) = filters.correlation_id {
        conditions.push(format!("correlation_id = ?{idx}"));
        params.push(Box::new(correlation_id.to_string()));
        // idx is not used after this, but keep for consistency
        let _ = idx + 1;
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    Ok((where_clause, params))
}

/// Converts a database row into a NormalizedEvent.
fn row_to_event(row: &rusqlite::Row<'_>) -> std::result::Result<NormalizedEvent, rusqlite::Error> {
    let id_str: String = row.get(0)?;
    let timestamp_str: String = row.get(1)?;
    let source_str: String = row.get(2)?;
    let severity_str: String = row.get(3)?;
    let summary: String = row.get(4)?;
    let details: Option<String> = row.get(5)?;
    let entities_json: String = row.get(6)?;
    let acknowledged_int: i32 = row.get(7)?;
    let correlation_id_str: Option<String> = row.get(8)?;

    let id = Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4());

    let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let source: ToolSource = serde_json::from_value(
        serde_json::Value::String(source_str),
    )
    .unwrap_or(ToolSource::System);

    let severity: Severity = serde_json::from_value(
        serde_json::Value::String(severity_str),
    )
    .unwrap_or(Severity::Info);

    let entities = serde_json::from_str(&entities_json).unwrap_or_default();

    let correlation_id =
        correlation_id_str.and_then(|s| Uuid::parse_str(&s).ok());

    Ok(NormalizedEvent {
        id,
        timestamp,
        source,
        severity,
        summary,
        details,
        entities,
        acknowledged: acknowledged_int != 0,
        correlation_id,
    })
}
