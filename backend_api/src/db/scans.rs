// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! ScanResult persistence — CRUD operations for security scan records.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared::errors::{CommandCenterError, Result};
use uuid::Uuid;

use super::Database;

/// Status of a scan operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Running,
    Completed,
    Failed,
}

/// Type of scan performed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Full,
    Home,
    Custom,
    Rootkit,
}

/// A scan result record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub scan_type: ScanType,
    pub status: ScanStatus,
    pub scope: serde_json::Value,
    pub findings_count: u32,
    pub findings: serde_json::Value,
}

impl Database {
    /// Inserts a new scan result record.
    pub fn insert_scan_result(&self, scan: &ScanResult) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let scan_type_str = serde_json::to_value(&scan.scan_type)
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to serialize scan_type: {e}"))
            })?
            .as_str()
            .unwrap_or("custom")
            .to_string();

        let status_str = serde_json::to_value(&scan.status)
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to serialize status: {e}"))
            })?
            .as_str()
            .unwrap_or("running")
            .to_string();

        let scope_str = serde_json::to_string(&scan.scope).map_err(|e| {
            CommandCenterError::Database(format!("failed to serialize scope: {e}"))
        })?;

        let findings_str = serde_json::to_string(&scan.findings).map_err(|e| {
            CommandCenterError::Database(format!("failed to serialize findings: {e}"))
        })?;

        conn.execute(
            "INSERT INTO scan_results (id, started_at, completed_at, scan_type, status, scope, findings_count, findings)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                scan.id.to_string(),
                scan.started_at.to_rfc3339(),
                scan.completed_at.map(|dt| dt.to_rfc3339()),
                scan_type_str,
                status_str,
                scope_str,
                scan.findings_count,
                findings_str,
            ],
        )
        .map_err(|e| {
            CommandCenterError::Database(format!("failed to insert scan result: {e}"))
        })?;

        Ok(())
    }

    /// Updates a scan result (e.g., when scan completes).
    pub fn update_scan_result(
        &self,
        id: &Uuid,
        status: ScanStatus,
        completed_at: Option<DateTime<Utc>>,
        findings_count: u32,
        findings: &serde_json::Value,
    ) -> Result<()> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let status_str = serde_json::to_value(&status)
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to serialize status: {e}"))
            })?
            .as_str()
            .unwrap_or("running")
            .to_string();

        let findings_str = serde_json::to_string(findings).map_err(|e| {
            CommandCenterError::Database(format!("failed to serialize findings: {e}"))
        })?;

        let rows = conn
            .execute(
                "UPDATE scan_results SET status = ?1, completed_at = ?2, findings_count = ?3, findings = ?4 WHERE id = ?5",
                rusqlite::params![
                    status_str,
                    completed_at.map(|dt| dt.to_rfc3339()),
                    findings_count,
                    findings_str,
                    id.to_string(),
                ],
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to update scan result: {e}"))
            })?;

        if rows == 0 {
            return Err(CommandCenterError::Database(format!(
                "scan result not found: {id}"
            )));
        }

        Ok(())
    }

    /// Retrieves a scan result by ID.
    pub fn get_scan_result(&self, id: &Uuid) -> Result<Option<ScanResult>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT id, started_at, completed_at, scan_type, status, scope, findings_count, findings
                 FROM scan_results WHERE id = ?1",
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to prepare query: {e}"))
            })?;

        let result = stmt
            .query_row([id.to_string()], |row| row_to_scan_result(row))
            .optional()
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query scan result: {e}"))
            })?;

        Ok(result)
    }

    /// Lists scan results ordered by start time (newest first), with pagination.
    pub fn list_scan_results(&self, page: u32, per_page: u32) -> Result<Vec<ScanResult>> {
        let conn = self.connection().lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire lock: {e}"))
        })?;

        let offset = page.saturating_sub(1) * per_page;

        let mut stmt = conn
            .prepare(
                "SELECT id, started_at, completed_at, scan_type, status, scope, findings_count, findings
                 FROM scan_results
                 ORDER BY started_at DESC
                 LIMIT ?1 OFFSET ?2",
            )
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to prepare query: {e}"))
            })?;

        let results = stmt
            .query_map(rusqlite::params![per_page, offset], |row| {
                row_to_scan_result(row)
            })
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to query scan results: {e}"))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(results)
    }
}

/// Converts a database row into a ScanResult.
fn row_to_scan_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanResult> {
    let id_str: String = row.get(0)?;
    let started_at_str: String = row.get(1)?;
    let completed_at_str: Option<String> = row.get(2)?;
    let scan_type_str: String = row.get(3)?;
    let status_str: String = row.get(4)?;
    let scope_str: String = row.get(5)?;
    let findings_count: u32 = row.get(6)?;
    let findings_str: String = row.get(7)?;

    let id = Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4());

    let started_at = DateTime::parse_from_rfc3339(&started_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    let completed_at = completed_at_str
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let scan_type: ScanType =
        serde_json::from_value(serde_json::Value::String(scan_type_str))
            .unwrap_or(ScanType::Custom);

    let status: ScanStatus =
        serde_json::from_value(serde_json::Value::String(status_str))
            .unwrap_or(ScanStatus::Running);

    let scope: serde_json::Value =
        serde_json::from_str(&scope_str).unwrap_or(serde_json::Value::Object(Default::default()));

    let findings: serde_json::Value = serde_json::from_str(&findings_str)
        .unwrap_or(serde_json::Value::Array(Default::default()));

    Ok(ScanResult {
        id,
        started_at,
        completed_at,
        scan_type,
        status,
        scope,
        findings_count,
        findings,
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
