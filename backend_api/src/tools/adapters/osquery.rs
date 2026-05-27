// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! osquery adapter for the Linux Security Home Command Center.
//!
//! Provides system visibility through SQL-based queries against the osquery
//! virtual table interface. Supports pre-built queries for common security
//! data (processes, sockets, users, crontab, packages, kernel modules) and
//! validated custom queries with read-only enforcement and timeout protection.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use shared::distro::{adapter_for, DistroInfo};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Pre-built Queries ─────────────────────────────────────────────────────

/// Query to list all running processes with key attributes.
pub const QUERY_PROCESSES: &str =
    "SELECT pid, name, path, cmdline, uid, state FROM processes";

/// Query to list open network sockets with connection details.
pub const QUERY_SOCKETS: &str =
    "SELECT pid, protocol, local_address, local_port, remote_address, remote_port, state FROM process_open_sockets";

/// Query to list system users.
pub const QUERY_USERS: &str =
    "SELECT uid, gid, username, description, directory, shell FROM users";

/// Query to list crontab entries.
pub const QUERY_CRONTAB: &str =
    "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path FROM crontab";

/// Query to list installed packages (deb and rpm combined).
pub const QUERY_PACKAGES: &str =
    "SELECT name, version, source, arch FROM deb_packages UNION ALL SELECT name, version, source, arch FROM rpm_packages";

/// Query to list loaded kernel modules.
pub const QUERY_KERNEL_MODULES: &str =
    "SELECT name, size, status, address FROM kernel_modules";

// ─── Constants ─────────────────────────────────────────────────────────────

/// Maximum allowed query length in characters.
const MAX_QUERY_LENGTH: usize = 4096;

/// Maximum number of rows returned before truncation.
const MAX_RESULT_ROWS: usize = 10_000;

/// Default query execution timeout.
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Forbidden SQL keywords that indicate write operations.
const FORBIDDEN_KEYWORDS: &[&str] = &[
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "ATTACH",
];

// ─── Query Result ──────────────────────────────────────────────────────────

/// Result of an osquery query execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryResult {
    /// Rows returned by the query as JSON objects.
    pub rows: Vec<serde_json::Value>,
    /// Whether the result was truncated due to exceeding the row limit.
    pub truncated: bool,
    /// Total number of rows returned (before truncation if truncated, otherwise same as rows.len()).
    pub row_count: usize,
}

// ─── OsqueryClient ─────────────────────────────────────────────────────────

/// Client for executing validated queries against osquery.
///
/// Uses `osqueryi --json` for query execution with safety guarantees:
/// - Read-only query validation (no write operations allowed)
/// - Query length limits (max 4096 characters)
/// - Execution timeout (default 10 seconds)
/// - Result row limits (max 10,000 rows)
#[derive(Debug, Clone)]
pub struct OsqueryClient {
    /// Timeout for query execution.
    timeout: Duration,
}

impl OsqueryClient {
    /// Creates a new `OsqueryClient` with default settings.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_QUERY_TIMEOUT,
        }
    }

    /// Creates a new `OsqueryClient` with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Validates a SQL query for safe execution against osquery.
    ///
    /// # Validation Rules
    ///
    /// - Query length must not exceed 4096 characters.
    /// - Query must start with `SELECT` (case-insensitive, after trimming whitespace).
    /// - Query must NOT contain write keywords: INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH.
    /// - Query must NOT contain semicolons (prevents multi-statement injection).
    ///
    /// # Errors
    ///
    /// Returns `CommandCenterError::Internal` with a descriptive message if validation fails.
    pub fn validate_query(sql: &str) -> Result<()> {
        // Check length limit.
        if sql.len() > MAX_QUERY_LENGTH {
            return Err(CommandCenterError::Internal(format!(
                "query exceeds maximum length of {} characters (got {})",
                MAX_QUERY_LENGTH,
                sql.len()
            )));
        }

        let trimmed = sql.trim();

        // Must not be empty.
        if trimmed.is_empty() {
            return Err(CommandCenterError::Internal(
                "query must not be empty".to_owned(),
            ));
        }

        // Must start with SELECT.
        if !trimmed
            .get(..6)
            .map(|s| s.eq_ignore_ascii_case("SELECT"))
            .unwrap_or(false)
        {
            return Err(CommandCenterError::Internal(
                "query must start with SELECT (only read-only queries are allowed)".to_owned(),
            ));
        }

        // Must not contain semicolons (prevent multi-statement).
        if trimmed.contains(';') {
            return Err(CommandCenterError::Internal(
                "query must not contain semicolons (multi-statement queries are not allowed)"
                    .to_owned(),
            ));
        }

        // Must not contain forbidden write keywords.
        let upper = trimmed.to_uppercase();
        for keyword in FORBIDDEN_KEYWORDS {
            if contains_keyword_boundary(&upper, keyword) {
                return Err(CommandCenterError::Internal(format!(
                    "query contains forbidden keyword '{}' (only read-only queries are allowed)",
                    keyword
                )));
            }
        }

        Ok(())
    }

    /// Executes a raw SQL query against osquery and returns parsed JSON rows.
    ///
    /// This method does NOT validate the query — use [`validate_query`] first
    /// for user-provided queries, or use [`execute_with_timeout`] which validates
    /// automatically.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The `osqueryi` binary cannot be found or executed.
    /// - The query execution fails or returns invalid JSON.
    pub async fn execute_query(&self, sql: &str) -> Result<Vec<serde_json::Value>> {
        let mut cmd = SafeCommand::new("osqueryi");
        cmd.args(&["--json", sql])?;
        cmd.timeout(self.timeout);

        let output = cmd.execute().await?;

        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "osquery".to_owned(),
                reason: format!(
                    "osqueryi exited with code {:?}: {}",
                    output.exit_code,
                    output.stderr.trim()
                ),
            });
        }

        // Parse JSON output. osqueryi --json returns a JSON array of objects.
        let stdout = output.stdout.trim();
        if stdout.is_empty() || stdout == "[]" {
            return Ok(Vec::new());
        }

        let rows: Vec<serde_json::Value> =
            serde_json::from_str(stdout).map_err(|e| {
                CommandCenterError::ToolOperationFailed {
                    tool: "osquery".to_owned(),
                    reason: format!("failed to parse osqueryi JSON output: {}", e),
                }
            })?;

        Ok(rows)
    }

    /// Executes a validated query with timeout and row-limit enforcement.
    ///
    /// This is the primary entry point for executing user-provided custom queries.
    /// It validates the query, executes it with the configured timeout, and truncates
    /// results exceeding the 10,000 row limit.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails or query execution fails.
    pub async fn execute_with_timeout(
        &self,
        sql: &str,
        timeout: Duration,
    ) -> Result<QueryResult> {
        // Validate the query first.
        Self::validate_query(sql)?;

        debug!(query = %sql, timeout_secs = timeout.as_secs(), "Executing osquery query");

        // Create a client with the specified timeout for this execution.
        let client = OsqueryClient::with_timeout(timeout);
        let rows = client.execute_query(sql).await?;

        let total_rows = rows.len();
        let truncated = total_rows > MAX_RESULT_ROWS;
        let result_rows = if truncated {
            warn!(
                total_rows = total_rows,
                max_rows = MAX_RESULT_ROWS,
                "Query result truncated"
            );
            rows.into_iter().take(MAX_RESULT_ROWS).collect()
        } else {
            rows
        };

        let row_count = if truncated { total_rows } else { result_rows.len() };

        Ok(QueryResult {
            rows: result_rows,
            truncated,
            row_count,
        })
    }
}

impl Default for OsqueryClient {
    fn default() -> Self {
        Self::new()
    }
}

// ─── OsqueryAdapter ────────────────────────────────────────────────────────

/// Tool adapter for osquery, providing system visibility through SQL queries.
///
/// osquery exposes operating system information as virtual SQL tables, enabling
/// powerful queries for security monitoring: running processes, open sockets,
/// installed packages, kernel modules, and more.
pub struct OsqueryAdapter;

impl OsqueryAdapter {
    /// Creates a new `OsqueryAdapter`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for OsqueryAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolAdapter for OsqueryAdapter {
    fn name(&self) -> &str {
        "osquery"
    }

    fn display_name(&self) -> &str {
        "osquery"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Visibility
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let distro_adapter = adapter_for(distro.package_manager);
        let package_name = distro_adapter
            .map_tool_package("osquery")
            .ok_or_else(|| CommandCenterError::ToolNotAvailable {
                tool: "osquery".to_owned(),
            })?;

        info!(package = %package_name, distro = %distro.id, "Installing osquery");
        distro_adapter.install_package(&package_name)?;
        info!("osquery installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting osqueryd service");
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["start", "osqueryd"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "osquery".to_owned(),
                reason: format!("failed to start osqueryd: {}", output.stderr.trim()),
            });
        }

        info!("osqueryd service started");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping osqueryd service");
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["stop", "osqueryd"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "osquery".to_owned(),
                reason: format!("failed to stop osqueryd: {}", output.stderr.trim()),
            });
        }

        info!("osqueryd service stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("osqueryi");
        if cmd.arg("--version").is_err() {
            return HealthStatus::Unhealthy("failed to build health check command".to_owned());
        }
        cmd.timeout(Duration::from_secs(5));

        match cmd.execute().await {
            Ok(output) => {
                if output.exit_code == Some(0) {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Degraded(format!(
                        "osqueryi --version exited with code {:?}",
                        output.exit_code
                    ))
                }
            }
            Err(e) => HealthStatus::Unhealthy(format!("osqueryi not responsive: {}", e)),
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        // osquery is available for all supported distributions.
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // osquery package is approximately 30 MB.
        30 * 1024 * 1024
    }
}

// ─── Helper Functions ──────────────────────────────────────────────────────

/// Checks if a keyword appears as a whole word in the given uppercase string.
///
/// A keyword is considered a "whole word" if it is preceded by the start of the
/// string or a non-alphanumeric/underscore character, and followed by the end of
/// the string or a non-alphanumeric/underscore character.
fn contains_keyword_boundary(haystack: &str, keyword: &str) -> bool {
    let keyword_len = keyword.len();
    let haystack_bytes = haystack.as_bytes();

    let mut start = 0;
    while let Some(pos) = haystack[start..].find(keyword) {
        let abs_pos = start + pos;

        // Check preceding character boundary.
        let before_ok = if abs_pos == 0 {
            true
        } else {
            let ch = haystack_bytes[abs_pos - 1] as char;
            !ch.is_alphanumeric() && ch != '_'
        };

        // Check following character boundary.
        let after_pos = abs_pos + keyword_len;
        let after_ok = if after_pos >= haystack.len() {
            true
        } else {
            let ch = haystack_bytes[after_pos] as char;
            !ch.is_alphanumeric() && ch != '_'
        };

        if before_ok && after_ok {
            return true;
        }

        // Move past this occurrence.
        start = abs_pos + 1;
    }

    false
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Query Validation Tests ────────────────────────────────────────

    #[test]
    fn test_validate_query_accepts_valid_select() {
        assert!(OsqueryClient::validate_query("SELECT * FROM processes").is_ok());
        assert!(OsqueryClient::validate_query("select pid from processes").is_ok());
        assert!(OsqueryClient::validate_query("  SELECT name FROM users").is_ok());
        assert!(OsqueryClient::validate_query(QUERY_PROCESSES).is_ok());
        assert!(OsqueryClient::validate_query(QUERY_SOCKETS).is_ok());
        assert!(OsqueryClient::validate_query(QUERY_USERS).is_ok());
        assert!(OsqueryClient::validate_query(QUERY_CRONTAB).is_ok());
        assert!(OsqueryClient::validate_query(QUERY_PACKAGES).is_ok());
        assert!(OsqueryClient::validate_query(QUERY_KERNEL_MODULES).is_ok());
    }

    #[test]
    fn test_validate_query_rejects_empty() {
        assert!(OsqueryClient::validate_query("").is_err());
        assert!(OsqueryClient::validate_query("   ").is_err());
    }

    #[test]
    fn test_validate_query_rejects_non_select() {
        assert!(OsqueryClient::validate_query("INSERT INTO foo VALUES (1)").is_err());
        assert!(OsqueryClient::validate_query("UPDATE foo SET x=1").is_err());
        assert!(OsqueryClient::validate_query("DELETE FROM foo").is_err());
        assert!(OsqueryClient::validate_query("DROP TABLE foo").is_err());
        assert!(OsqueryClient::validate_query("ALTER TABLE foo ADD x INT").is_err());
        assert!(OsqueryClient::validate_query("CREATE TABLE foo (x INT)").is_err());
    }

    #[test]
    fn test_validate_query_rejects_semicolons() {
        assert!(OsqueryClient::validate_query("SELECT 1; DROP TABLE foo").is_err());
        assert!(OsqueryClient::validate_query("SELECT * FROM processes;").is_err());
    }

    #[test]
    fn test_validate_query_rejects_forbidden_keywords_in_body() {
        assert!(OsqueryClient::validate_query(
            "SELECT * FROM processes WHERE name IN (SELECT name FROM users) UNION ALL DELETE FROM foo"
        ).is_err());
    }

    #[test]
    fn test_validate_query_rejects_attach() {
        assert!(OsqueryClient::validate_query(
            "SELECT 1 FROM foo ATTACH DATABASE '/tmp/evil.db' AS evil"
        ).is_err());
    }

    #[test]
    fn test_validate_query_rejects_too_long() {
        let long_query = format!("SELECT {}", "x".repeat(MAX_QUERY_LENGTH));
        assert!(OsqueryClient::validate_query(&long_query).is_err());
    }

    #[test]
    fn test_validate_query_accepts_max_length() {
        // Exactly at the limit should be fine.
        let query = format!("SELECT {}", "x".repeat(MAX_QUERY_LENGTH - 7));
        assert!(OsqueryClient::validate_query(&query).is_ok());
    }

    #[test]
    fn test_validate_query_keyword_boundary_detection() {
        // "CREATED_AT" contains "CREATE" but should NOT be rejected
        // because it's not a word boundary match.
        assert!(OsqueryClient::validate_query(
            "SELECT created_at FROM processes"
        ).is_ok());

        // "UPDATED_AT" contains "UPDATE" but should NOT be rejected.
        assert!(OsqueryClient::validate_query(
            "SELECT updated_at FROM processes"
        ).is_ok());

        // "DELETED" contains "DELETE" but should NOT be rejected.
        assert!(OsqueryClient::validate_query(
            "SELECT deleted FROM processes"
        ).is_ok());

        // Actual "DELETE" as a word should be rejected.
        assert!(OsqueryClient::validate_query(
            "SELECT * FROM foo WHERE DELETE FROM bar"
        ).is_err());
    }

    // ─── Keyword Boundary Helper Tests ─────────────────────────────────

    #[test]
    fn test_contains_keyword_boundary_basic() {
        assert!(contains_keyword_boundary("DROP TABLE FOO", "DROP"));
        assert!(contains_keyword_boundary("SELECT * FROM FOO DROP", "DROP"));
        assert!(!contains_keyword_boundary("DROPDOWN MENU", "DROP"));
        assert!(!contains_keyword_boundary("BACKDROP", "DROP"));
    }

    #[test]
    fn test_contains_keyword_boundary_with_special_chars() {
        assert!(contains_keyword_boundary("(DELETE)", "DELETE"));
        assert!(contains_keyword_boundary("X,DELETE,Y", "DELETE"));
        assert!(contains_keyword_boundary(" INSERT ", "INSERT"));
    }

    // ─── QueryResult Tests ─────────────────────────────────────────────

    #[test]
    fn test_query_result_serialization() {
        let result = QueryResult {
            rows: vec![serde_json::json!({"pid": "1", "name": "init"})],
            truncated: false,
            row_count: 1,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: QueryResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn test_query_result_truncated() {
        let result = QueryResult {
            rows: vec![serde_json::json!({"x": 1})],
            truncated: true,
            row_count: 15000,
        };
        assert!(result.truncated);
        assert_eq!(result.row_count, 15000);
    }

    // ─── OsqueryAdapter Trait Tests ────────────────────────────────────

    #[test]
    fn test_adapter_name() {
        let adapter = OsqueryAdapter;
        assert_eq!(adapter.name(), "osquery");
    }

    #[test]
    fn test_adapter_display_name() {
        let adapter = OsqueryAdapter;
        assert_eq!(adapter.display_name(), "osquery");
    }

    #[test]
    fn test_adapter_category() {
        let adapter = OsqueryAdapter;
        assert_eq!(adapter.category(), ToolCategory::Visibility);
    }

    #[test]
    fn test_adapter_is_available_for_all_distros() {
        let adapter = OsqueryAdapter;

        let ubuntu = shared::distro::detect_distro_from_content(
            "ID=ubuntu\nVERSION_ID=\"22.04\"\nNAME=\"Ubuntu\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&ubuntu));

        let fedora = shared::distro::detect_distro_from_content(
            "ID=fedora\nVERSION_ID=39\nNAME=\"Fedora\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&fedora));

        let arch = shared::distro::detect_distro_from_content(
            "ID=arch\nNAME=\"Arch Linux\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&arch));
    }

    #[test]
    fn test_adapter_estimated_size() {
        let adapter = OsqueryAdapter;
        assert!(adapter.estimated_size_bytes() > 0);
    }

    // ─── OsqueryClient Tests ───────────────────────────────────────────

    #[test]
    fn test_client_default_timeout() {
        let client = OsqueryClient::new();
        assert_eq!(client.timeout, DEFAULT_QUERY_TIMEOUT);
    }

    #[test]
    fn test_client_custom_timeout() {
        let client = OsqueryClient::with_timeout(Duration::from_secs(30));
        assert_eq!(client.timeout, Duration::from_secs(30));
    }

    // ─── Pre-built Query Constants Tests ───────────────────────────────

    #[test]
    fn test_prebuilt_queries_are_valid() {
        let queries = [
            QUERY_PROCESSES,
            QUERY_SOCKETS,
            QUERY_USERS,
            QUERY_CRONTAB,
            QUERY_PACKAGES,
            QUERY_KERNEL_MODULES,
        ];

        for query in &queries {
            assert!(
                OsqueryClient::validate_query(query).is_ok(),
                "Pre-built query failed validation: {}",
                query
            );
        }
    }

    #[test]
    fn test_prebuilt_queries_start_with_select() {
        let queries = [
            QUERY_PROCESSES,
            QUERY_SOCKETS,
            QUERY_USERS,
            QUERY_CRONTAB,
            QUERY_PACKAGES,
            QUERY_KERNEL_MODULES,
        ];

        for query in &queries {
            assert!(
                query.trim().to_uppercase().starts_with("SELECT"),
                "Pre-built query does not start with SELECT: {}",
                query
            );
        }
    }
}
