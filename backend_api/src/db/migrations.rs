// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Schema migration system with version tracking.
//!
//! Migrations are applied sequentially. Each migration is a function that
//! receives a connection reference and applies schema changes. The current
//! version is stored in the `schema_version` table.

use rusqlite::Connection;
use shared::errors::{CommandCenterError, Result};
use tracing::info;

use super::schema;

/// Current schema version. Increment when adding new migrations.
const CURRENT_VERSION: u32 = 1;

/// A single migration step.
struct Migration {
    version: u32,
    description: &'static str,
    sql: &'static [&'static str],
}

/// All migrations in order. Each migration contains the SQL statements
/// needed to bring the schema from the previous version to this version.
static MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    description: "Initial schema — core tables and indexes",
    sql: &[
        schema::CREATE_SCHEMA_VERSION,
        schema::CREATE_SECURITY_EVENTS,
        schema::CREATE_EVENTS_TIMESTAMP_INDEX,
        schema::CREATE_EVENTS_SOURCE_INDEX,
        schema::CREATE_EVENTS_SEVERITY_INDEX,
        schema::CREATE_EVENTS_CORRELATION_INDEX,
        schema::CREATE_TOOLS,
        schema::CREATE_SCAN_RESULTS,
        schema::CREATE_QUARANTINED_FILES,
        schema::CREATE_RESPONSE_RULES,
        schema::CREATE_RESPONSE_ACTIONS,
        schema::CREATE_ACTIONS_RULE_INDEX,
        schema::CREATE_ACTIONS_INCIDENT_INDEX,
    ],
}];

/// Runs all pending migrations on the given connection.
pub fn run_migrations(conn: &Connection) -> Result<()> {
    let current = get_current_version(conn)?;

    if current >= CURRENT_VERSION {
        info!("Database schema is up to date (version {current})");
        return Ok(());
    }

    info!(
        "Running migrations from version {current} to {CURRENT_VERSION}"
    );

    for migration in MIGRATIONS.iter() {
        if migration.version > current {
            info!(
                "Applying migration v{}: {}",
                migration.version, migration.description
            );

            for statement in migration.sql {
                conn.execute_batch(statement).map_err(|e| {
                    CommandCenterError::Database(format!(
                        "migration v{} failed: {e}",
                        migration.version
                    ))
                })?;
            }

            // Record the applied migration version
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?1)",
                [migration.version],
            )
            .map_err(|e| {
                CommandCenterError::Database(format!(
                    "failed to record migration v{}: {e}",
                    migration.version
                ))
            })?;

            info!("Migration v{} applied successfully", migration.version);
        }
    }

    Ok(())
}

/// Gets the current schema version from the database.
/// Returns 0 if the schema_version table does not exist yet.
fn get_current_version(conn: &Connection) -> Result<u32> {
    // Check if schema_version table exists
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='schema_version'",
            [],
            |row| row.get(0),
        )
        .map_err(|e| {
            CommandCenterError::Database(format!("failed to check schema_version table: {e}"))
        })?;

    if !table_exists {
        return Ok(0);
    }

    // Get the highest applied version
    let version: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )
        .map_err(|e| {
            CommandCenterError::Database(format!("failed to read schema version: {e}"))
        })?;

    Ok(version)
}
