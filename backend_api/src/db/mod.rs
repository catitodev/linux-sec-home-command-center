// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Database module — SQLCipher encrypted storage layer.
//!
//! Provides connection management, schema migrations, and CRUD operations
//! for all core data models used by the Backend API.

pub mod events;
pub mod migrations;
pub mod rules;
pub mod scans;
pub mod schema;
pub mod tools;

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use shared::errors::{CommandCenterError, Result};
use tracing::info;

/// Thread-safe database handle wrapping an encrypted SQLCipher connection.
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    /// Opens or creates an encrypted SQLCipher database at the given path.
    ///
    /// The `key` parameter is used as the encryption passphrase via `PRAGMA key`.
    /// If the database file does not exist, it will be created and encrypted.
    pub fn new(path: &Path, key: &str) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| {
            CommandCenterError::Database(format!("failed to open database: {e}"))
        })?;

        // Set the encryption key for SQLCipher
        conn.execute_batch(&format!("PRAGMA key = '{key}';"))
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to set encryption key: {e}"))
            })?;

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode = WAL;")
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to set WAL mode: {e}"))
            })?;

        // Enable foreign key enforcement
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| {
                CommandCenterError::Database(format!("failed to enable foreign keys: {e}"))
            })?;

        info!("Database opened at {}", path.display());

        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };

        // Run pending migrations
        db.migrate()?;

        Ok(db)
    }

    /// Runs all pending schema migrations.
    pub fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| {
            CommandCenterError::Database(format!("failed to acquire database lock: {e}"))
        })?;
        migrations::run_migrations(&conn)
    }

    /// Returns a reference to the inner connection mutex for direct access.
    ///
    /// Callers must lock the mutex before using the connection.
    pub(crate) fn connection(&self) -> &Arc<Mutex<Connection>> {
        &self.conn
    }
}
