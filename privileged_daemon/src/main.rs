// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Privileged Daemon for the Linux Security Home Command Center.
//!
//! This binary runs as a systemd service with root privileges. It registers
//! a D-Bus service and executes only operations defined in the whitelist
//! configuration file.
//!
//! At startup, the daemon performs self-integrity verification by comparing
//! SHA256 hashes of Command Center binaries against reference values stored
//! in a root-owned immutable file. If verification fails, the daemon refuses
//! to start the Backend_API and emits a critical tamper alert.

use std::path::PathBuf;
use std::process;

use shared::config::LoggingConfig;
use shared::logging::init_logging;
use tracing::{error, info};

use privileged_daemon::integrity::{emit_tamper_alert, IntegrityResult, IntegrityVerifier};
use privileged_daemon::integrity_hashes::DEFAULT_REFERENCE_HASHES_PATH;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging to journald
    let logging_config = LoggingConfig::default();
    init_logging(&logging_config)?;

    info!("Linux Security Home Command Center — Privileged Daemon starting");

    // ─── Self-Integrity Verification ───────────────────────────────────────
    info!("performing self-integrity verification");

    let reference_hashes_path = PathBuf::from(DEFAULT_REFERENCE_HASHES_PATH);
    let aide_db_path = PathBuf::from("/var/lib/aide/aide.db");

    // Only perform integrity verification if the reference hash file exists.
    // On first install, the hash file won't exist yet.
    if reference_hashes_path.exists() {
        let mut verifier = IntegrityVerifier::new(
            reference_hashes_path.clone(),
            aide_db_path,
        );

        match verifier.verify_binaries().await {
            Ok(IntegrityResult::Valid) => {
                info!("binary integrity verification passed");
            }
            Ok(IntegrityResult::BinaryTampered { path, expected, actual }) => {
                let details = format!(
                    "Binary '{}' has been tampered with. \
                     Expected SHA256: {}, Actual SHA256: {}",
                    path.display(),
                    expected,
                    actual
                );
                error!("{}", details);
                emit_tamper_alert(&details);
                error!("refusing to start Backend_API — integrity verification failed");
                process::exit(1);
            }
            Ok(IntegrityResult::Timeout) => {
                let details = "Integrity verification timed out (30s limit exceeded)";
                error!("{}", details);
                emit_tamper_alert(details);
                error!("refusing to start Backend_API — verification timeout");
                process::exit(1);
            }
            Ok(IntegrityResult::ConfigTampered { path }) => {
                let details = format!(
                    "Configuration file '{}' has been tampered with",
                    path.display()
                );
                error!("{}", details);
                emit_tamper_alert(&details);
                error!("refusing to start Backend_API — config integrity failed");
                process::exit(1);
            }
            Err(e) => {
                let details = format!("Integrity verification error: {}", e);
                error!("{}", details);
                emit_tamper_alert(&details);
                error!("refusing to start Backend_API — verification error");
                process::exit(1);
            }
        }

        // Verify configuration files
        let whitelist_path = PathBuf::from("/etc/security-command-center/whitelist.toml");
        if whitelist_path.exists() {
            if let Err(e) = verifier.verify_config_file(&whitelist_path) {
                let details = format!("Config verification failed: {}", e);
                error!("{}", details);
                emit_tamper_alert(&details);
                error!("refusing to start — configuration integrity check failed");
                process::exit(1);
            }
        }
    } else {
        info!(
            path = %reference_hashes_path.display(),
            "reference hash file not found — skipping integrity verification \
             (expected on first install)"
        );
    }

    // ─── Normal Startup ────────────────────────────────────────────────────
    info!("integrity verification complete — proceeding with startup");
    info!("Registering D-Bus service");

    Ok(())
}
