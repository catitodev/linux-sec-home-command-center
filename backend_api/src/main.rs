// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Backend API server for the Linux Security Home Command Center.
//!
//! This binary runs as an unprivileged system user and serves the REST API
//! over a Unix domain socket. It communicates with the Privileged Daemon
//! via D-Bus for operations requiring root access.

use std::path::PathBuf;

use shared::config::LoggingConfig;
use shared::logging::init_logging;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{error, info};

use backend_api::api::server::start_server;

/// Default Unix socket path for the Backend_API.
const DEFAULT_SOCKET_PATH: &str = "/run/security-command-center/api.sock";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging to journald
    let logging_config = LoggingConfig::default();
    init_logging(&logging_config)?;

    info!("Linux Security Home Command Center — Backend API starting");

    // Determine socket path (from environment or default)
    let socket_path = std::env::var("SCC_SOCKET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_SOCKET_PATH));

    // Ensure the socket directory exists
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| {
                error!(
                    path = %parent.display(),
                    error = %e,
                    "failed to create socket directory"
                );
                e
            })?;
            info!(path = %parent.display(), "created socket directory");
        }
    }

    // Set up graceful shutdown via SIGTERM
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("received SIGTERM, initiating graceful shutdown");
            }
            _ = sigint.recv() => {
                info!("received SIGINT, initiating graceful shutdown");
            }
        }

        let _ = shutdown_tx.send(true);
    });

    info!(socket_path = %socket_path.display(), "starting HTTP server");

    // Start the HTTP server on the Unix domain socket
    if let Err(e) = start_server(&socket_path, shutdown_rx).await {
        error!(error = %e, "HTTP server exited with error");
        return Err(e.to_string().into());
    }

    info!("Backend API shut down cleanly");
    Ok(())
}
