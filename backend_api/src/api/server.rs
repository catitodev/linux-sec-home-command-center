// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! HTTP server bound to a Unix domain socket.
//!
//! Serves the Backend_API exclusively over a Unix socket with no TCP port exposed.
//! Applies Content-Security-Policy and other security headers to all responses.

use std::path::Path;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::UnixListener;
use tracing::{error, info, warn};

use super::router::route_request;

/// Content-Security-Policy header value.
/// No inline scripts permitted (Requirement 2.7).
const CSP_HEADER: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";

/// Start the HTTP server on the given Unix domain socket path.
///
/// This function binds to the socket, sets restrictive permissions (0660),
/// and serves HTTP/1.1 requests until the provided shutdown signal fires.
///
/// # Errors
///
/// Returns an error if the socket cannot be bound or permissions cannot be set.
pub async fn start_server(
    socket_path: &Path,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Remove stale socket file if it exists
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Set socket permissions to 0660 (owner + group read/write only)
    set_socket_permissions(socket_path)?;

    info!(
        socket_path = %socket_path.display(),
        "HTTP server listening on Unix domain socket"
    );

    let shutdown = Arc::new(shutdown);

    loop {
        let shutdown_clone = Arc::clone(&shutdown);

        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        let io = hyper_util::rt::TokioIo::new(stream);

                        tokio::task::spawn(async move {
                            let service = service_fn(|req| handle_request(req));

                            if let Err(err) = http1::Builder::new()
                                .serve_connection(io, service)
                                .await
                            {
                                // Connection errors are common (client disconnect) — log at warn
                                warn!(error = %err, "error serving connection");
                            }
                        });
                    }
                    Err(err) => {
                        error!(error = %err, "failed to accept connection");
                    }
                }
            }
            _ = wait_for_shutdown(shutdown_clone) => {
                info!("shutdown signal received, stopping HTTP server");
                break;
            }
        }
    }

    // Clean up socket file on shutdown
    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    Ok(())
}

/// Handle an incoming HTTP request by routing it and applying security headers.
async fn handle_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response = route_request(req).await;

    // Apply security headers to all responses
    let response = apply_security_headers(response);

    Ok(response)
}

/// Apply security headers to a response.
fn apply_security_headers(mut response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    let headers = response.headers_mut();

    headers.insert(
        "content-security-policy",
        CSP_HEADER.parse().expect("valid CSP header value"),
    );
    headers.insert(
        "x-content-type-options",
        "nosniff".parse().expect("valid header value"),
    );
    headers.insert(
        "x-frame-options",
        "DENY".parse().expect("valid header value"),
    );

    response
}

/// Set Unix socket file permissions to 0660 (owner + group read/write).
fn set_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o660);
    std::fs::set_permissions(path, permissions)?;

    Ok(())
}

/// Wait for the shutdown signal to fire.
async fn wait_for_shutdown(shutdown: Arc<tokio::sync::watch::Receiver<bool>>) {
    let mut rx = shutdown.as_ref().clone();
    // Wait until the value becomes true
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            // Sender dropped — treat as shutdown
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csp_header_no_inline_scripts() {
        // Verify CSP does not allow 'unsafe-inline' for scripts
        assert!(CSP_HEADER.contains("script-src 'self'"));
        assert!(!CSP_HEADER.contains("script-src 'self' 'unsafe-inline'"));
    }

    #[test]
    fn test_apply_security_headers() {
        let response = Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("test")))
            .unwrap();

        let response = apply_security_headers(response);
        let headers = response.headers();

        assert!(headers.contains_key("content-security-policy"));
        assert!(headers.contains_key("x-content-type-options"));
        assert!(headers.contains_key("x-frame-options"));

        assert_eq!(
            headers.get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    }
}
