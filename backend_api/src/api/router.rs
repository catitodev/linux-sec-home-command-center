// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Basic HTTP request router for the Backend_API.
//!
//! Matches on method + path and returns JSON responses with proper content-type.
//! Placeholder routes are provided for initial health checking; full route
//! implementations will be added in subsequent tasks.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Method, Request, Response, StatusCode};

/// Route an incoming HTTP request to the appropriate handler.
///
/// Returns a JSON response with the correct content-type header.
pub async fn route_request(req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    match (method, path.as_str()) {
        (Method::GET, "/api/v1/health") => health_handler().await,
        _ => not_found_handler().await,
    }
}

/// Health check endpoint.
///
/// Returns `{"status": "ok"}` with HTTP 200.
async fn health_handler() -> Response<Full<Bytes>> {
    json_response(StatusCode::OK, r#"{"status":"ok"}"#)
}

/// Handler for unknown routes.
///
/// Returns `{"error": "not found"}` with HTTP 404.
async fn not_found_handler() -> Response<Full<Bytes>> {
    json_response(StatusCode::NOT_FOUND, r#"{"error":"not found"}"#)
}

/// Build a JSON response with the given status code and body.
fn json_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_endpoint_returns_ok() {
        let response = health_handler().await;
        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert_eq!(
            headers.get("content-type").unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn test_not_found_returns_404() {
        let response = not_found_handler().await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_json_response_has_content_type() {
        let response = json_response(StatusCode::OK, r#"{"test":true}"#);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }
}
