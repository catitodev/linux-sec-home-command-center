// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Authentication middleware for the Backend_API.
//!
//! Extracts session tokens from the `Authorization: Bearer <token>` header
//! and validates them against the SessionManager. Returns uniform 401
//! responses for invalid or expired sessions.

use super::session::{SessionInfo, SessionManager};
use super::AuthErrorResponse;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use tracing::debug;

/// Authentication middleware that validates session tokens.
#[derive(Debug, Clone)]
pub struct AuthMiddleware {
    session_manager: SessionManager,
}

impl AuthMiddleware {
    /// Create a new AuthMiddleware with the given session manager.
    pub fn new(session_manager: SessionManager) -> Self {
        Self { session_manager }
    }

    /// Validate the session token from the request.
    ///
    /// Extracts the token from the `Authorization: Bearer <token>` header.
    /// Returns `Ok(SessionInfo)` if valid, or an error response if not.
    pub fn validate_request<B>(
        &self,
        req: &Request<B>,
    ) -> Result<SessionInfo, Response<Full<Bytes>>> {
        let token = Self::extract_bearer_token(req);

        match token {
            Some(token) => match self.session_manager.validate_session(token) {
                Ok(info) => Ok(info),
                Err(_) => {
                    debug!("Session validation failed");
                    Err(Self::unauthorized_response(
                        AuthErrorResponse::session_expired(),
                    ))
                }
            },
            None => {
                debug!("No Bearer token in Authorization header");
                Err(Self::unauthorized_response(
                    AuthErrorResponse::session_expired(),
                ))
            }
        }
    }

    /// Extract the Bearer token from the Authorization header.
    fn extract_bearer_token<B>(req: &Request<B>) -> Option<&str> {
        req.headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
    }

    /// Build a 401 Unauthorized JSON response.
    fn unauthorized_response(error: AuthErrorResponse) -> Response<Full<Bytes>> {
        let body = serde_json::to_string(&error).unwrap_or_else(|_| {
            r#"{"error":"session_expired","message":"Session expired, please re-authenticate"}"#
                .to_string()
        });

        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .expect("valid response")
    }

    /// Get a reference to the underlying session manager.
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }
}

/// Build a 401 Unauthorized JSON response for use outside the middleware.
pub fn unauthorized_json(error: AuthErrorResponse) -> Response<Full<Bytes>> {
    let body = serde_json::to_string(&error).unwrap_or_else(|_| {
        r#"{"error":"authentication_failed","message":"Invalid credentials"}"#.to_string()
    });

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("valid response")
}

/// Build a 429 Too Many Requests JSON response for locked accounts.
pub fn account_locked_json(remaining_seconds: u64) -> Response<Full<Bytes>> {
    let error = AuthErrorResponse::account_locked(remaining_seconds);
    let body = serde_json::to_string(&error).unwrap_or_else(|_| {
        format!(
            r#"{{"error":"account_locked","message":"Account temporarily locked","retry_after_seconds":{}}}"#,
            remaining_seconds
        )
    });

    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("retry-after", remaining_seconds.to_string())
        .body(Full::new(Bytes::from(body)))
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::config::SessionConfig;

    fn create_middleware() -> AuthMiddleware {
        let config = SessionConfig::default();
        let session_manager = SessionManager::new(&config);
        AuthMiddleware::new(session_manager)
    }

    #[test]
    fn test_validate_request_without_auth_header() {
        let middleware = create_middleware();
        let req = Request::builder()
            .uri("/api/v1/test")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = middleware.validate_request(&req);
        assert!(result.is_err());

        let response = result.unwrap_err();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_validate_request_with_invalid_token() {
        let middleware = create_middleware();
        let req = Request::builder()
            .uri("/api/v1/test")
            .header("authorization", "Bearer invalid-token-here")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = middleware.validate_request(&req);
        assert!(result.is_err());

        let response = result.unwrap_err();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_validate_request_with_valid_token() {
        let middleware = create_middleware();

        // Create a session first
        let token = middleware.session_manager().create_session("testuser");

        let req = Request::builder()
            .uri("/api/v1/test")
            .header("authorization", format!("Bearer {}", token))
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = middleware.validate_request(&req);
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.username, "testuser");
    }

    #[test]
    fn test_validate_request_with_wrong_auth_scheme() {
        let middleware = create_middleware();
        let req = Request::builder()
            .uri("/api/v1/test")
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let result = middleware.validate_request(&req);
        assert!(result.is_err());
    }

    #[test]
    fn test_unauthorized_response_format() {
        let error = AuthErrorResponse::invalid_credentials();
        let response = unauthorized_json(error);

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    #[test]
    fn test_account_locked_response_format() {
        let response = account_locked_json(900);

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(response.headers().get("retry-after").unwrap(), "900");
    }

    #[test]
    fn test_auth_error_response_serialization() {
        let error = AuthErrorResponse::invalid_credentials();
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("authentication_failed"));
        assert!(json.contains("Invalid credentials"));
        assert!(!json.contains("retry_after_seconds"));

        let error = AuthErrorResponse::session_expired();
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("session_expired"));
        assert!(json.contains("re-authenticate"));

        let error = AuthErrorResponse::account_locked(900);
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("account_locked"));
        assert!(json.contains("900"));
    }
}
