// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! PAM authentication module.
//!
//! Authenticates users against the local PAM subsystem. Returns uniform
//! errors that never reveal whether the username exists or the password
//! was incorrect.

use shared::errors::CommandCenterError;
use tracing::warn;

#[cfg(feature = "pam")]
use tracing::info;

/// Trait for authentication backends, enabling testing without real PAM.
pub trait Authenticator: Send + Sync {
    /// Authenticate a user with username and password.
    ///
    /// Returns `Ok(())` on success, or `Err(CommandCenterError::AuthenticationFailed)`
    /// on failure. The error is intentionally uniform — it does not reveal
    /// whether the username was invalid or the password was wrong.
    fn authenticate(&self, username: &str, password: &str) -> Result<(), CommandCenterError>;
}

/// PAM-based authenticator using the system PAM subsystem.
///
/// Uses the "security-command-center" PAM service if available,
/// falling back to "login" service.
pub struct PamAuthenticator {
    /// PAM service name to use for authentication.
    service_name: String,
}

impl PamAuthenticator {
    /// Create a new PAM authenticator with the default service name.
    pub fn new() -> Self {
        Self {
            service_name: "login".to_string(),
        }
    }

    /// Create a new PAM authenticator with a custom service name.
    pub fn with_service(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
        }
    }
}

impl Default for PamAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator for PamAuthenticator {
    fn authenticate(&self, username: &str, password: &str) -> Result<(), CommandCenterError> {
        // Validate inputs are non-empty (but still return uniform error)
        if username.is_empty() || password.is_empty() {
            warn!("Authentication attempt with empty credentials");
            return Err(CommandCenterError::AuthenticationFailed);
        }

        // Attempt PAM authentication via pam crate
        #[cfg(feature = "pam")]
        {
            match pam::Authenticator::with_password(&self.service_name) {
                Ok(mut auth) => {
                    auth.get_handler().set_credentials(username, password);
                    match auth.authenticate() {
                        Ok(()) => {
                            info!(user = %username, "PAM authentication successful");
                            Ok(())
                        }
                        Err(_) => {
                            warn!(user = %username, "PAM authentication failed");
                            Err(CommandCenterError::AuthenticationFailed)
                        }
                    }
                }
                Err(_) => {
                    warn!(
                        service = %self.service_name,
                        "Failed to create PAM authenticator"
                    );
                    Err(CommandCenterError::AuthenticationFailed)
                }
            }
        }

        // When compiled without PAM feature, use a stub that always fails.
        // This allows compilation on systems without PAM development headers.
        #[cfg(not(feature = "pam"))]
        {
            // Suppress unused variable warnings
            let _ = &self.service_name;
            warn!(
                user = %username,
                "PAM feature not enabled — authentication unavailable"
            );
            Err(CommandCenterError::AuthenticationFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock authenticator for testing that accepts specific credentials.
    pub struct MockAuthenticator {
        pub valid_username: String,
        pub valid_password: String,
    }

    impl MockAuthenticator {
        pub fn new(username: &str, password: &str) -> Self {
            Self {
                valid_username: username.to_string(),
                valid_password: password.to_string(),
            }
        }
    }

    impl Authenticator for MockAuthenticator {
        fn authenticate(&self, username: &str, password: &str) -> Result<(), CommandCenterError> {
            if username == self.valid_username && password == self.valid_password {
                Ok(())
            } else {
                Err(CommandCenterError::AuthenticationFailed)
            }
        }
    }

    #[test]
    fn test_pam_authenticator_rejects_empty_username() {
        let auth = PamAuthenticator::new();
        let result = auth.authenticate("", "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_pam_authenticator_rejects_empty_password() {
        let auth = PamAuthenticator::new();
        let result = auth.authenticate("user", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_authenticator_accepts_valid_credentials() {
        let auth = MockAuthenticator::new("admin", "secret");
        assert!(auth.authenticate("admin", "secret").is_ok());
    }

    #[test]
    fn test_mock_authenticator_rejects_wrong_password() {
        let auth = MockAuthenticator::new("admin", "secret");
        let result = auth.authenticate("admin", "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_mock_authenticator_rejects_wrong_username() {
        let auth = MockAuthenticator::new("admin", "secret");
        let result = auth.authenticate("nobody", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_uniform_error_for_wrong_user_and_wrong_password() {
        let auth = MockAuthenticator::new("admin", "secret");

        let err_wrong_user = auth.authenticate("nobody", "secret").unwrap_err();
        let err_wrong_pass = auth.authenticate("admin", "wrong").unwrap_err();
        let err_both_wrong = auth.authenticate("nobody", "wrong").unwrap_err();

        // All errors should be the same variant
        assert!(matches!(err_wrong_user, CommandCenterError::AuthenticationFailed));
        assert!(matches!(err_wrong_pass, CommandCenterError::AuthenticationFailed));
        assert!(matches!(err_both_wrong, CommandCenterError::AuthenticationFailed));

        // Error messages should be identical (uniform response)
        assert_eq!(err_wrong_user.to_string(), err_wrong_pass.to_string());
        assert_eq!(err_wrong_pass.to_string(), err_both_wrong.to_string());
    }
}
