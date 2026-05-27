// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Operation whitelist enforcement for the Privileged Daemon.
//!
//! Loads the whitelist configuration from `/etc/security-command-center/whitelist.toml`
//! and validates incoming D-Bus method calls against the allowed operations list.

use shared::config::{WhitelistConfig, WhitelistedOperation};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

/// Validates D-Bus operations against the configured whitelist.
#[derive(Debug, Clone)]
pub struct WhitelistValidator {
    /// Map of operation name → whitelisted operation details.
    operations: HashMap<String, WhitelistedOperation>,
}

impl WhitelistValidator {
    /// Load the whitelist from a TOML configuration file.
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from_file(path: &Path) -> Result<Self, WhitelistError> {
        let content = std::fs::read_to_string(path).map_err(|e| WhitelistError::IoError {
            path: path.display().to_string(),
            source: e,
        })?;

        Self::from_toml(&content)
    }

    /// Parse the whitelist from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self, WhitelistError> {
        let config: WhitelistConfig =
            toml::from_str(content).map_err(|e| WhitelistError::ParseError {
                details: e.to_string(),
            })?;

        let operations: HashMap<String, WhitelistedOperation> = config
            .operations
            .into_iter()
            .map(|op| (op.name.clone(), op))
            .collect();

        info!(
            operation_count = operations.len(),
            "Whitelist loaded successfully"
        );

        Ok(Self { operations })
    }

    /// Check whether an operation is permitted by the whitelist.
    ///
    /// Returns `true` if the operation is whitelisted, `false` otherwise.
    /// Rejected operations are logged with the operation name and requesting user.
    pub fn is_allowed(&self, operation: &str, requesting_user: &str) -> bool {
        if self.operations.contains_key(operation) {
            true
        } else {
            warn!(
                operation = operation,
                requesting_user = requesting_user,
                "Operation rejected: not in whitelist"
            );
            false
        }
    }

    /// Get the whitelisted operation details, if it exists.
    pub fn get_operation(&self, operation: &str) -> Option<&WhitelistedOperation> {
        self.operations.get(operation)
    }

    /// Check whether an operation requires additional Polkit confirmation.
    pub fn requires_confirmation(&self, operation: &str) -> bool {
        self.operations
            .get(operation)
            .map(|op| op.requires_confirmation)
            .unwrap_or(false)
    }

    /// Return the list of all whitelisted operation names.
    pub fn allowed_operations(&self) -> Vec<&str> {
        self.operations.keys().map(|s| s.as_str()).collect()
    }
}

/// Errors that can occur during whitelist loading or validation.
#[derive(Debug, thiserror::Error)]
pub enum WhitelistError {
    /// Failed to read the whitelist file.
    #[error("failed to read whitelist file '{path}': {source}")]
    IoError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse the whitelist TOML content.
    #[error("failed to parse whitelist configuration: {details}")]
    ParseError { details: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_whitelist_toml() -> &'static str {
        r#"
[[operations]]
name = "StartTool"
description = "Start a security tool"
requires_confirmation = false

[[operations]]
name = "StopTool"
description = "Stop a security tool"
requires_confirmation = true

[[operations]]
name = "BlockIP"
description = "Block an IP address"
requires_confirmation = true
"#
    }

    #[test]
    fn test_load_valid_whitelist() {
        let validator = WhitelistValidator::from_toml(sample_whitelist_toml()).unwrap();
        assert_eq!(validator.allowed_operations().len(), 3);
    }

    #[test]
    fn test_allowed_operation() {
        let validator = WhitelistValidator::from_toml(sample_whitelist_toml()).unwrap();
        assert!(validator.is_allowed("StartTool", "testuser"));
        assert!(validator.is_allowed("StopTool", "testuser"));
        assert!(validator.is_allowed("BlockIP", "testuser"));
    }

    #[test]
    fn test_rejected_operation() {
        let validator = WhitelistValidator::from_toml(sample_whitelist_toml()).unwrap();
        assert!(!validator.is_allowed("DeleteEverything", "testuser"));
        assert!(!validator.is_allowed("", "testuser"));
        assert!(!validator.is_allowed("starttool", "testuser")); // case-sensitive
    }

    #[test]
    fn test_requires_confirmation() {
        let validator = WhitelistValidator::from_toml(sample_whitelist_toml()).unwrap();
        assert!(!validator.requires_confirmation("StartTool"));
        assert!(validator.requires_confirmation("StopTool"));
        assert!(validator.requires_confirmation("BlockIP"));
        assert!(!validator.requires_confirmation("NonExistent"));
    }

    #[test]
    fn test_invalid_toml() {
        let result = WhitelistValidator::from_toml("this is not valid toml [[[");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_operations() {
        let toml = r#"
operations = []
"#;
        let validator = WhitelistValidator::from_toml(toml).unwrap();
        assert!(validator.allowed_operations().is_empty());
        assert!(!validator.is_allowed("StartTool", "testuser"));
    }
}
