// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! D-Bus client for communicating with the Privileged_Daemon.
//!
//! The Backend_API uses this module to invoke privileged operations via D-Bus,
//! with Polkit authorization requested before each privileged call.

use shared::dbus::{DBUS_BUS_NAME, DBUS_INTERFACE_NAME, DBUS_OBJECT_PATH};
use shared::types::OperationResult;
use tracing::{debug, error, info};
use zbus::Connection;

/// Errors that can occur during D-Bus communication.
#[derive(Debug, thiserror::Error)]
pub enum DbusClientError {
    /// Failed to connect to the system D-Bus.
    #[error("failed to connect to system D-Bus: {0}")]
    ConnectionFailed(String),

    /// Polkit authorization was denied.
    #[error("Polkit authorization denied for action: {0}")]
    AuthorizationDenied(String),

    /// D-Bus method call failed.
    #[error("D-Bus method call failed: {0}")]
    MethodCallFailed(String),

    /// Failed to parse the response from the daemon.
    #[error("failed to parse daemon response: {0}")]
    ResponseParseFailed(String),
}

/// D-Bus client for the Privileged_Daemon.
///
/// Provides a high-level interface to call privileged operations via D-Bus,
/// handling Polkit authorization transparently.
pub struct PrivilegedClient {
    connection: Connection,
}

impl PrivilegedClient {
    /// Create a new `PrivilegedClient` connected to the system D-Bus.
    ///
    /// # Errors
    ///
    /// Returns `DbusClientError::ConnectionFailed` if the system bus is unreachable.
    pub async fn connect() -> Result<Self, DbusClientError> {
        let connection = Connection::system()
            .await
            .map_err(|e| DbusClientError::ConnectionFailed(e.to_string()))?;

        debug!("connected to system D-Bus");

        Ok(Self { connection })
    }

    /// Call a privileged method on the Privileged_Daemon with Polkit authorization.
    ///
    /// This method:
    /// 1. Requests Polkit authorization for the given action
    /// 2. Calls the specified D-Bus method with the provided arguments
    /// 3. Returns the operation result
    ///
    /// # Arguments
    ///
    /// * `method` — The D-Bus method name (e.g., "StartTool", "BlockIP")
    /// * `polkit_action` — The Polkit action ID for authorization
    /// * `args` — String arguments to pass to the method
    ///
    /// # Errors
    ///
    /// Returns an error if authorization is denied or the D-Bus call fails.
    pub async fn call_privileged(
        &self,
        method: &str,
        polkit_action: &str,
        args: &[&str],
    ) -> Result<OperationResult, DbusClientError> {
        // Step 1: Check Polkit authorization
        self.check_polkit_authorization(polkit_action).await?;

        // Step 2: Call the D-Bus method
        info!(method = method, "calling privileged daemon via D-Bus");

        let reply: (bool, String) = self
            .connection
            .call_method(
                Some(DBUS_BUS_NAME),
                DBUS_OBJECT_PATH,
                Some(DBUS_INTERFACE_NAME),
                method,
                &args,
            )
            .await
            .map_err(|e| {
                error!(method = method, error = %e, "D-Bus method call failed");
                DbusClientError::MethodCallFailed(e.to_string())
            })?
            .body()
            .deserialize()
            .map_err(|e| DbusClientError::ResponseParseFailed(e.to_string()))?;

        let (success, message) = reply;

        Ok(OperationResult {
            success,
            message,
            data: None,
        })
    }

    /// Check Polkit authorization for the given action.
    ///
    /// Queries the Polkit authority to determine if the current process
    /// is authorized to perform the specified action.
    ///
    /// # Errors
    ///
    /// Returns `DbusClientError::AuthorizationDenied` if authorization is not granted.
    async fn check_polkit_authorization(
        &self,
        action_id: &str,
    ) -> Result<(), DbusClientError> {
        debug!(action_id = action_id, "requesting Polkit authorization");

        // Query Polkit via D-Bus
        // The subject is the current process (system-bus-name)
        let bus_name = self
            .connection
            .unique_name()
            .map(|n| n.as_str().to_string())
            .unwrap_or_default();

        // Build the subject tuple: (subject_kind, subject_details)
        // For a system bus caller: ("system-bus-name", {"name": bus_name})
        let subject_kind = "system-bus-name";
        let subject_details: std::collections::HashMap<&str, zbus::zvariant::Value<'_>> = {
            let mut map = std::collections::HashMap::new();
            map.insert("name", zbus::zvariant::Value::from(bus_name.as_str()));
            map
        };

        let details: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let flags: u32 = 1; // AllowUserInteraction

        let reply: (u32, bool, std::collections::HashMap<String, String>) = self
            .connection
            .call_method(
                Some("org.freedesktop.PolicyKit1"),
                "/org/freedesktop/PolicyKit1/Authority",
                Some("org.freedesktop.PolicyKit1.Authority"),
                "CheckAuthorization",
                &(
                    (subject_kind, subject_details),
                    action_id,
                    details,
                    flags,
                    "",
                ),
            )
            .await
            .map_err(|e| {
                error!(action_id = action_id, error = %e, "Polkit authorization check failed");
                DbusClientError::AuthorizationDenied(format!(
                    "{}: {}",
                    action_id, e
                ))
            })?
            .body()
            .deserialize()
            .map_err(|e| {
                DbusClientError::AuthorizationDenied(format!(
                    "failed to parse Polkit response: {}",
                    e
                ))
            })?;

        let (is_authorized_u32, _is_challenge, _details) = reply;

        // Polkit returns: 0 = not authorized, 1 = authorized, 2 = challenge
        if is_authorized_u32 == 0 {
            info!(action_id = action_id, "Polkit authorization denied");
            return Err(DbusClientError::AuthorizationDenied(
                action_id.to_string(),
            ));
        }

        debug!(action_id = action_id, "Polkit authorization granted");
        Ok(())
    }
}

/// Map a D-Bus method name to its corresponding Polkit action ID.
///
/// This provides a centralized mapping so callers don't need to know
/// the Polkit action IDs directly.
pub fn polkit_action_for_method(method: &str) -> &'static str {
    match method {
        "StartTool" | "StopTool" | "RestartTool" => {
            "org.securitycommandcenter.manage-tools"
        }
        "ApplyFirewallRule" | "RemoveFirewallRule" | "BlockIP" => {
            "org.securitycommandcenter.firewall"
        }
        "QuarantineFile" | "RestoreFromQuarantine" | "DeleteQuarantined" => {
            "org.securitycommandcenter.quarantine"
        }
        "CaptureForensicsSnapshot" | "TraceProcess" => {
            "org.securitycommandcenter.forensics"
        }
        "CreateSnapshot" | "RollbackSnapshot" => {
            "org.securitycommandcenter.manage-tools"
        }
        "ApproveUSBDevice" | "BlockUSBDevice" => {
            "org.securitycommandcenter.manage-tools"
        }
        "EnforceMACProfile" => "org.securitycommandcenter.manage-tools",
        "VerifyIntegrity" => "org.securitycommandcenter.manage-tools",
        _ => "org.securitycommandcenter.manage-tools",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polkit_action_mapping_tools() {
        assert_eq!(
            polkit_action_for_method("StartTool"),
            "org.securitycommandcenter.manage-tools"
        );
        assert_eq!(
            polkit_action_for_method("StopTool"),
            "org.securitycommandcenter.manage-tools"
        );
        assert_eq!(
            polkit_action_for_method("RestartTool"),
            "org.securitycommandcenter.manage-tools"
        );
    }

    #[test]
    fn test_polkit_action_mapping_firewall() {
        assert_eq!(
            polkit_action_for_method("ApplyFirewallRule"),
            "org.securitycommandcenter.firewall"
        );
        assert_eq!(
            polkit_action_for_method("BlockIP"),
            "org.securitycommandcenter.firewall"
        );
    }

    #[test]
    fn test_polkit_action_mapping_quarantine() {
        assert_eq!(
            polkit_action_for_method("QuarantineFile"),
            "org.securitycommandcenter.quarantine"
        );
        assert_eq!(
            polkit_action_for_method("RestoreFromQuarantine"),
            "org.securitycommandcenter.quarantine"
        );
    }

    #[test]
    fn test_polkit_action_mapping_forensics() {
        assert_eq!(
            polkit_action_for_method("CaptureForensicsSnapshot"),
            "org.securitycommandcenter.forensics"
        );
        assert_eq!(
            polkit_action_for_method("TraceProcess"),
            "org.securitycommandcenter.forensics"
        );
    }

    #[test]
    fn test_polkit_action_mapping_unknown_defaults() {
        assert_eq!(
            polkit_action_for_method("UnknownMethod"),
            "org.securitycommandcenter.manage-tools"
        );
    }
}
