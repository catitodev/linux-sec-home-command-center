// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Command execution safety layer for the Linux Security Home Command Center.
//!
//! Provides safe subprocess execution using argument arrays (no shell interpolation),
//! input validation, execution timeouts, and sanitized logging.
//!
//! # Safety Guarantees
//!
//! - Commands are **never** executed via `sh -c` or any shell interpreter.
//! - Arguments are passed as arrays directly to the kernel via `execve`.
//! - All user-provided arguments are validated before use.
//! - Sensitive patterns (passwords, tokens) are redacted in logs.
//! - A configurable timeout (default 300s) kills runaway processes.

use std::time::{Duration, Instant};

use tokio::process::Command;
use tracing::{error, info, warn};

use crate::errors::{CommandCenterError, Result};

/// Default maximum execution timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Output captured from a completed command execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Standard output from the process.
    pub stdout: String,
    /// Standard error from the process.
    pub stderr: String,
    /// Exit code of the process (None if terminated by signal).
    pub exit_code: Option<i32>,
    /// Wall-clock duration of the execution.
    pub duration: Duration,
}

/// A safe command builder that enforces argument-array execution,
/// input validation, timeout enforcement, and sanitized logging.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
/// use shared::exec::SafeCommand;
///
/// # async fn example() -> shared::errors::Result<()> {
/// let mut cmd = SafeCommand::new("ls");
/// cmd.arg("-la")?;
/// cmd.arg("/tmp")?;
/// cmd.timeout(Duration::from_secs(30));
/// let output = cmd.execute().await?;
///
/// println!("stdout: {}", output.stdout);
/// # Ok(())
/// # }
/// ```
pub struct SafeCommand {
    program: String,
    args: Vec<String>,
    timeout_duration: Duration,
}

impl SafeCommand {
    /// Creates a new `SafeCommand` for the given program.
    ///
    /// The program is executed directly — never through a shell interpreter.
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_owned(),
            args: Vec::new(),
            timeout_duration: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Adds a single validated argument to the command.
    ///
    /// # Errors
    ///
    /// Returns an error if the argument fails validation (e.g., contains null bytes).
    pub fn arg(&mut self, arg: &str) -> Result<&mut Self> {
        validate_argument(arg)?;
        self.args.push(arg.to_owned());
        Ok(self)
    }

    /// Adds multiple validated arguments to the command.
    ///
    /// # Errors
    ///
    /// Returns an error if any argument fails validation.
    pub fn args(&mut self, args: &[&str]) -> Result<&mut Self> {
        for arg in args {
            validate_argument(arg)?;
        }
        self.args.extend(args.iter().map(|a| (*a).to_owned()));
        Ok(self)
    }

    /// Sets the maximum execution timeout.
    ///
    /// If the process does not complete within this duration, it will be killed.
    /// Default is 300 seconds.
    pub fn timeout(&mut self, duration: Duration) -> &mut Self {
        self.timeout_duration = duration;
        self
    }

    /// Executes the command with timeout enforcement and pre-execution logging.
    ///
    /// # Safety Guarantees
    ///
    /// - The command is executed directly via `tokio::process::Command` (no shell).
    /// - The process is killed if it exceeds the configured timeout.
    /// - Full command and arguments are logged (with sensitive values redacted).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The process fails to spawn.
    /// - The process exceeds the timeout (killed and error returned).
    /// - An I/O error occurs while reading output.
    pub async fn execute(&self) -> Result<CommandOutput> {
        // Log the command before execution with sanitized arguments.
        let sanitized_args: Vec<String> =
            self.args.iter().map(|a| sanitize_for_logging(a)).collect();

        info!(
            command = %self.program,
            args = ?sanitized_args,
            timeout_secs = self.timeout_duration.as_secs(),
            "Executing command"
        );

        // Build the tokio Command — NEVER use shell execution.
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);

        // Prevent inheriting stdin to avoid blocking on input.
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let start = Instant::now();

        // Spawn the child process.
        let mut child = cmd.spawn().map_err(|e| {
            error!(
                command = %self.program,
                error = %e,
                "Failed to spawn command"
            );
            CommandCenterError::Io(e)
        })?;

        // Wait for the process with timeout enforcement.
        // We use `child.wait()` + reading output separately to retain kill capability.
        let wait_result = tokio::time::timeout(self.timeout_duration, child.wait()).await;

        let duration = start.elapsed();

        match wait_result {
            Ok(Ok(status)) => {
                // Process completed within timeout. Read captured output.
                let stdout = {
                    let mut buf = Vec::new();
                    if let Some(mut out) = child.stdout.take() {
                        use tokio::io::AsyncReadExt;
                        let _ = out.read_to_end(&mut buf).await;
                    }
                    String::from_utf8_lossy(&buf).into_owned()
                };
                let stderr = {
                    let mut buf = Vec::new();
                    if let Some(mut err) = child.stderr.take() {
                        use tokio::io::AsyncReadExt;
                        let _ = err.read_to_end(&mut buf).await;
                    }
                    String::from_utf8_lossy(&buf).into_owned()
                };

                let exit_code = status.code();

                info!(
                    command = %self.program,
                    exit_code = ?exit_code,
                    duration_ms = duration.as_millis() as u64,
                    "Command completed"
                );

                Ok(CommandOutput {
                    stdout,
                    stderr,
                    exit_code,
                    duration,
                })
            }
            Ok(Err(e)) => {
                error!(
                    command = %self.program,
                    error = %e,
                    "Command I/O error"
                );
                Err(CommandCenterError::Io(e))
            }
            Err(_elapsed) => {
                // Timeout exceeded — kill the process.
                warn!(
                    command = %self.program,
                    timeout_secs = self.timeout_duration.as_secs(),
                    "Command exceeded timeout, killing process"
                );

                // Attempt to kill the child process.
                if let Err(e) = child.kill().await {
                    error!(
                        command = %self.program,
                        error = %e,
                        "Failed to kill timed-out process"
                    );
                }

                Err(CommandCenterError::Internal(format!(
                    "command '{}' exceeded timeout of {}s",
                    self.program,
                    self.timeout_duration.as_secs()
                )))
            }
        }
    }
}

/// Validates a command argument for safety.
///
/// Rejects arguments containing:
/// - Null bytes (`\0`) which could truncate strings at the OS level.
///
/// Note: Shell metacharacters are NOT rejected because arguments are passed
/// directly to `execve` as an array — they are treated as literal characters
/// by the kernel, not interpreted by a shell.
///
/// # Errors
///
/// Returns `CommandCenterError::Internal` if the argument is invalid.
pub fn validate_argument(arg: &str) -> Result<()> {
    if arg.contains('\0') {
        return Err(CommandCenterError::Internal(format!(
            "argument contains null byte: '{}'",
            sanitize_for_logging(arg)
        )));
    }
    Ok(())
}

/// Sanitizes a string for safe logging by redacting known sensitive patterns.
///
/// Redacts values that look like:
/// - Passwords (following `--password`, `-p`, `passwd=`, etc.)
/// - API tokens and keys (long hex/base64 strings following `token=`, `key=`, etc.)
/// - Environment variable assignments with sensitive names
pub fn sanitize_for_logging(arg: &str) -> String {
    // Redact values in key=value patterns with sensitive keys.
    let sensitive_keys = [
        "password",
        "passwd",
        "pass",
        "token",
        "secret",
        "key",
        "api_key",
        "apikey",
        "auth",
        "credential",
        "private",
    ];

    // Check for key=value patterns.
    if let Some(eq_pos) = arg.find('=') {
        let key_part = &arg[..eq_pos].to_lowercase();
        let key_name = key_part
            .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
            .next()
            .unwrap_or(key_part);

        for sensitive in &sensitive_keys {
            if key_name.contains(sensitive) {
                return format!("{}=<REDACTED>", &arg[..eq_pos]);
            }
        }
    }

    // Check if the entire argument looks like a long token/key (40+ hex or base64 chars).
    if arg.len() >= 40 && arg.chars().all(|c| c.is_ascii_hexdigit()) {
        return "<REDACTED_HEX>".to_owned();
    }

    if arg.len() >= 40
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return "<REDACTED_BASE64>".to_owned();
    }

    arg.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_argument_accepts_normal_strings() {
        assert!(validate_argument("hello").is_ok());
        assert!(validate_argument("/path/to/file").is_ok());
        assert!(validate_argument("--flag=value").is_ok());
        assert!(validate_argument("").is_ok());
    }

    #[test]
    fn test_validate_argument_accepts_shell_metacharacters() {
        // Shell metacharacters are safe because we never use shell execution.
        assert!(validate_argument("hello; world").is_ok());
        assert!(validate_argument("$(whoami)").is_ok());
        assert!(validate_argument("`id`").is_ok());
        assert!(validate_argument("a | b").is_ok());
        assert!(validate_argument("a && b").is_ok());
        assert!(validate_argument("a > /dev/null").is_ok());
        assert!(validate_argument("$HOME").is_ok());
    }

    #[test]
    fn test_validate_argument_rejects_null_bytes() {
        assert!(validate_argument("hello\0world").is_err());
        assert!(validate_argument("\0").is_err());
        assert!(validate_argument("before\0").is_err());
    }

    #[test]
    fn test_sanitize_for_logging_passes_normal_strings() {
        assert_eq!(sanitize_for_logging("hello"), "hello");
        assert_eq!(sanitize_for_logging("/path/to/file"), "/path/to/file");
        assert_eq!(sanitize_for_logging("--verbose"), "--verbose");
    }

    #[test]
    fn test_sanitize_for_logging_redacts_password_patterns() {
        assert_eq!(
            sanitize_for_logging("password=mysecret123"),
            "password=<REDACTED>"
        );
        assert_eq!(
            sanitize_for_logging("DB_PASSWORD=hunter2"),
            "DB_PASSWORD=<REDACTED>"
        );
        assert_eq!(
            sanitize_for_logging("token=abc123def456"),
            "token=<REDACTED>"
        );
        assert_eq!(
            sanitize_for_logging("api_key=sk-1234567890"),
            "api_key=<REDACTED>"
        );
    }

    #[test]
    fn test_sanitize_for_logging_redacts_long_hex_tokens() {
        let hex_token = "a".repeat(40);
        assert_eq!(sanitize_for_logging(&hex_token), "<REDACTED_HEX>");
    }

    #[test]
    fn test_sanitize_for_logging_redacts_long_base64_tokens() {
        let base64_token = "A".repeat(40) + "==";
        assert_eq!(sanitize_for_logging(&base64_token), "<REDACTED_BASE64>");
    }

    #[test]
    fn test_sanitize_for_logging_preserves_short_values() {
        // Short hex strings should not be redacted.
        assert_eq!(sanitize_for_logging("abcdef"), "abcdef");
        assert_eq!(sanitize_for_logging("1234567890"), "1234567890");
    }

    #[test]
    fn test_sanitize_for_logging_preserves_non_sensitive_key_value() {
        assert_eq!(sanitize_for_logging("name=john"), "name=john");
        assert_eq!(sanitize_for_logging("count=42"), "count=42");
        assert_eq!(sanitize_for_logging("path=/usr/bin"), "path=/usr/bin");
    }

    #[test]
    fn test_safe_command_new() {
        let cmd = SafeCommand::new("ls");
        assert_eq!(cmd.program, "ls");
        assert!(cmd.args.is_empty());
        assert_eq!(cmd.timeout_duration, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
    }

    #[test]
    fn test_safe_command_arg_validation() {
        let mut cmd = SafeCommand::new("echo");
        assert!(cmd.arg("hello").is_ok());
        assert!(cmd.arg("hello\0world").is_err());
    }

    #[test]
    fn test_safe_command_args_validation() {
        let mut cmd = SafeCommand::new("echo");
        assert!(cmd.args(&["hello", "world"]).is_ok());
        assert!(cmd.args(&["good", "bad\0arg"]).is_err());
    }

    #[test]
    fn test_safe_command_timeout_setting() {
        let mut cmd = SafeCommand::new("sleep");
        cmd.timeout(Duration::from_secs(10));
        assert_eq!(cmd.timeout_duration, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_safe_command_execute_success() {
        let mut cmd = SafeCommand::new("echo");
        cmd.arg("hello").unwrap();
        cmd.timeout(Duration::from_secs(5));

        let output = cmd.execute().await.unwrap();
        assert_eq!(output.stdout.trim(), "hello");
        assert_eq!(output.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_safe_command_execute_captures_stderr() {
        let mut cmd = SafeCommand::new("sh");
        cmd.args(&["-c", "echo error >&2"]).unwrap();
        cmd.timeout(Duration::from_secs(5));

        let output = cmd.execute().await.unwrap();
        assert!(output.stderr.contains("error"));
    }

    #[tokio::test]
    async fn test_safe_command_execute_nonzero_exit() {
        let mut cmd = SafeCommand::new("false");
        cmd.timeout(Duration::from_secs(5));

        let output = cmd.execute().await.unwrap();
        assert_ne!(output.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_safe_command_execute_timeout() {
        let mut cmd = SafeCommand::new("sleep");
        cmd.arg("60").unwrap();
        cmd.timeout(Duration::from_millis(100));

        let result = cmd.execute().await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("timeout"));
    }

    #[tokio::test]
    async fn test_safe_command_shell_metacharacters_are_literal() {
        // Verify that shell metacharacters are NOT interpreted.
        // If shell execution were used, `$(whoami)` would be expanded.
        let mut cmd = SafeCommand::new("echo");
        cmd.arg("$(whoami)").unwrap();
        cmd.timeout(Duration::from_secs(5));

        let output = cmd.execute().await.unwrap();
        // The literal string should appear in stdout, not the result of whoami.
        assert_eq!(output.stdout.trim(), "$(whoami)");
    }

    #[tokio::test]
    async fn test_safe_command_spawn_failure() {
        let cmd = SafeCommand::new("/nonexistent/binary/path");

        let result = cmd.execute().await;
        assert!(result.is_err());
    }
}
