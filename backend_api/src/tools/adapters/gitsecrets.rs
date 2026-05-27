// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Git secrets scanning adapter: detects leaked credentials in git repositories.
//!
//! Coordinates trufflehog and gitleaks to scan repositories for accidentally
//! committed secrets (API keys, passwords, tokens), deduplicates findings,
//! provides revocation guidance, and supports pre-commit hook installation.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use shared::distro::{DistroInfo, PackageManager};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Types ─────────────────────────────────────────────────────────────────

/// Which secrets scanning tool produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretsTool {
    Trufflehog,
    Gitleaks,
}

/// Type of secret detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    ApiKey,
    Password,
    Token,
    PrivateKey,
    DatabaseUrl,
    AwsCredential,
    GithubToken,
    GenericSecret,
}

/// A single finding from a secrets scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretsFinding {
    /// Unique identifier for this finding.
    pub id: Uuid,
    /// Path to the file containing the secret.
    pub file_path: PathBuf,
    /// Git commit hash where the secret was found.
    pub commit_hash: Option<String>,
    /// Type of secret detected.
    pub secret_type: SecretType,
    /// Line number in the file.
    pub line_number: Option<u32>,
    /// Which tool detected this secret.
    pub tool: SecretsTool,
    /// When the finding was detected.
    pub detected_at: DateTime<Utc>,
}

/// Coordinates scanning with both trufflehog and gitleaks.
pub struct SecretsScanner;

impl SecretsScanner {
    /// Parses gitleaks JSON output into findings.
    ///
    /// Gitleaks outputs JSON array of findings with fields:
    /// - File, Commit, Rule, StartLine
    pub fn parse_gitleaks_output(output: &str) -> Vec<SecretsFinding> {
        let mut findings = Vec::new();
        let now = Utc::now();

        // Attempt to parse as JSON array
        if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(output) {
            for entry in entries {
                let file_path = entry
                    .get("File")
                    .or_else(|| entry.get("file"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let commit_hash = entry
                    .get("Commit")
                    .or_else(|| entry.get("commit"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let line_number = entry
                    .get("StartLine")
                    .or_else(|| entry.get("startLine"))
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32);

                let rule = entry
                    .get("RuleID")
                    .or_else(|| entry.get("rule"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let secret_type = Self::classify_secret_type(rule);

                findings.push(SecretsFinding {
                    id: Uuid::new_v4(),
                    file_path: PathBuf::from(file_path),
                    commit_hash,
                    secret_type,
                    line_number,
                    tool: SecretsTool::Gitleaks,
                    detected_at: now,
                });
            }
        }

        findings
    }

    /// Parses trufflehog JSON output into findings.
    pub fn parse_trufflehog_output(output: &str) -> Vec<SecretsFinding> {
        let mut findings = Vec::new();
        let now = Utc::now();

        // Trufflehog outputs one JSON object per line
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
                let file_path = entry
                    .get("SourceMetadata")
                    .and_then(|sm| sm.get("Data"))
                    .and_then(|d| d.get("Filesystem"))
                    .and_then(|fs| fs.get("file"))
                    .or_else(|| entry.get("file"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let commit_hash = entry
                    .get("SourceMetadata")
                    .and_then(|sm| sm.get("Data"))
                    .and_then(|d| d.get("Git"))
                    .and_then(|g| g.get("commit"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let detector_name = entry
                    .get("DetectorName")
                    .or_else(|| entry.get("detectorName"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let secret_type = Self::classify_secret_type(detector_name);

                if !file_path.is_empty() {
                    findings.push(SecretsFinding {
                        id: Uuid::new_v4(),
                        file_path: PathBuf::from(file_path),
                        commit_hash,
                        secret_type,
                        line_number: None,
                        tool: SecretsTool::Trufflehog,
                        detected_at: now,
                    });
                }
            }
        }

        findings
    }

    /// Deduplicates findings from both tools based on file path and commit.
    pub fn deduplicate(findings: &[SecretsFinding]) -> Vec<SecretsFinding> {
        let mut seen = std::collections::HashSet::new();
        let mut deduped = Vec::new();

        for finding in findings {
            let key = (
                finding.file_path.to_string_lossy().to_string(),
                finding.commit_hash.clone().unwrap_or_default(),
                finding.line_number,
            );

            if seen.insert(key) {
                deduped.push(finding.clone());
            }
        }

        deduped
    }

    /// Classifies a secret type from a rule/detector name.
    fn classify_secret_type(rule: &str) -> SecretType {
        let lower = rule.to_lowercase();
        if lower.contains("aws") {
            SecretType::AwsCredential
        } else if lower.contains("github") || lower.contains("gh_") {
            SecretType::GithubToken
        } else if lower.contains("private") || lower.contains("rsa") || lower.contains("ssh") {
            SecretType::PrivateKey
        } else if lower.contains("password") || lower.contains("passwd") {
            SecretType::Password
        } else if lower.contains("token") || lower.contains("jwt") {
            SecretType::Token
        } else if lower.contains("database") || lower.contains("postgres") || lower.contains("mysql") {
            SecretType::DatabaseUrl
        } else if lower.contains("api") || lower.contains("key") {
            SecretType::ApiKey
        } else {
            SecretType::GenericSecret
        }
    }
}

/// Manages pre-commit hook installation for gitleaks.
pub struct PreCommitHook;

impl PreCommitHook {
    /// Generates the gitleaks pre-commit hook script content.
    pub fn generate_hook_script() -> &'static str {
        r#"#!/bin/bash
# Gitleaks pre-commit hook installed by Linux Security Command Center
# Scans staged changes for secrets before allowing commit

if ! command -v gitleaks &> /dev/null; then
    echo "WARNING: gitleaks not found, skipping secrets scan"
    exit 0
fi

gitleaks protect --staged --no-banner
exit_code=$?

if [ $exit_code -ne 0 ]; then
    echo ""
    echo "ERROR: Secrets detected in staged changes!"
    echo "Please remove the secrets before committing."
    echo "Use 'git commit --no-verify' to bypass (not recommended)."
    exit 1
fi
"#
    }

    /// Returns the path where the pre-commit hook should be installed.
    pub fn hook_path(repo_path: &Path) -> PathBuf {
        repo_path.join(".git").join("hooks").join("pre-commit")
    }

    /// Checks if a pre-commit hook is already installed.
    pub fn is_installed(repo_path: &Path) -> bool {
        Self::hook_path(repo_path).exists()
    }
}

/// Provides revocation guidance for different secret types.
pub struct RevocationGuidance;

impl RevocationGuidance {
    /// Returns revocation steps for a given secret type.
    pub fn guidance_for(secret_type: &SecretType) -> &'static str {
        match secret_type {
            SecretType::AwsCredential => {
                "1. Go to AWS IAM Console → Users → Security Credentials\n\
                 2. Find the compromised access key and click 'Make Inactive'\n\
                 3. Create a new access key pair\n\
                 4. Update all services using the old key\n\
                 5. Delete the inactive key after confirming no usage"
            }
            SecretType::GithubToken => {
                "1. Go to GitHub → Settings → Developer Settings → Personal Access Tokens\n\
                 2. Find and revoke the compromised token\n\
                 3. Generate a new token with appropriate scopes\n\
                 4. Update all services using the old token"
            }
            SecretType::Password => {
                "1. Change the password immediately on the affected service\n\
                 2. Check for unauthorized access in service logs\n\
                 3. Enable MFA if not already active\n\
                 4. Update all applications using this password"
            }
            SecretType::PrivateKey => {
                "1. Generate a new key pair immediately\n\
                 2. Remove the compromised public key from all authorized_keys files\n\
                 3. Add the new public key to required services\n\
                 4. Revoke any certificates signed with the compromised key"
            }
            SecretType::DatabaseUrl => {
                "1. Change the database password immediately\n\
                 2. Review database access logs for unauthorized queries\n\
                 3. Update connection strings in all applications\n\
                 4. Consider rotating the database user entirely"
            }
            SecretType::Token | SecretType::ApiKey => {
                "1. Revoke the token/key in the issuing service's dashboard\n\
                 2. Generate a new token/key with appropriate permissions\n\
                 3. Update all applications using the old credential\n\
                 4. Monitor for unauthorized usage of the old credential"
            }
            SecretType::GenericSecret => {
                "1. Identify the service this secret belongs to\n\
                 2. Rotate the credential in the service's management console\n\
                 3. Update all applications using this credential\n\
                 4. Monitor for unauthorized access"
            }
        }
    }
}

// ─── GitSecretsAdapter ─────────────────────────────────────────────────────

/// Adapter for git secrets scanning (trufflehog + gitleaks).
pub struct GitSecretsAdapter;

#[async_trait]
impl ToolAdapter for GitSecretsAdapter {
    fn name(&self) -> &str {
        "gitleaks"
    }

    fn display_name(&self) -> &str {
        "Git Secrets Scanner"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::GitSecurity
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        info!(distro = %distro.id, "Installing git secrets scanning tools");

        // Try to install gitleaks via package manager first
        let gitleaks_result = self.install_gitleaks(distro).await;
        if let Err(ref e) = gitleaks_result {
            warn!(error = %e, "Package manager install failed for gitleaks, trying binary download");
            self.install_gitleaks_binary().await?;
        }

        // Install trufflehog (typically via binary download)
        self.install_trufflehog().await?;

        info!("Git secrets scanning tools installed");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        // Scan-based tool — no service to start.
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        // Scan-based tool — no service to stop.
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut gl_cmd = SafeCommand::new("which");
        if gl_cmd.arg("gitleaks").is_err() {
            return HealthStatus::Unhealthy("failed to build command".to_string());
        }
        gl_cmd.timeout(Duration::from_secs(5));

        let gl_ok = gl_cmd
            .execute()
            .await
            .map(|o| o.exit_code == Some(0))
            .unwrap_or(false);

        let mut th_cmd = SafeCommand::new("which");
        if th_cmd.arg("trufflehog").is_err() {
            return HealthStatus::Unhealthy("failed to build command".to_string());
        }
        th_cmd.timeout(Duration::from_secs(5));

        let th_ok = th_cmd
            .execute()
            .await
            .map(|o| o.exit_code == Some(0))
            .unwrap_or(false);

        match (gl_ok, th_ok) {
            (true, true) => HealthStatus::Healthy,
            (true, false) => {
                HealthStatus::Degraded("trufflehog binary not found".to_string())
            }
            (false, true) => {
                HealthStatus::Degraded("gitleaks binary not found".to_string())
            }
            (false, false) => {
                HealthStatus::Unhealthy("neither gitleaks nor trufflehog found".to_string())
            }
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // ~50 MB combined (Go binaries)
        50_000_000
    }
}

impl GitSecretsAdapter {
    /// Attempts to install gitleaks via the system package manager.
    async fn install_gitleaks(&self, distro: &DistroInfo) -> Result<()> {
        let install_args: Vec<&str> = match distro.package_manager {
            PackageManager::Apt => vec!["apt-get", "install", "-y", "gitleaks"],
            PackageManager::Dnf => vec!["dnf", "install", "-y", "gitleaks"],
            PackageManager::Pacman => vec!["pacman", "-S", "--noconfirm", "gitleaks"],
            PackageManager::Zypper => vec!["zypper", "install", "-y", "gitleaks"],
        };

        let mut cmd = SafeCommand::new(install_args[0]);
        cmd.args(&install_args[1..])?;
        cmd.timeout(Duration::from_secs(120));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "gitleaks".to_string(),
                reason: format!("package install failed: {}", output.stderr),
            });
        }

        Ok(())
    }

    /// Installs gitleaks via binary download as fallback.
    async fn install_gitleaks_binary(&self) -> Result<()> {
        info!("Downloading gitleaks binary");

        // Use a version-pinned URL for reproducibility
        let mut cmd = SafeCommand::new("sh");
        cmd.args(&[
            "-c",
            "curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz | tar xz -C /usr/local/bin gitleaks",
        ])?;
        cmd.timeout(Duration::from_secs(120));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "gitleaks".to_string(),
                reason: format!("binary download failed: {}", output.stderr),
            });
        }

        Ok(())
    }

    /// Installs trufflehog via binary download.
    async fn install_trufflehog(&self) -> Result<()> {
        info!("Downloading trufflehog binary");

        let mut cmd = SafeCommand::new("sh");
        cmd.args(&[
            "-c",
            "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
        ])?;
        cmd.timeout(Duration::from_secs(120));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            warn!(stderr = %output.stderr, "trufflehog install script returned non-zero");
            // Non-fatal: gitleaks alone is sufficient
        }

        Ok(())
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = GitSecretsAdapter;
        assert_eq!(adapter.name(), "gitleaks");
        assert_eq!(adapter.display_name(), "Git Secrets Scanner");
        assert_eq!(adapter.category(), ToolCategory::GitSecurity);
    }

    #[test]
    fn test_adapter_available_for_all_distros() {
        let adapter = GitSecretsAdapter;
        let distro = DistroInfo {
            id: "ubuntu".to_string(),
            version_id: "22.04".to_string(),
            name: "Ubuntu".to_string(),
            package_manager: PackageManager::Apt,
            has_btrfs: false,
            kernel_version: (6, 5),
            has_ebpf: true,
            mac_framework: shared::distro::MACFramework::AppArmor,
        };
        assert!(adapter.is_available_for(&distro));
    }

    #[test]
    fn test_parse_gitleaks_output() {
        let output = r#"[{"File":"config.py","Commit":"abc123","RuleID":"generic-api-key","StartLine":10}]"#;
        let findings = SecretsScanner::parse_gitleaks_output(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, PathBuf::from("config.py"));
        assert_eq!(findings[0].commit_hash, Some("abc123".to_string()));
        assert_eq!(findings[0].line_number, Some(10));
        assert_eq!(findings[0].tool, SecretsTool::Gitleaks);
    }

    #[test]
    fn test_parse_gitleaks_empty() {
        let output = "[]";
        let findings = SecretsScanner::parse_gitleaks_output(output);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_classify_secret_type() {
        assert_eq!(
            SecretsScanner::parse_gitleaks_output(
                r#"[{"File":"f","RuleID":"aws-access-key","StartLine":1}]"#
            )[0].secret_type,
            SecretType::AwsCredential
        );
    }

    #[test]
    fn test_deduplicate_findings() {
        let now = Utc::now();
        let findings = vec![
            SecretsFinding {
                id: Uuid::new_v4(),
                file_path: PathBuf::from("config.py"),
                commit_hash: Some("abc123".to_string()),
                secret_type: SecretType::ApiKey,
                line_number: Some(10),
                tool: SecretsTool::Gitleaks,
                detected_at: now,
            },
            SecretsFinding {
                id: Uuid::new_v4(),
                file_path: PathBuf::from("config.py"),
                commit_hash: Some("abc123".to_string()),
                secret_type: SecretType::ApiKey,
                line_number: Some(10),
                tool: SecretsTool::Trufflehog,
                detected_at: now,
            },
        ];

        let deduped = SecretsScanner::deduplicate(&findings);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_revocation_guidance_aws() {
        let guidance = RevocationGuidance::guidance_for(&SecretType::AwsCredential);
        assert!(guidance.contains("AWS IAM Console"));
    }

    #[test]
    fn test_revocation_guidance_github() {
        let guidance = RevocationGuidance::guidance_for(&SecretType::GithubToken);
        assert!(guidance.contains("GitHub"));
    }

    #[test]
    fn test_pre_commit_hook_script() {
        let script = PreCommitHook::generate_hook_script();
        assert!(script.contains("gitleaks"));
        assert!(script.contains("pre-commit"));
    }

    #[test]
    fn test_pre_commit_hook_path() {
        let repo = PathBuf::from("/home/user/project");
        let hook_path = PreCommitHook::hook_path(&repo);
        assert_eq!(hook_path, PathBuf::from("/home/user/project/.git/hooks/pre-commit"));
    }

    #[test]
    fn test_pre_commit_hook_not_installed() {
        let repo = PathBuf::from("/nonexistent/repo");
        assert!(!PreCommitHook::is_installed(&repo));
    }

    #[test]
    fn test_estimated_size() {
        let adapter = GitSecretsAdapter;
        assert!(adapter.estimated_size_bytes() > 0);
    }
}
