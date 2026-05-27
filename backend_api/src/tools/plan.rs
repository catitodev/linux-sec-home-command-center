// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Installation plan generation and display.
//!
//! Creates a phased installation plan that groups tools by category and
//! provides information for user review before proceeding with installation.

use serde::{Deserialize, Serialize};

use shared::distro::PackageManager;

/// A single entry in an installation phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanEntry {
    /// Internal tool name (e.g., "falco").
    pub name: String,
    /// Human-readable display name (e.g., "Falco").
    pub display_name: String,
    /// Distribution-specific package name, if available.
    pub package_name: Option<String>,
    /// Estimated download size in bytes.
    pub estimated_size_bytes: u64,
    /// Whether this tool is available for the detected distribution.
    pub available_for_distro: bool,
}

/// A phase in the installation plan grouping related tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallPhase {
    /// Phase name (e.g., "Foundation (Visibility)").
    pub name: String,
    /// Description of what this phase provides.
    pub description: String,
    /// Tools to install in this phase.
    pub entries: Vec<PlanEntry>,
}

/// Complete installation plan for user review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallPlan {
    /// Name of the detected distribution.
    pub distro_name: String,
    /// Package manager that will be used.
    pub package_manager: PackageManager,
    /// Ordered phases of installation.
    pub phases: Vec<InstallPhase>,
}

impl InstallPlan {
    /// Returns the total number of tools in the plan.
    pub fn total_tools(&self) -> usize {
        self.phases.iter().map(|p| p.entries.len()).sum()
    }

    /// Returns the number of tools available for the detected distribution.
    pub fn available_tools(&self) -> usize {
        self.phases
            .iter()
            .flat_map(|p| &p.entries)
            .filter(|e| e.available_for_distro)
            .count()
    }

    /// Returns the total estimated download size in bytes for available tools.
    pub fn total_estimated_size(&self) -> u64 {
        self.phases
            .iter()
            .flat_map(|p| &p.entries)
            .filter(|e| e.available_for_distro)
            .map(|e| e.estimated_size_bytes)
            .sum()
    }

    /// Formats the installation plan as a human-readable string for display.
    pub fn display_plan(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!(
            "═══ Installation Plan for {} ═══\n",
            self.distro_name
        ));
        output.push_str(&format!(
            "Package Manager: {}\n",
            self.package_manager
        ));
        output.push_str(&format!(
            "Tools: {} available / {} total\n",
            self.available_tools(),
            self.total_tools()
        ));

        let total_size = self.total_estimated_size();
        if total_size > 0 {
            output.push_str(&format!(
                "Estimated Download: {}\n",
                format_bytes(total_size)
            ));
        }

        output.push('\n');

        for (i, phase) in self.phases.iter().enumerate() {
            if phase.entries.is_empty() {
                continue;
            }

            output.push_str(&format!(
                "── Phase {} — {} ──\n",
                i + 1,
                phase.name
            ));
            output.push_str(&format!("   {}\n\n", phase.description));

            for entry in &phase.entries {
                let status = if entry.available_for_distro {
                    "✓"
                } else {
                    "✗"
                };

                let pkg_info = match &entry.package_name {
                    Some(pkg) => format!(" ({})", pkg),
                    None => " (no package mapping)".to_string(),
                };

                let size_info = if entry.estimated_size_bytes > 0 {
                    format!(" ~{}", format_bytes(entry.estimated_size_bytes))
                } else {
                    String::new()
                };

                output.push_str(&format!(
                    "   [{}] {}{}{}\n",
                    status, entry.display_name, pkg_info, size_info
                ));
            }

            output.push('\n');
        }

        output.push_str("═══════════════════════════════════════\n");
        output.push_str("Proceed with installation? [y/N] ");

        output
    }
}

/// Formats a byte count into a human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> InstallPlan {
        InstallPlan {
            distro_name: "Ubuntu 22.04".to_string(),
            package_manager: PackageManager::Apt,
            phases: vec![
                InstallPhase {
                    name: "Foundation (Visibility)".to_string(),
                    description: "Core visibility tools".to_string(),
                    entries: vec![
                        PlanEntry {
                            name: "osquery".to_string(),
                            display_name: "osquery".to_string(),
                            package_name: Some("osquery".to_string()),
                            estimated_size_bytes: 50 * 1024 * 1024,
                            available_for_distro: true,
                        },
                        PlanEntry {
                            name: "falco".to_string(),
                            display_name: "Falco".to_string(),
                            package_name: Some("falco".to_string()),
                            estimated_size_bytes: 30 * 1024 * 1024,
                            available_for_distro: true,
                        },
                    ],
                },
                InstallPhase {
                    name: "Detection".to_string(),
                    description: "Malware scanning tools".to_string(),
                    entries: vec![PlanEntry {
                        name: "clamav".to_string(),
                        display_name: "ClamAV".to_string(),
                        package_name: Some("clamav".to_string()),
                        estimated_size_bytes: 100 * 1024 * 1024,
                        available_for_distro: true,
                    }],
                },
                InstallPhase {
                    name: "Git Security".to_string(),
                    description: "Secrets scanning".to_string(),
                    entries: vec![PlanEntry {
                        name: "trufflehog".to_string(),
                        display_name: "TruffleHog".to_string(),
                        package_name: None,
                        estimated_size_bytes: 0,
                        available_for_distro: false,
                    }],
                },
            ],
        }
    }

    #[test]
    fn test_total_tools() {
        let plan = sample_plan();
        assert_eq!(plan.total_tools(), 4);
    }

    #[test]
    fn test_available_tools() {
        let plan = sample_plan();
        assert_eq!(plan.available_tools(), 3);
    }

    #[test]
    fn test_total_estimated_size() {
        let plan = sample_plan();
        // 50 MB + 30 MB + 100 MB = 180 MB (only available tools)
        assert_eq!(plan.total_estimated_size(), 180 * 1024 * 1024);
    }

    #[test]
    fn test_display_plan_contains_key_info() {
        let plan = sample_plan();
        let output = plan.display_plan();

        assert!(output.contains("Ubuntu 22.04"));
        assert!(output.contains("apt"));
        assert!(output.contains("3 available / 4 total"));
        assert!(output.contains("Phase 1"));
        assert!(output.contains("osquery"));
        assert!(output.contains("Falco"));
        assert!(output.contains("ClamAV"));
        assert!(output.contains("[✓]"));
        assert!(output.contains("[✗]"));
        assert!(output.contains("TruffleHog"));
        assert!(output.contains("Proceed with installation?"));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn test_empty_plan() {
        let plan = InstallPlan {
            distro_name: "Arch Linux".to_string(),
            package_manager: PackageManager::Pacman,
            phases: vec![],
        };
        assert_eq!(plan.total_tools(), 0);
        assert_eq!(plan.available_tools(), 0);
        assert_eq!(plan.total_estimated_size(), 0);
    }
}
