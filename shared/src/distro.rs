// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Distribution detection and package manager abstraction.
//!
//! Detects the Linux distribution by reading `/etc/os-release`, maps tool names
//! to distribution-specific package names, and provides a unified interface for
//! package management operations across apt, dnf, pacman, and zypper.

use std::collections::HashMap;
use std::fs;

use serde::{Deserialize, Serialize};

use crate::errors::{CommandCenterError, Result};

/// Supported package managers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageManager {
    /// Debian/Ubuntu package manager.
    Apt,
    /// Fedora/RHEL package manager.
    Dnf,
    /// Arch Linux package manager.
    Pacman,
    /// openSUSE package manager.
    Zypper,
}

/// Mandatory Access Control framework detected on the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MACFramework {
    /// AppArmor (Debian/Ubuntu/openSUSE default).
    AppArmor,
    /// SELinux (Fedora/RHEL default).
    SELinux,
    /// No MAC framework detected.
    None,
}

/// Information about the detected Linux distribution and system capabilities.
#[derive(Debug, Clone)]
pub struct DistroInfo {
    /// Distribution identifier from os-release (e.g., "ubuntu", "fedora").
    pub id: String,
    /// Version identifier from os-release (e.g., "22.04", "39").
    pub version_id: String,
    /// Human-readable distribution name.
    pub name: String,
    /// Detected package manager for this distribution.
    pub package_manager: PackageManager,
    /// Whether the root filesystem is on Btrfs.
    pub has_btrfs: bool,
    /// Kernel version as (major, minor).
    pub kernel_version: (u32, u32),
    /// Whether the kernel supports eBPF (>= 4.18).
    pub has_ebpf: bool,
    /// Detected MAC framework.
    pub mac_framework: MACFramework,
}

/// Trait abstracting distribution-specific package management operations.
pub trait DistroAdapter {
    /// Returns the package manager used by this distribution.
    fn package_manager(&self) -> PackageManager;

    /// Maps a security tool name to the distribution-specific package name.
    ///
    /// Returns `None` if the tool has no known package for this distribution.
    fn map_tool_package(&self, tool: &str) -> Option<String>;

    /// Installs a package using the distribution's package manager.
    fn install_package(&self, pkg: &str) -> Result<()>;

    /// Checks whether the root filesystem is on Btrfs.
    fn has_btrfs_root(&self) -> bool;
}

/// List of supported distribution IDs.
const SUPPORTED_DISTROS: &[&str] = &[
    "ubuntu", "debian", "linuxmint", "pop",
    "fedora", "rhel", "centos", "rocky", "alma",
    "arch", "manjaro", "endeavouros",
    "opensuse-tumbleweed", "opensuse-leap", "sles",
];

/// Detects the Linux distribution by reading `/etc/os-release`.
///
/// # Errors
///
/// Returns an error if `/etc/os-release` is missing, unreadable, or contains
/// an unrecognized distribution ID.
pub fn detect_distro() -> Result<DistroInfo> {
    detect_distro_from_path("/etc/os-release")
}

/// Internal detection function that accepts a custom path (for testing).
pub fn detect_distro_from_path(os_release_path: &str) -> Result<DistroInfo> {
    let content = fs::read_to_string(os_release_path).map_err(|e| {
        CommandCenterError::Configuration(format!(
            "Failed to read {}: {}. Cannot detect distribution.",
            os_release_path, e
        ))
    })?;

    detect_distro_from_content(&content)
}

/// Detects distribution info from the content of an os-release file.
///
/// This is the core parsing logic, separated for testability.
pub fn detect_distro_from_content(content: &str) -> Result<DistroInfo> {
    let fields = parse_os_release(content);

    let id = fields.get("ID").cloned().unwrap_or_default();
    let version_id = fields.get("VERSION_ID").cloned().unwrap_or_default();
    let name = fields
        .get("PRETTY_NAME")
        .or_else(|| fields.get("NAME"))
        .cloned()
        .unwrap_or_else(|| id.clone());

    if id.is_empty() {
        return Err(CommandCenterError::Configuration(format!(
            "No ID field found in os-release. Supported distributions: {}",
            SUPPORTED_DISTROS.join(", ")
        )));
    }

    let package_manager = match id_to_package_manager(&id) {
        Some(pm) => pm,
        None => {
            return Err(CommandCenterError::Configuration(format!(
                "Unrecognized distribution ID '{}' (version: '{}'). \
                 Supported distributions: {}",
                id,
                version_id,
                SUPPORTED_DISTROS.join(", ")
            )));
        }
    };

    let mac_framework = detect_mac_framework_for_id(&id);
    let has_btrfs = detect_btrfs();
    let kernel_version = detect_kernel_version();
    let has_ebpf = has_ebpf_support_from_version(kernel_version);

    Ok(DistroInfo {
        id,
        version_id,
        name,
        package_manager,
        has_btrfs,
        kernel_version,
        has_ebpf,
        mac_framework,
    })
}

/// Parses an os-release file into key-value pairs.
///
/// Handles both quoted and unquoted values, and strips surrounding quotes.
pub fn parse_os_release(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim();
            // Strip surrounding quotes (single or double)
            let value = if (value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\''))
            {
                value[1..value.len() - 1].to_string()
            } else {
                value.to_string()
            };
            map.insert(key, value);
        }
    }
    map
}

/// Maps a distribution ID to its package manager.
fn id_to_package_manager(id: &str) -> Option<PackageManager> {
    match id {
        "ubuntu" | "debian" | "linuxmint" | "pop" => Some(PackageManager::Apt),
        "fedora" | "rhel" | "centos" | "rocky" | "alma" => Some(PackageManager::Dnf),
        "arch" | "manjaro" | "endeavouros" => Some(PackageManager::Pacman),
        "opensuse-tumbleweed" | "opensuse-leap" | "sles" => Some(PackageManager::Zypper),
        _ => None,
    }
}

/// Determines the default MAC framework based on distribution ID.
fn detect_mac_framework_for_id(id: &str) -> MACFramework {
    match id {
        "fedora" | "rhel" | "centos" | "rocky" | "alma" => MACFramework::SELinux,
        "ubuntu" | "debian" | "linuxmint" | "pop" | "opensuse-tumbleweed"
        | "opensuse-leap" | "sles" => MACFramework::AppArmor,
        // Arch-based distros typically don't ship with a MAC framework enabled
        _ => MACFramework::None,
    }
}

/// Detects whether the root filesystem is on Btrfs by reading `/proc/mounts`.
pub fn detect_btrfs() -> bool {
    detect_btrfs_from_path("/proc/mounts")
}

/// Internal Btrfs detection from a custom path (for testing).
pub fn detect_btrfs_from_path(mounts_path: &str) -> bool {
    let content = match fs::read_to_string(mounts_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    detect_btrfs_from_content(&content)
}

/// Detects Btrfs root from mount file content.
pub fn detect_btrfs_from_content(content: &str) -> bool {
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // /proc/mounts format: device mountpoint fstype options dump pass
        if parts.len() >= 3 && parts[1] == "/" && parts[2] == "btrfs" {
            return true;
        }
    }
    false
}

/// Detects the kernel version by reading `/proc/version`.
///
/// Returns `(major, minor)`. Falls back to `(0, 0)` if detection fails.
pub fn detect_kernel_version() -> (u32, u32) {
    detect_kernel_version_from_path("/proc/version")
}

/// Internal kernel version detection from a custom path (for testing).
pub fn detect_kernel_version_from_path(version_path: &str) -> (u32, u32) {
    let content = match fs::read_to_string(version_path) {
        Ok(c) => c,
        Err(_) => return (0, 0),
    };
    parse_kernel_version(&content)
}

/// Parses a kernel version string to extract major.minor.
///
/// Expects a string like "Linux version 6.5.0-14-generic ..." and extracts (6, 5).
pub fn parse_kernel_version(content: &str) -> (u32, u32) {
    // Look for a version pattern: digits.digits
    for word in content.split_whitespace() {
        if let Some((major, rest)) = word.split_once('.') {
            if let Ok(major_num) = major.parse::<u32>() {
                // Extract minor: take digits before next dot or end
                let minor_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(minor_num) = minor_str.parse::<u32>() {
                    return (major_num, minor_num);
                }
            }
        }
    }
    (0, 0)
}

/// Checks if the kernel version supports eBPF (>= 4.18).
pub fn has_ebpf_support() -> bool {
    has_ebpf_support_from_version(detect_kernel_version())
}

/// Checks eBPF support from a given kernel version tuple.
pub fn has_ebpf_support_from_version(version: (u32, u32)) -> bool {
    let (major, minor) = version;
    major > 4 || (major == 4 && minor >= 18)
}

// ─── Concrete DistroAdapter Implementations ────────────────────────────────

/// Adapter for apt-based distributions (Debian, Ubuntu, Linux Mint, Pop!_OS).
pub struct AptAdapter;

/// Adapter for dnf-based distributions (Fedora, RHEL, CentOS, Rocky, Alma).
pub struct DnfAdapter;

/// Adapter for pacman-based distributions (Arch, Manjaro, EndeavourOS).
pub struct PacmanAdapter;

/// Adapter for zypper-based distributions (openSUSE, SLES).
pub struct ZypperAdapter;

/// Creates the appropriate `DistroAdapter` for the given package manager.
pub fn adapter_for(pm: PackageManager) -> Box<dyn DistroAdapter> {
    match pm {
        PackageManager::Apt => Box::new(AptAdapter),
        PackageManager::Dnf => Box::new(DnfAdapter),
        PackageManager::Pacman => Box::new(PacmanAdapter),
        PackageManager::Zypper => Box::new(ZypperAdapter),
    }
}

/// Returns the apt tool-to-package mapping.
fn apt_package_map() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("osquery", "osquery");
    m.insert("falco", "falco");
    m.insert("auditd", "auditd");
    m.insert("opensnitch", "opensnitch");
    m.insert("crowdsec", "crowdsec");
    m.insert("ufw", "ufw");
    m.insert("usbguard", "usbguard");
    m.insert("firejail", "firejail");
    m.insert("apparmor", "apparmor");
    m.insert("dnscrypt-proxy", "dnscrypt-proxy");
    m.insert("clamav", "clamav");
    m.insert("yara", "yara");
    m.insert("chkrootkit", "chkrootkit");
    m.insert("rkhunter", "rkhunter");
    m.insert("aide", "aide");
    m.insert("lynis", "lynis");
    m
}

/// Returns the dnf tool-to-package mapping.
fn dnf_package_map() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("osquery", "osquery");
    m.insert("falco", "falco");
    m.insert("auditd", "audit");
    m.insert("opensnitch", "opensnitch");
    m.insert("crowdsec", "crowdsec");
    m.insert("ufw", "ufw");
    m.insert("usbguard", "usbguard");
    m.insert("firejail", "firejail");
    m.insert("apparmor", "apparmor");
    m.insert("dnscrypt-proxy", "dnscrypt-proxy");
    m.insert("clamav", "clamav");
    m.insert("yara", "yara");
    m.insert("chkrootkit", "chkrootkit");
    m.insert("rkhunter", "rkhunter");
    m.insert("aide", "aide");
    m.insert("lynis", "lynis");
    m
}

/// Returns the pacman tool-to-package mapping.
fn pacman_package_map() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("osquery", "osquery");
    m.insert("falco", "falco");
    m.insert("auditd", "audit");
    m.insert("opensnitch", "opensnitch");
    m.insert("crowdsec", "crowdsec");
    m.insert("ufw", "ufw");
    m.insert("usbguard", "usbguard");
    m.insert("firejail", "firejail");
    m.insert("apparmor", "apparmor");
    m.insert("dnscrypt-proxy", "dnscrypt-proxy");
    m.insert("clamav", "clamav");
    m.insert("yara", "yara");
    m.insert("chkrootkit", "chkrootkit");
    m.insert("rkhunter", "rkhunter");
    m.insert("aide", "aide");
    m.insert("lynis", "lynis");
    m
}

/// Returns the zypper tool-to-package mapping.
fn zypper_package_map() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("osquery", "osquery");
    m.insert("falco", "falco");
    m.insert("auditd", "audit");
    m.insert("opensnitch", "opensnitch");
    m.insert("crowdsec", "crowdsec");
    m.insert("ufw", "ufw");
    m.insert("usbguard", "usbguard");
    m.insert("firejail", "firejail");
    m.insert("apparmor", "apparmor-utils");
    m.insert("dnscrypt-proxy", "dnscrypt-proxy");
    m.insert("clamav", "clamav");
    m.insert("yara", "yara");
    m.insert("chkrootkit", "chkrootkit");
    m.insert("rkhunter", "rkhunter");
    m.insert("aide", "aide");
    m.insert("lynis", "lynis");
    m
}

impl DistroAdapter for AptAdapter {
    fn package_manager(&self) -> PackageManager {
        PackageManager::Apt
    }

    fn map_tool_package(&self, tool: &str) -> Option<String> {
        apt_package_map().get(tool).map(|s| s.to_string())
    }

    fn install_package(&self, pkg: &str) -> Result<()> {
        let output = std::process::Command::new("apt-get")
            .args(["install", "-y", pkg])
            .output()
            .map_err(|e| CommandCenterError::Internal(format!(
                "Failed to execute apt-get: {}", e
            )))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(CommandCenterError::ToolOperationFailed {
                tool: pkg.to_string(),
                reason: format!("apt-get install failed: {}", stderr),
            })
        }
    }

    fn has_btrfs_root(&self) -> bool {
        detect_btrfs()
    }
}

impl DistroAdapter for DnfAdapter {
    fn package_manager(&self) -> PackageManager {
        PackageManager::Dnf
    }

    fn map_tool_package(&self, tool: &str) -> Option<String> {
        dnf_package_map().get(tool).map(|s| s.to_string())
    }

    fn install_package(&self, pkg: &str) -> Result<()> {
        let output = std::process::Command::new("dnf")
            .args(["install", "-y", pkg])
            .output()
            .map_err(|e| CommandCenterError::Internal(format!(
                "Failed to execute dnf: {}", e
            )))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(CommandCenterError::ToolOperationFailed {
                tool: pkg.to_string(),
                reason: format!("dnf install failed: {}", stderr),
            })
        }
    }

    fn has_btrfs_root(&self) -> bool {
        detect_btrfs()
    }
}

impl DistroAdapter for PacmanAdapter {
    fn package_manager(&self) -> PackageManager {
        PackageManager::Pacman
    }

    fn map_tool_package(&self, tool: &str) -> Option<String> {
        pacman_package_map().get(tool).map(|s| s.to_string())
    }

    fn install_package(&self, pkg: &str) -> Result<()> {
        let output = std::process::Command::new("pacman")
            .args(["-S", "--noconfirm", pkg])
            .output()
            .map_err(|e| CommandCenterError::Internal(format!(
                "Failed to execute pacman: {}", e
            )))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(CommandCenterError::ToolOperationFailed {
                tool: pkg.to_string(),
                reason: format!("pacman install failed: {}", stderr),
            })
        }
    }

    fn has_btrfs_root(&self) -> bool {
        detect_btrfs()
    }
}

impl DistroAdapter for ZypperAdapter {
    fn package_manager(&self) -> PackageManager {
        PackageManager::Zypper
    }

    fn map_tool_package(&self, tool: &str) -> Option<String> {
        zypper_package_map().get(tool).map(|s| s.to_string())
    }

    fn install_package(&self, pkg: &str) -> Result<()> {
        let output = std::process::Command::new("zypper")
            .args(["install", "-y", pkg])
            .output()
            .map_err(|e| CommandCenterError::Internal(format!(
                "Failed to execute zypper: {}", e
            )))?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(CommandCenterError::ToolOperationFailed {
                tool: pkg.to_string(),
                reason: format!("zypper install failed: {}", stderr),
            })
        }
    }

    fn has_btrfs_root(&self) -> bool {
        detect_btrfs()
    }
}

// ─── Display implementations ───────────────────────────────────────────────

impl std::fmt::Display for PackageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageManager::Apt => write!(f, "apt"),
            PackageManager::Dnf => write!(f, "dnf"),
            PackageManager::Pacman => write!(f, "pacman"),
            PackageManager::Zypper => write!(f, "zypper"),
        }
    }
}

impl std::fmt::Display for MACFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MACFramework::AppArmor => write!(f, "AppArmor"),
            MACFramework::SELinux => write!(f, "SELinux"),
            MACFramework::None => write!(f, "None"),
        }
    }
}

/// Returns the list of all supported tool names for package mapping.
pub fn supported_tools() -> &'static [&'static str] {
    &[
        "osquery", "falco", "auditd", "opensnitch", "crowdsec", "ufw",
        "usbguard", "firejail", "apparmor", "dnscrypt-proxy", "clamav",
        "yara", "chkrootkit", "rkhunter", "aide", "lynis",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_os_release_ubuntu() {
        let content = r#"
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
"#;
        let fields = parse_os_release(content);
        assert_eq!(fields.get("ID").unwrap(), "ubuntu");
        assert_eq!(fields.get("VERSION_ID").unwrap(), "22.04");
        assert_eq!(fields.get("PRETTY_NAME").unwrap(), "Ubuntu 22.04.3 LTS");
    }

    #[test]
    fn test_parse_os_release_fedora() {
        let content = r#"
NAME="Fedora Linux"
VERSION="39 (Workstation Edition)"
ID=fedora
VERSION_ID=39
PRETTY_NAME="Fedora Linux 39 (Workstation Edition)"
"#;
        let fields = parse_os_release(content);
        assert_eq!(fields.get("ID").unwrap(), "fedora");
        assert_eq!(fields.get("VERSION_ID").unwrap(), "39");
    }

    #[test]
    fn test_parse_os_release_arch() {
        let content = r#"
NAME="Arch Linux"
ID=arch
PRETTY_NAME="Arch Linux"
"#;
        let fields = parse_os_release(content);
        assert_eq!(fields.get("ID").unwrap(), "arch");
        // Arch doesn't have VERSION_ID
        assert!(fields.get("VERSION_ID").is_none());
    }

    #[test]
    fn test_detect_distro_ubuntu() {
        let content = r#"
NAME="Ubuntu"
ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04.3 LTS"
"#;
        let info = detect_distro_from_content(content).unwrap();
        assert_eq!(info.id, "ubuntu");
        assert_eq!(info.version_id, "22.04");
        assert_eq!(info.package_manager, PackageManager::Apt);
        assert_eq!(info.mac_framework, MACFramework::AppArmor);
    }

    #[test]
    fn test_detect_distro_fedora() {
        let content = "ID=fedora\nVERSION_ID=39\nNAME=\"Fedora Linux\"\n";
        let info = detect_distro_from_content(content).unwrap();
        assert_eq!(info.id, "fedora");
        assert_eq!(info.version_id, "39");
        assert_eq!(info.package_manager, PackageManager::Dnf);
        assert_eq!(info.mac_framework, MACFramework::SELinux);
    }

    #[test]
    fn test_detect_distro_arch() {
        let content = "ID=arch\nNAME=\"Arch Linux\"\n";
        let info = detect_distro_from_content(content).unwrap();
        assert_eq!(info.id, "arch");
        assert_eq!(info.version_id, "");
        assert_eq!(info.package_manager, PackageManager::Pacman);
        assert_eq!(info.mac_framework, MACFramework::None);
    }

    #[test]
    fn test_detect_distro_opensuse() {
        let content = "ID=opensuse-tumbleweed\nVERSION_ID=\"20231201\"\n";
        let info = detect_distro_from_content(content).unwrap();
        assert_eq!(info.id, "opensuse-tumbleweed");
        assert_eq!(info.package_manager, PackageManager::Zypper);
        assert_eq!(info.mac_framework, MACFramework::AppArmor);
    }

    #[test]
    fn test_detect_distro_missing_id() {
        let content = "NAME=\"Some Linux\"\nVERSION_ID=\"1.0\"\n";
        let result = detect_distro_from_content(content);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("No ID field"));
    }

    #[test]
    fn test_detect_distro_unrecognized_id() {
        let content = "ID=unknownlinux\nVERSION_ID=\"1.0\"\n";
        let result = detect_distro_from_content(content);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Unrecognized distribution ID"));
        assert!(err_msg.contains("unknownlinux"));
        assert!(err_msg.contains("Supported distributions"));
    }

    #[test]
    fn test_detect_btrfs_present() {
        let content = "/dev/sda1 / btrfs rw,relatime 0 0\n/dev/sda2 /home ext4 rw 0 0\n";
        assert!(detect_btrfs_from_content(content));
    }

    #[test]
    fn test_detect_btrfs_absent() {
        let content = "/dev/sda1 / ext4 rw,relatime 0 0\n/dev/sda2 /home ext4 rw 0 0\n";
        assert!(!detect_btrfs_from_content(content));
    }

    #[test]
    fn test_detect_btrfs_non_root() {
        // Btrfs on /home but not on /
        let content = "/dev/sda1 / ext4 rw 0 0\n/dev/sda2 /home btrfs rw 0 0\n";
        assert!(!detect_btrfs_from_content(content));
    }

    #[test]
    fn test_parse_kernel_version_standard() {
        let content = "Linux version 6.5.0-14-generic (buildd@lcy02-amd64-116)";
        assert_eq!(parse_kernel_version(content), (6, 5));
    }

    #[test]
    fn test_parse_kernel_version_old() {
        let content = "Linux version 4.18.0-513.el8.x86_64";
        assert_eq!(parse_kernel_version(content), (4, 18));
    }

    #[test]
    fn test_parse_kernel_version_very_old() {
        let content = "Linux version 4.17.0-rc1";
        assert_eq!(parse_kernel_version(content), (4, 17));
    }

    #[test]
    fn test_parse_kernel_version_empty() {
        assert_eq!(parse_kernel_version(""), (0, 0));
    }

    #[test]
    fn test_has_ebpf_support_new_kernel() {
        assert!(has_ebpf_support_from_version((6, 5)));
        assert!(has_ebpf_support_from_version((5, 0)));
        assert!(has_ebpf_support_from_version((4, 18)));
    }

    #[test]
    fn test_has_ebpf_support_old_kernel() {
        assert!(!has_ebpf_support_from_version((4, 17)));
        assert!(!has_ebpf_support_from_version((3, 10)));
        assert!(!has_ebpf_support_from_version((0, 0)));
    }

    #[test]
    fn test_apt_tool_mapping() {
        let adapter = AptAdapter;
        assert_eq!(adapter.map_tool_package("clamav"), Some("clamav".to_string()));
        assert_eq!(adapter.map_tool_package("auditd"), Some("auditd".to_string()));
        assert_eq!(adapter.map_tool_package("nonexistent"), None);
    }

    #[test]
    fn test_dnf_tool_mapping() {
        let adapter = DnfAdapter;
        assert_eq!(adapter.map_tool_package("auditd"), Some("audit".to_string()));
        assert_eq!(adapter.map_tool_package("clamav"), Some("clamav".to_string()));
        assert_eq!(adapter.map_tool_package("nonexistent"), None);
    }

    #[test]
    fn test_pacman_tool_mapping() {
        let adapter = PacmanAdapter;
        assert_eq!(adapter.map_tool_package("auditd"), Some("audit".to_string()));
        assert_eq!(adapter.map_tool_package("lynis"), Some("lynis".to_string()));
        assert_eq!(adapter.map_tool_package("nonexistent"), None);
    }

    #[test]
    fn test_zypper_tool_mapping() {
        let adapter = ZypperAdapter;
        assert_eq!(adapter.map_tool_package("apparmor"), Some("apparmor-utils".to_string()));
        assert_eq!(adapter.map_tool_package("auditd"), Some("audit".to_string()));
        assert_eq!(adapter.map_tool_package("nonexistent"), None);
    }

    #[test]
    fn test_adapter_for_creates_correct_adapter() {
        let apt = adapter_for(PackageManager::Apt);
        assert_eq!(apt.package_manager(), PackageManager::Apt);

        let dnf = adapter_for(PackageManager::Dnf);
        assert_eq!(dnf.package_manager(), PackageManager::Dnf);

        let pacman = adapter_for(PackageManager::Pacman);
        assert_eq!(pacman.package_manager(), PackageManager::Pacman);

        let zypper = adapter_for(PackageManager::Zypper);
        assert_eq!(zypper.package_manager(), PackageManager::Zypper);
    }

    #[test]
    fn test_all_supported_tools_have_apt_mapping() {
        let adapter = AptAdapter;
        for tool in supported_tools() {
            assert!(
                adapter.map_tool_package(tool).is_some(),
                "Tool '{}' has no apt mapping",
                tool
            );
        }
    }

    #[test]
    fn test_parse_os_release_comments_and_empty_lines() {
        let content = "# This is a comment\n\nID=ubuntu\n# Another comment\nVERSION_ID=\"22.04\"\n";
        let fields = parse_os_release(content);
        assert_eq!(fields.get("ID").unwrap(), "ubuntu");
        assert_eq!(fields.get("VERSION_ID").unwrap(), "22.04");
    }

    #[test]
    fn test_package_manager_display() {
        assert_eq!(format!("{}", PackageManager::Apt), "apt");
        assert_eq!(format!("{}", PackageManager::Dnf), "dnf");
        assert_eq!(format!("{}", PackageManager::Pacman), "pacman");
        assert_eq!(format!("{}", PackageManager::Zypper), "zypper");
    }
}
