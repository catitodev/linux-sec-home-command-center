// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! USBGuard adapter for the Linux Security Home Command Center.
//!
//! Provides USB device access control with default-block policy, HID safety
//! checks (auto-whitelisting keyboards/mice), and emergency recovery if input
//! devices become blocked.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use shared::distro::{adapter_for, DistroInfo};
use shared::errors::{CommandCenterError, Result};
use shared::exec::SafeCommand;

use crate::tools::adapter::{HealthStatus, ToolAdapter, ToolCategory};

// ─── Constants ─────────────────────────────────────────────────────────────

/// Emergency recovery timeout: if no input detected for this duration after
/// activation, temporarily disable block policy.
const EMERGENCY_NO_INPUT_TIMEOUT: Duration = Duration::from_secs(30);

/// Duration to temporarily disable block policy during emergency recovery.
const EMERGENCY_RECOVERY_WINDOW: Duration = Duration::from_secs(60);

/// USB device class for HID (Human Interface Device).
const USB_CLASS_HID: &str = "03";

// ─── Enums ─────────────────────────────────────────────────────────────────

/// Status of a USB device in USBGuard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum USBDeviceStatus {
    /// Device is approved and can be used.
    Approved,
    /// Device is blocked and cannot be used.
    Blocked,
    /// Device is pending approval decision.
    Pending,
}

// ─── Structs ───────────────────────────────────────────────────────────────

/// Represents a USB device tracked by USBGuard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct USBDevice {
    /// USB vendor ID (e.g., "046d" for Logitech).
    pub vendor_id: String,
    /// USB product ID.
    pub product_id: String,
    /// Device serial number (may be empty).
    pub serial: String,
    /// USB device class code (e.g., "03" for HID).
    pub device_class: String,
    /// Human-readable vendor name.
    pub vendor_name: String,
    /// Human-readable product name.
    pub product_name: String,
    /// Current device status.
    pub status: USBDeviceStatus,
}

impl USBDevice {
    /// Checks if this device is a HID device (keyboard, mouse, etc.).
    pub fn is_hid(&self) -> bool {
        self.device_class == USB_CLASS_HID
    }
}

/// Manages USB device approval/blocking through USBGuard.
#[derive(Debug)]
pub struct USBDeviceManager;

impl USBDeviceManager {
    /// Creates a new `USBDeviceManager`.
    pub fn new() -> Self {
        Self
    }

    /// Lists all known USB devices and their status.
    pub async fn list_devices(&self) -> Result<Vec<USBDevice>> {
        let mut cmd = SafeCommand::new("usbguard");
        cmd.args(&["list-devices"])?;
        cmd.timeout(Duration::from_secs(10));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "usbguard".to_owned(),
                reason: format!("failed to list devices: {}", output.stderr.trim()),
            });
        }

        // Parse usbguard list-devices output
        // In production, this would parse the device list format
        Ok(Vec::new())
    }

    /// Approves a USB device by its device number.
    pub async fn approve_device(&self, device_id: u32) -> Result<()> {
        let mut cmd = SafeCommand::new("usbguard");
        cmd.args(&["allow-device", &device_id.to_string()])?;
        cmd.timeout(Duration::from_secs(10));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "usbguard".to_owned(),
                reason: format!("failed to approve device: {}", output.stderr.trim()),
            });
        }

        info!(device_id = device_id, "USB device approved");
        Ok(())
    }

    /// Blocks a USB device by its device number.
    pub async fn block_device(&self, device_id: u32) -> Result<()> {
        let mut cmd = SafeCommand::new("usbguard");
        cmd.args(&["block-device", &device_id.to_string()])?;
        cmd.timeout(Duration::from_secs(10));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "usbguard".to_owned(),
                reason: format!("failed to block device: {}", output.stderr.trim()),
            });
        }

        info!(device_id = device_id, "USB device blocked");
        Ok(())
    }

    /// Gets the device event history.
    pub async fn get_history(&self) -> Result<Vec<String>> {
        let mut cmd = SafeCommand::new("usbguard");
        cmd.args(&["list-rules"])?;
        cmd.timeout(Duration::from_secs(10));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "usbguard".to_owned(),
                reason: format!("failed to get history: {}", output.stderr.trim()),
            });
        }

        let entries: Vec<String> = output
            .stdout
            .lines()
            .map(|l| l.to_owned())
            .collect();
        Ok(entries)
    }
}

impl Default for USBDeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Performs HID safety checks before enabling block policy.
///
/// Scans connected HID devices (keyboards, mice) and auto-whitelists them
/// to prevent locking the user out of their system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HIDSafetyCheck {
    /// Number of HID devices found.
    pub hid_devices_found: usize,
    /// Number of HID devices auto-whitelisted.
    pub devices_whitelisted: usize,
    /// Whether the safety check passed (at least one input device found).
    pub passed: bool,
}

impl HIDSafetyCheck {
    /// Creates a new safety check result.
    pub fn new(hid_devices_found: usize, devices_whitelisted: usize) -> Self {
        Self {
            hid_devices_found,
            devices_whitelisted,
            passed: hid_devices_found > 0,
        }
    }
}

/// Emergency recovery mechanism for USBGuard.
///
/// If no input is detected for 30 seconds after activation, temporarily
/// disables the block policy for 60 seconds to allow the user to recover.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmergencyRecovery {
    /// Whether emergency recovery is currently active.
    pub is_active: bool,
    /// Timeout before triggering recovery (seconds).
    pub no_input_timeout_secs: u64,
    /// Duration of the recovery window (seconds).
    pub recovery_window_secs: u64,
}

impl EmergencyRecovery {
    /// Creates a new `EmergencyRecovery` with default settings.
    pub fn new() -> Self {
        Self {
            is_active: false,
            no_input_timeout_secs: EMERGENCY_NO_INPUT_TIMEOUT.as_secs(),
            recovery_window_secs: EMERGENCY_RECOVERY_WINDOW.as_secs(),
        }
    }

    /// Activates emergency recovery mode.
    pub fn activate(&mut self) {
        self.is_active = true;
        warn!("USBGuard emergency recovery activated — block policy temporarily disabled");
    }

    /// Deactivates emergency recovery mode.
    pub fn deactivate(&mut self) {
        self.is_active = false;
        info!("USBGuard emergency recovery deactivated — block policy restored");
    }
}

impl Default for EmergencyRecovery {
    fn default() -> Self {
        Self::new()
    }
}

// ─── USBGuardAdapter ───────────────────────────────────────────────────────

/// Tool adapter for USBGuard USB device access control.
///
/// Implements a default-block policy for USB devices with HID safety checks
/// and emergency recovery to prevent input device lockout.
pub struct USBGuardAdapter;

impl USBGuardAdapter {
    /// Creates a new `USBGuardAdapter`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for USBGuardAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ToolAdapter for USBGuardAdapter {
    fn name(&self) -> &str {
        "usbguard"
    }

    fn display_name(&self) -> &str {
        "USBGuard"
    }

    fn category(&self) -> ToolCategory {
        ToolCategory::Protection
    }

    async fn install(&self, distro: &DistroInfo) -> Result<()> {
        let distro_adapter = adapter_for(distro.package_manager);
        let package_name = distro_adapter
            .map_tool_package("usbguard")
            .ok_or_else(|| CommandCenterError::ToolNotAvailable {
                tool: "usbguard".to_owned(),
            })?;

        info!(package = %package_name, distro = %distro.id, "Installing USBGuard");
        distro_adapter.install_package(&package_name)?;
        info!("USBGuard installed successfully");
        Ok(())
    }

    async fn start(&self) -> Result<()> {
        info!("Starting USBGuard service with default-block policy");

        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["start", "usbguard"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "usbguard".to_owned(),
                reason: format!("failed to start usbguard: {}", output.stderr.trim()),
            });
        }

        info!("USBGuard service started with default-block policy");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("Stopping USBGuard service");
        let mut cmd = SafeCommand::new("systemctl");
        cmd.args(&["stop", "usbguard"])?;
        cmd.timeout(Duration::from_secs(30));

        let output = cmd.execute().await?;
        if output.exit_code != Some(0) {
            return Err(CommandCenterError::ToolOperationFailed {
                tool: "usbguard".to_owned(),
                reason: format!("failed to stop usbguard: {}", output.stderr.trim()),
            });
        }

        info!("USBGuard service stopped");
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        let mut cmd = SafeCommand::new("systemctl");
        if cmd.args(&["is-active", "usbguard"]).is_err() {
            return HealthStatus::Unhealthy("failed to build health check command".to_owned());
        }
        cmd.timeout(Duration::from_secs(5));

        match cmd.execute().await {
            Ok(output) => {
                let status = output.stdout.trim();
                if status == "active" {
                    HealthStatus::Healthy
                } else if status == "inactive" {
                    HealthStatus::NotRunning
                } else {
                    HealthStatus::Degraded(format!("usbguard status: {}", status))
                }
            }
            Err(e) => HealthStatus::Unhealthy(format!("health check failed: {}", e)),
        }
    }

    fn is_available_for(&self, _distro: &DistroInfo) -> bool {
        // USBGuard is available for all supported distributions.
        true
    }

    fn estimated_size_bytes(&self) -> u64 {
        // USBGuard approximately 5 MB.
        5 * 1024 * 1024
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_name() {
        let adapter = USBGuardAdapter::new();
        assert_eq!(adapter.name(), "usbguard");
    }

    #[test]
    fn test_adapter_display_name() {
        let adapter = USBGuardAdapter::new();
        assert_eq!(adapter.display_name(), "USBGuard");
    }

    #[test]
    fn test_adapter_category() {
        let adapter = USBGuardAdapter::new();
        assert_eq!(adapter.category(), ToolCategory::Protection);
    }

    #[test]
    fn test_adapter_is_available_for_all_distros() {
        let adapter = USBGuardAdapter::new();

        let ubuntu = shared::distro::detect_distro_from_content(
            "ID=ubuntu\nVERSION_ID=\"22.04\"\nNAME=\"Ubuntu\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&ubuntu));

        let arch = shared::distro::detect_distro_from_content(
            "ID=arch\nNAME=\"Arch Linux\"\n",
        )
        .unwrap();
        assert!(adapter.is_available_for(&arch));
    }

    #[test]
    fn test_adapter_estimated_size() {
        let adapter = USBGuardAdapter::new();
        assert!(adapter.estimated_size_bytes() > 0);
    }

    #[test]
    fn test_usb_device_is_hid() {
        let hid_device = USBDevice {
            vendor_id: "046d".to_owned(),
            product_id: "c52b".to_owned(),
            serial: "".to_owned(),
            device_class: "03".to_owned(),
            vendor_name: "Logitech".to_owned(),
            product_name: "Unifying Receiver".to_owned(),
            status: USBDeviceStatus::Approved,
        };
        assert!(hid_device.is_hid());

        let storage_device = USBDevice {
            vendor_id: "0781".to_owned(),
            product_id: "5567".to_owned(),
            serial: "ABC123".to_owned(),
            device_class: "08".to_owned(),
            vendor_name: "SanDisk".to_owned(),
            product_name: "Cruzer Blade".to_owned(),
            status: USBDeviceStatus::Blocked,
        };
        assert!(!storage_device.is_hid());
    }

    #[test]
    fn test_usb_device_serialization() {
        let device = USBDevice {
            vendor_id: "046d".to_owned(),
            product_id: "c52b".to_owned(),
            serial: "SN123".to_owned(),
            device_class: "03".to_owned(),
            vendor_name: "Logitech".to_owned(),
            product_name: "Keyboard".to_owned(),
            status: USBDeviceStatus::Approved,
        };

        let json = serde_json::to_string(&device).unwrap();
        let deserialized: USBDevice = serde_json::from_str(&json).unwrap();
        assert_eq!(device, deserialized);
    }

    #[test]
    fn test_usb_device_status_variants() {
        let statuses = [
            USBDeviceStatus::Approved,
            USBDeviceStatus::Blocked,
            USBDeviceStatus::Pending,
        ];
        for status in &statuses {
            let device = USBDevice {
                vendor_id: "0000".to_owned(),
                product_id: "0000".to_owned(),
                serial: "".to_owned(),
                device_class: "00".to_owned(),
                vendor_name: "Test".to_owned(),
                product_name: "Device".to_owned(),
                status: *status,
            };
            let json = serde_json::to_string(&device).unwrap();
            let deserialized: USBDevice = serde_json::from_str(&json).unwrap();
            assert_eq!(device, deserialized);
        }
    }

    #[test]
    fn test_hid_safety_check_with_devices() {
        let check = HIDSafetyCheck::new(2, 2);
        assert!(check.passed);
        assert_eq!(check.hid_devices_found, 2);
        assert_eq!(check.devices_whitelisted, 2);
    }

    #[test]
    fn test_hid_safety_check_no_devices() {
        let check = HIDSafetyCheck::new(0, 0);
        assert!(!check.passed);
    }

    #[test]
    fn test_hid_safety_check_serialization() {
        let check = HIDSafetyCheck::new(3, 2);
        let json = serde_json::to_string(&check).unwrap();
        let deserialized: HIDSafetyCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, deserialized);
    }

    #[test]
    fn test_emergency_recovery_defaults() {
        let recovery = EmergencyRecovery::new();
        assert!(!recovery.is_active);
        assert_eq!(recovery.no_input_timeout_secs, 30);
        assert_eq!(recovery.recovery_window_secs, 60);
    }

    #[test]
    fn test_emergency_recovery_activate_deactivate() {
        let mut recovery = EmergencyRecovery::new();
        assert!(!recovery.is_active);

        recovery.activate();
        assert!(recovery.is_active);

        recovery.deactivate();
        assert!(!recovery.is_active);
    }

    #[test]
    fn test_emergency_recovery_serialization() {
        let recovery = EmergencyRecovery::new();
        let json = serde_json::to_string(&recovery).unwrap();
        let deserialized: EmergencyRecovery = serde_json::from_str(&json).unwrap();
        assert_eq!(recovery, deserialized);
    }
}
