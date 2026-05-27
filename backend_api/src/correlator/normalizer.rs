// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Event normalization layer.
//!
//! Converts raw tool-specific events into [`NormalizedEvent`] instances.
//! All normalization must complete within 5 seconds of alert generation (SLA).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use shared::types::{Entity, NormalizedEvent, Severity, ToolSource};

/// Raw event data from a specific security tool before normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    /// Source tool identifier.
    pub source: ToolSource,
    /// Timestamp of the raw event.
    pub timestamp: DateTime<Utc>,
    /// Raw event payload as key-value pairs.
    pub fields: std::collections::HashMap<String, String>,
}

/// Event normalizer that converts tool-specific events into the common schema.
///
/// SLA: All normalization must complete within 5 seconds of alert generation.
pub struct EventNormalizer;

impl EventNormalizer {
    /// Creates a new `EventNormalizer`.
    pub fn new() -> Self {
        Self
    }

    /// Normalizes a raw event into the common [`NormalizedEvent`] format.
    ///
    /// Dispatches to the appropriate per-tool normalizer based on the source.
    pub fn normalize(&self, raw: &RawEvent) -> NormalizedEvent {
        match raw.source {
            ToolSource::Falco => self.normalize_falco(raw),
            ToolSource::Auditd => self.normalize_auditd(raw),
            ToolSource::OpenSnitch => self.normalize_opensnitch(raw),
            ToolSource::CrowdSec => self.normalize_crowdsec(raw),
            ToolSource::ClamAv => self.normalize_clamav(raw),
            ToolSource::Aide => self.normalize_aide(raw),
            ToolSource::Osquery => self.normalize_osquery(raw),
            _ => self.normalize_generic(raw),
        }
    }

    /// Normalizes a Falco event.
    ///
    /// Expected fields: `rule`, `priority`, `output`, `pid`, `process_name`, `container_id`.
    pub fn normalize_falco(&self, raw: &RawEvent) -> NormalizedEvent {
        let severity = self.map_falco_priority(
            raw.fields.get("priority").map(|s| s.as_str()).unwrap_or("notice"),
        );
        let summary = raw
            .fields
            .get("rule")
            .cloned()
            .unwrap_or_else(|| "Falco alert".to_string());
        let details = raw.fields.get("output").cloned();

        let mut entities = Vec::new();
        if let Some(pid_str) = raw.fields.get("pid") {
            if let Ok(pid) = pid_str.parse::<u32>() {
                entities.push(Entity::Process {
                    pid,
                    name: raw.fields.get("process_name").cloned(),
                });
            }
        }

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: raw.timestamp,
            source: ToolSource::Falco,
            severity,
            summary,
            details,
            entities,
            acknowledged: false,
            correlation_id: None,
        }
    }

    /// Normalizes an auditd event.
    ///
    /// Expected fields: `type`, `key`, `pid`, `uid`, `exe`, `success`.
    pub fn normalize_auditd(&self, raw: &RawEvent) -> NormalizedEvent {
        let audit_type = raw
            .fields
            .get("type")
            .cloned()
            .unwrap_or_else(|| "UNKNOWN".to_string());
        let severity = self.map_auditd_severity(&audit_type);
        let summary = format!(
            "Audit event: {}",
            raw.fields.get("key").unwrap_or(&audit_type)
        );
        let details = raw.fields.get("exe").cloned();

        let mut entities = Vec::new();
        if let Some(pid_str) = raw.fields.get("pid") {
            if let Ok(pid) = pid_str.parse::<u32>() {
                entities.push(Entity::Process {
                    pid,
                    name: raw.fields.get("exe").cloned(),
                });
            }
        }
        if let Some(uid_str) = raw.fields.get("uid") {
            if uid_str.parse::<u32>().is_ok() {
                entities.push(Entity::User {
                    name: raw
                        .fields
                        .get("user")
                        .cloned()
                        .unwrap_or_else(|| format!("uid:{}", uid_str)),
                    uid: uid_str.parse().ok(),
                });
            }
        }

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: raw.timestamp,
            source: ToolSource::Auditd,
            severity,
            summary,
            details,
            entities,
            acknowledged: false,
            correlation_id: None,
        }
    }

    /// Normalizes an OpenSnitch event.
    ///
    /// Expected fields: `action`, `process`, `pid`, `dst_host`, `dst_port`, `protocol`.
    pub fn normalize_opensnitch(&self, raw: &RawEvent) -> NormalizedEvent {
        let action = raw
            .fields
            .get("action")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let severity = if action == "deny" {
            Severity::Medium
        } else {
            Severity::Info
        };
        let process_name = raw
            .fields
            .get("process")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let dst = raw
            .fields
            .get("dst_host")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let summary = format!("Network connection {} by {} to {}", action, process_name, dst);

        let mut entities = Vec::new();
        if let Some(pid_str) = raw.fields.get("pid") {
            if let Ok(pid) = pid_str.parse::<u32>() {
                entities.push(Entity::Process {
                    pid,
                    name: Some(process_name.clone()),
                });
            }
        }
        if let Some(port_str) = raw.fields.get("dst_port") {
            entities.push(Entity::Network {
                address: dst.clone(),
                port: port_str.parse().ok(),
            });
        }

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: raw.timestamp,
            source: ToolSource::OpenSnitch,
            severity,
            summary,
            details: raw.fields.get("protocol").cloned(),
            entities,
            acknowledged: false,
            correlation_id: None,
        }
    }

    /// Normalizes a CrowdSec event.
    ///
    /// Expected fields: `scenario`, `source_ip`, `decisions_type`, `scope`.
    pub fn normalize_crowdsec(&self, raw: &RawEvent) -> NormalizedEvent {
        let scenario = raw
            .fields
            .get("scenario")
            .cloned()
            .unwrap_or_else(|| "Unknown scenario".to_string());
        let severity = self.map_crowdsec_severity(&scenario);
        let summary = format!("CrowdSec: {}", scenario);

        let mut entities = Vec::new();
        if let Some(ip) = raw.fields.get("source_ip") {
            entities.push(Entity::Network {
                address: ip.clone(),
                port: None,
            });
        }

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: raw.timestamp,
            source: ToolSource::CrowdSec,
            severity,
            summary,
            details: raw.fields.get("decisions_type").cloned(),
            entities,
            acknowledged: false,
            correlation_id: None,
        }
    }

    /// Normalizes a ClamAV event.
    ///
    /// Expected fields: `file_path`, `virus_name`, `action`.
    pub fn normalize_clamav(&self, raw: &RawEvent) -> NormalizedEvent {
        let virus_name = raw
            .fields
            .get("virus_name")
            .cloned()
            .unwrap_or_else(|| "Unknown malware".to_string());
        let file_path = raw
            .fields
            .get("file_path")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let summary = format!("Malware detected: {} in {}", virus_name, file_path);

        let entities = vec![Entity::File {
            path: file_path.clone(),
        }];

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: raw.timestamp,
            source: ToolSource::ClamAv,
            severity: Severity::High,
            summary,
            details: raw.fields.get("action").cloned(),
            entities,
            acknowledged: false,
            correlation_id: None,
        }
    }

    /// Normalizes an AIDE event.
    ///
    /// Expected fields: `file_path`, `change_type`, `attributes`.
    pub fn normalize_aide(&self, raw: &RawEvent) -> NormalizedEvent {
        let file_path = raw
            .fields
            .get("file_path")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let change_type = raw
            .fields
            .get("change_type")
            .cloned()
            .unwrap_or_else(|| "modified".to_string());
        let severity = self.map_aide_severity(&change_type);
        let summary = format!("File integrity: {} {}", file_path, change_type);

        let entities = vec![Entity::File {
            path: file_path.clone(),
        }];

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: raw.timestamp,
            source: ToolSource::Aide,
            severity,
            summary,
            details: raw.fields.get("attributes").cloned(),
            entities,
            acknowledged: false,
            correlation_id: None,
        }
    }

    /// Normalizes an osquery event.
    ///
    /// Expected fields: `name`, `action`, `columns`, `pid`, `path`.
    pub fn normalize_osquery(&self, raw: &RawEvent) -> NormalizedEvent {
        let query_name = raw
            .fields
            .get("name")
            .cloned()
            .unwrap_or_else(|| "osquery result".to_string());
        let action = raw
            .fields
            .get("action")
            .cloned()
            .unwrap_or_else(|| "added".to_string());
        let severity = if action == "added" {
            Severity::Low
        } else {
            Severity::Info
        };
        let summary = format!("osquery: {} ({})", query_name, action);

        let mut entities = Vec::new();
        if let Some(pid_str) = raw.fields.get("pid") {
            if let Ok(pid) = pid_str.parse::<u32>() {
                entities.push(Entity::Process {
                    pid,
                    name: raw.fields.get("path").cloned(),
                });
            }
        }
        if let Some(path) = raw.fields.get("path") {
            entities.push(Entity::File { path: path.clone() });
        }

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: raw.timestamp,
            source: ToolSource::Osquery,
            severity,
            summary,
            details: raw.fields.get("columns").cloned(),
            entities,
            acknowledged: false,
            correlation_id: None,
        }
    }

    /// Generic normalizer for tools without a specific handler.
    fn normalize_generic(&self, raw: &RawEvent) -> NormalizedEvent {
        let summary = raw
            .fields
            .get("summary")
            .cloned()
            .unwrap_or_else(|| format!("{:?} event", raw.source));

        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: raw.timestamp,
            source: raw.source.clone(),
            severity: Severity::Info,
            summary,
            details: raw.fields.get("details").cloned(),
            entities: Vec::new(),
            acknowledged: false,
            correlation_id: None,
        }
    }

    // --- Severity mapping helpers ---

    fn map_falco_priority(&self, priority: &str) -> Severity {
        match priority.to_lowercase().as_str() {
            "emergency" | "alert" | "critical" => Severity::Critical,
            "error" => Severity::High,
            "warning" => Severity::Medium,
            "notice" => Severity::Low,
            _ => Severity::Info,
        }
    }

    fn map_auditd_severity(&self, audit_type: &str) -> Severity {
        match audit_type {
            "EXECVE" | "SYSCALL" => Severity::Low,
            "AVC" | "SELINUX_ERR" => Severity::Medium,
            "ANOM_PROMISCUOUS" | "ANOM_LOGIN_FAILURES" => Severity::High,
            "INTEGRITY_RULE" => Severity::Critical,
            _ => Severity::Info,
        }
    }

    fn map_crowdsec_severity(&self, scenario: &str) -> Severity {
        let lower = scenario.to_lowercase();
        if lower.contains("brute") || lower.contains("exploit") {
            Severity::High
        } else if lower.contains("scan") || lower.contains("crawl") {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    fn map_aide_severity(&self, change_type: &str) -> Severity {
        match change_type {
            "added" => Severity::Low,
            "removed" => Severity::High,
            "modified" => Severity::Medium,
            _ => Severity::Info,
        }
    }
}

impl Default for EventNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw(source: ToolSource, fields: Vec<(&str, &str)>) -> RawEvent {
        RawEvent {
            source,
            timestamp: Utc::now(),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn test_normalize_falco_critical() {
        let normalizer = EventNormalizer::new();
        let raw = make_raw(
            ToolSource::Falco,
            vec![
                ("rule", "Terminal shell in container"),
                ("priority", "critical"),
                ("output", "shell spawned in container abc123"),
                ("pid", "1234"),
                ("process_name", "bash"),
            ],
        );
        let event = normalizer.normalize(&raw);
        assert_eq!(event.source, ToolSource::Falco);
        assert_eq!(event.severity, Severity::Critical);
        assert_eq!(event.summary, "Terminal shell in container");
        assert!(!event.entities.is_empty());
        match &event.entities[0] {
            Entity::Process { pid, name } => {
                assert_eq!(*pid, 1234);
                assert_eq!(name.as_deref(), Some("bash"));
            }
            _ => panic!("Expected Process entity"),
        }
    }

    #[test]
    fn test_normalize_auditd_with_user() {
        let normalizer = EventNormalizer::new();
        let raw = make_raw(
            ToolSource::Auditd,
            vec![
                ("type", "AVC"),
                ("key", "selinux_violation"),
                ("pid", "5678"),
                ("uid", "1000"),
                ("user", "testuser"),
                ("exe", "/usr/bin/test"),
            ],
        );
        let event = normalizer.normalize(&raw);
        assert_eq!(event.source, ToolSource::Auditd);
        assert_eq!(event.severity, Severity::Medium);
        assert!(event.summary.contains("selinux_violation"));
        assert_eq!(event.entities.len(), 2);
    }

    #[test]
    fn test_normalize_opensnitch_deny() {
        let normalizer = EventNormalizer::new();
        let raw = make_raw(
            ToolSource::OpenSnitch,
            vec![
                ("action", "deny"),
                ("process", "curl"),
                ("pid", "999"),
                ("dst_host", "192.168.1.100"),
                ("dst_port", "443"),
                ("protocol", "tcp"),
            ],
        );
        let event = normalizer.normalize(&raw);
        assert_eq!(event.severity, Severity::Medium);
        assert!(event.summary.contains("deny"));
        assert!(event.summary.contains("curl"));
        assert_eq!(event.entities.len(), 2);
    }

    #[test]
    fn test_normalize_clamav_detection() {
        let normalizer = EventNormalizer::new();
        let raw = make_raw(
            ToolSource::ClamAv,
            vec![
                ("file_path", "/tmp/malware.exe"),
                ("virus_name", "Trojan.Generic"),
                ("action", "quarantined"),
            ],
        );
        let event = normalizer.normalize(&raw);
        assert_eq!(event.severity, Severity::High);
        assert!(event.summary.contains("Trojan.Generic"));
        assert!(event.summary.contains("/tmp/malware.exe"));
        match &event.entities[0] {
            Entity::File { path } => assert_eq!(path, "/tmp/malware.exe"),
            _ => panic!("Expected File entity"),
        }
    }

    #[test]
    fn test_normalize_aide_file_removed() {
        let normalizer = EventNormalizer::new();
        let raw = make_raw(
            ToolSource::Aide,
            vec![
                ("file_path", "/etc/shadow"),
                ("change_type", "removed"),
                ("attributes", "permissions,size"),
            ],
        );
        let event = normalizer.normalize(&raw);
        assert_eq!(event.severity, Severity::High);
        assert!(event.summary.contains("/etc/shadow"));
        assert!(event.summary.contains("removed"));
    }

    #[test]
    fn test_normalize_crowdsec_brute_force() {
        let normalizer = EventNormalizer::new();
        let raw = make_raw(
            ToolSource::CrowdSec,
            vec![
                ("scenario", "crowdsecurity/ssh-brute-force"),
                ("source_ip", "10.0.0.1"),
                ("decisions_type", "ban"),
            ],
        );
        let event = normalizer.normalize(&raw);
        assert_eq!(event.severity, Severity::High);
        assert!(event.summary.contains("brute-force"));
        match &event.entities[0] {
            Entity::Network { address, .. } => assert_eq!(address, "10.0.0.1"),
            _ => panic!("Expected Network entity"),
        }
    }

    #[test]
    fn test_normalize_osquery_added() {
        let normalizer = EventNormalizer::new();
        let raw = make_raw(
            ToolSource::Osquery,
            vec![
                ("name", "new_processes"),
                ("action", "added"),
                ("pid", "42"),
                ("path", "/usr/bin/suspicious"),
            ],
        );
        let event = normalizer.normalize(&raw);
        assert_eq!(event.severity, Severity::Low);
        assert!(event.summary.contains("new_processes"));
        assert_eq!(event.entities.len(), 2); // Process + File
    }
}
