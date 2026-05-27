// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Event Correlation Engine with sliding window analysis.
//!
//! Correlates normalized events from multiple security tools using:
//! - A 24-hour sliding window with FIFO eviction for historical context
//! - 60-second grouping windows per entity for multi-tool correlation
//! - Confidence scoring based on contributing tool count vs active tools
//! - Severity scoring based on maximum severities from contributing tools

use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use shared::types::{Entity, NormalizedEvent, Severity, ToolSource};

/// Key used to group events by entity for correlation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityKey {
    /// Process identified by PID.
    Pid(u32),
    /// Network address (IP).
    Ip(String),
    /// File path.
    FilePath(String),
    /// User name.
    User(String),
}

/// A 60-second correlation window grouping events for a single entity.
#[derive(Debug, Clone)]
pub struct CorrelationWindow {
    /// The entity key this window tracks.
    pub entity_key: EntityKey,
    /// Events within this window.
    pub events: Vec<NormalizedEvent>,
    /// Set of tools that contributed events to this window.
    pub tools_involved: HashSet<ToolSource>,
    /// Start of the correlation window.
    pub window_start: DateTime<Utc>,
    /// End of the correlation window (start + 60 seconds).
    pub window_end: DateTime<Utc>,
}

impl CorrelationWindow {
    /// Creates a new correlation window starting at the given timestamp.
    fn new(entity_key: EntityKey, start: DateTime<Utc>) -> Self {
        Self {
            entity_key,
            events: Vec::new(),
            tools_involved: HashSet::new(),
            window_start: start,
            window_end: start + Duration::seconds(60),
        }
    }

    /// Returns true if the given timestamp falls within this window.
    fn contains(&self, timestamp: &DateTime<Utc>) -> bool {
        *timestamp >= self.window_start && *timestamp <= self.window_end
    }

    /// Adds an event to this window.
    fn add_event(&mut self, event: &NormalizedEvent) {
        self.tools_involved.insert(event.source.clone());
        self.events.push(event.clone());
    }
}

/// Status of a correlated incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Newly created, not yet reviewed.
    Open,
    /// Currently being investigated.
    Investigating,
    /// Resolved by operator or automation.
    Resolved,
    /// Dismissed as false positive.
    Dismissed,
}

/// A correlated security incident combining events from multiple tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedIncident {
    /// Unique incident identifier.
    pub id: Uuid,
    /// When the incident was created.
    pub created_at: DateTime<Utc>,
    /// Severity score from 1 (lowest) to 10 (highest).
    pub severity_score: u8,
    /// Confidence score from 0.0 to 1.0.
    pub confidence_score: f64,
    /// Number of tools that contributed events.
    pub contributing_tool_count: usize,
    /// Current status of the incident.
    pub status: IncidentStatus,
    /// Events that contributed to this incident.
    pub contributing_events: Vec<NormalizedEvent>,
    /// Human-readable summary of the incident.
    pub summary: String,
}

/// The correlation engine that processes normalized events.
pub struct CorrelationEngine {
    /// 24-hour sliding window of all events (FIFO eviction).
    pub event_window: VecDeque<NormalizedEvent>,
    /// Active 60-second correlation windows per entity.
    pub active_windows: HashMap<EntityKey, CorrelationWindow>,
    /// Number of currently active (reporting) tools.
    pub active_tool_count: usize,
}

impl CorrelationEngine {
    /// Creates a new correlation engine.
    ///
    /// # Arguments
    /// * `active_tool_count` - Number of currently active security tools.
    pub fn new(active_tool_count: usize) -> Self {
        Self {
            event_window: VecDeque::new(),
            active_windows: HashMap::new(),
            active_tool_count: active_tool_count.max(1), // Avoid division by zero
        }
    }

    /// Ingests a normalized event and returns a correlated incident if correlation
    /// criteria are met (2+ tools contributing within a 60-second window).
    ///
    /// Steps:
    /// 1. Evict events older than 24 hours from the sliding window
    /// 2. Add event to the 24-hour window
    /// 3. Extract entity key from the event
    /// 4. Find or create a 60-second correlation window for the entity
    /// 5. If 2+ tools contribute → create a correlated incident
    /// 6. Standalone events get confidence = 1/active_tools
    pub fn ingest(&mut self, event: NormalizedEvent) -> Option<CorrelatedIncident> {
        // Step 1: FIFO eviction of events older than 24 hours
        self.evict_old_events(event.timestamp);

        // Step 2: Add to 24-hour window
        self.event_window.push_back(event.clone());

        // Step 3: Extract entity key
        let entity_key = match self.extract_entity_key(&event) {
            Some(key) => key,
            None => return None, // No entity to correlate on
        };

        // Step 4: Find or create correlation window
        let window = self
            .active_windows
            .entry(entity_key.clone())
            .or_insert_with(|| CorrelationWindow::new(entity_key.clone(), event.timestamp));

        // Check if event falls within the existing window
        if window.contains(&event.timestamp) {
            window.add_event(&event);
        } else {
            // Window expired, create a new one
            let new_window = CorrelationWindow::new(entity_key.clone(), event.timestamp);
            *window = new_window;
            window.add_event(&event);
        }

        // Step 5: Check if correlation threshold is met
        let tools_count = window.tools_involved.len();
        if tools_count >= 2 {
            // Remove the window and create incident from the owned value
            let window = self.active_windows.remove(&entity_key).unwrap();
            let incident = self.create_incident(&window);
            Some(incident)
        } else {
            None
        }
    }

    /// Creates a correlated incident from a correlation window.
    fn create_incident(&self, window: &CorrelationWindow) -> CorrelatedIncident {
        let contributing_tool_count = window.tools_involved.len();
        let confidence_score =
            contributing_tool_count as f64 / self.active_tool_count as f64;
        let severity_score = self.calculate_severity(&window.events, contributing_tool_count);

        let tool_names: Vec<String> = window
            .tools_involved
            .iter()
            .map(|t| format!("{:?}", t))
            .collect();
        let summary = format!(
            "Correlated incident: {} tools ({}) detected activity on {:?}",
            contributing_tool_count,
            tool_names.join(", "),
            window.entity_key
        );

        CorrelatedIncident {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            severity_score,
            confidence_score: confidence_score.min(1.0),
            contributing_tool_count,
            status: IncidentStatus::Open,
            contributing_events: window.events.clone(),
            summary,
        }
    }

    /// Calculates severity score: (sum_of_max_severities / (tool_count × 10)) × 10,
    /// rounded and clamped to 1-10.
    fn calculate_severity(&self, events: &[NormalizedEvent], tool_count: usize) -> u8 {
        if events.is_empty() || tool_count == 0 {
            return 1;
        }

        // Get max severity per tool
        let mut max_per_tool: HashMap<&ToolSource, u8> = HashMap::new();
        for event in events {
            let numeric = self.severity_to_numeric(&event.severity);
            let entry = max_per_tool.entry(&event.source).or_insert(0);
            if numeric > *entry {
                *entry = numeric;
            }
        }

        let sum_of_max: u32 = max_per_tool.values().map(|&v| v as u32).sum();
        let denominator = tool_count as u32 * 10;
        let raw_score = ((sum_of_max as f64 / denominator as f64) * 10.0).round() as u8;

        raw_score.clamp(1, 10)
    }

    /// Maps a Severity enum to a numeric value (1-10).
    fn severity_to_numeric(&self, severity: &Severity) -> u8 {
        match severity {
            Severity::Info => 2,
            Severity::Low => 4,
            Severity::Medium => 6,
            Severity::High => 8,
            Severity::Critical => 10,
        }
    }

    /// Extracts an entity key from the first entity in the event.
    fn extract_entity_key(&self, event: &NormalizedEvent) -> Option<EntityKey> {
        event.entities.first().map(|entity| match entity {
            Entity::Process { pid, .. } => EntityKey::Pid(*pid),
            Entity::Network { address, .. } => EntityKey::Ip(address.clone()),
            Entity::File { path } => EntityKey::FilePath(path.clone()),
            Entity::User { name, .. } => EntityKey::User(name.clone()),
            Entity::UsbDevice { device_id, .. } => EntityKey::FilePath(device_id.clone()),
        })
    }

    /// Evicts events older than 24 hours from the sliding window.
    fn evict_old_events(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::hours(24);
        while let Some(front) = self.event_window.front() {
            if front.timestamp < cutoff {
                self.event_window.pop_front();
            } else {
                break;
            }
        }

        // Also clean up expired correlation windows
        self.active_windows
            .retain(|_, w| w.window_end > now - Duration::seconds(60));
    }

    /// Returns the confidence score for a standalone event (no correlation).
    pub fn standalone_confidence(&self) -> f64 {
        1.0 / self.active_tool_count as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(source: ToolSource, severity: Severity, entity: Entity) -> NormalizedEvent {
        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source,
            severity,
            summary: "Test event".to_string(),
            details: None,
            entities: vec![entity],
            acknowledged: false,
            correlation_id: None,
        }
    }

    fn make_event_at(
        source: ToolSource,
        severity: Severity,
        entity: Entity,
        timestamp: DateTime<Utc>,
    ) -> NormalizedEvent {
        NormalizedEvent {
            id: Uuid::new_v4(),
            timestamp,
            source,
            severity,
            summary: "Test event".to_string(),
            details: None,
            entities: vec![entity],
            acknowledged: false,
            correlation_id: None,
        }
    }

    #[test]
    fn test_single_event_no_correlation() {
        let mut engine = CorrelationEngine::new(5);
        let event = make_event(
            ToolSource::Falco,
            Severity::High,
            Entity::Process {
                pid: 100,
                name: Some("bash".to_string()),
            },
        );
        let result = engine.ingest(event);
        assert!(result.is_none());
    }

    #[test]
    fn test_two_tools_same_entity_creates_incident() {
        let mut engine = CorrelationEngine::new(5);
        let entity = Entity::Process {
            pid: 100,
            name: Some("suspicious".to_string()),
        };

        let event1 = make_event(ToolSource::Falco, Severity::High, entity.clone());
        let result1 = engine.ingest(event1);
        assert!(result1.is_none());

        let event2 = make_event(ToolSource::Auditd, Severity::Medium, entity.clone());
        let result2 = engine.ingest(event2);
        assert!(result2.is_some());

        let incident = result2.unwrap();
        assert_eq!(incident.contributing_tool_count, 2);
        assert_eq!(incident.status, IncidentStatus::Open);
    }

    #[test]
    fn test_severity_calculation() {
        let mut engine = CorrelationEngine::new(4);
        let entity = Entity::Process {
            pid: 200,
            name: None,
        };

        // Falco: High (8), Auditd: Critical (10)
        let event1 = make_event(ToolSource::Falco, Severity::High, entity.clone());
        engine.ingest(event1);

        let event2 = make_event(ToolSource::Auditd, Severity::Critical, entity.clone());
        let incident = engine.ingest(event2).unwrap();

        // sum_of_max = 8 + 10 = 18, denominator = 2 * 10 = 20
        // raw = (18/20) * 10 = 9.0 → 9
        assert_eq!(incident.severity_score, 9);
    }

    #[test]
    fn test_confidence_score() {
        let mut engine = CorrelationEngine::new(6);
        let entity = Entity::Network {
            address: "10.0.0.1".to_string(),
            port: Some(22),
        };

        let event1 = make_event(ToolSource::CrowdSec, Severity::High, entity.clone());
        engine.ingest(event1);

        let event2 = make_event(ToolSource::OpenSnitch, Severity::Medium, entity.clone());
        let incident = engine.ingest(event2).unwrap();

        // 2 tools / 6 active = 0.333...
        assert!((incident.confidence_score - 2.0 / 6.0).abs() < 0.001);
    }

    #[test]
    fn test_fifo_eviction_24h() {
        let mut engine = CorrelationEngine::new(3);
        let entity = Entity::Process {
            pid: 300,
            name: None,
        };

        // Add an event 25 hours ago
        let old_time = Utc::now() - Duration::hours(25);
        let old_event = make_event_at(
            ToolSource::Falco,
            Severity::Low,
            entity.clone(),
            old_time,
        );
        engine.event_window.push_back(old_event);

        // Ingest a new event — should evict the old one
        let new_event = make_event(ToolSource::Auditd, Severity::Low, entity.clone());
        engine.ingest(new_event);

        // Only the new event should remain
        assert_eq!(engine.event_window.len(), 1);
    }

    #[test]
    fn test_standalone_confidence() {
        let engine = CorrelationEngine::new(5);
        assert!((engine.standalone_confidence() - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_same_tool_twice_no_correlation() {
        let mut engine = CorrelationEngine::new(5);
        let entity = Entity::Process {
            pid: 400,
            name: None,
        };

        let event1 = make_event(ToolSource::Falco, Severity::High, entity.clone());
        engine.ingest(event1);

        let event2 = make_event(ToolSource::Falco, Severity::Critical, entity.clone());
        let result = engine.ingest(event2);

        // Same tool twice should NOT create a correlated incident
        assert!(result.is_none());
    }

    #[test]
    fn test_different_entities_no_correlation() {
        let mut engine = CorrelationEngine::new(5);

        let entity1 = Entity::Process {
            pid: 500,
            name: None,
        };
        let entity2 = Entity::Process {
            pid: 600,
            name: None,
        };

        let event1 = make_event(ToolSource::Falco, Severity::High, entity1);
        engine.ingest(event1);

        let event2 = make_event(ToolSource::Auditd, Severity::High, entity2);
        let result = engine.ingest(event2);

        // Different entities should NOT correlate
        assert!(result.is_none());
    }

    #[test]
    fn test_window_expiry_no_correlation() {
        let mut engine = CorrelationEngine::new(5);
        let entity = Entity::Process {
            pid: 700,
            name: None,
        };

        // First event at time T
        let t1 = Utc::now() - Duration::seconds(120);
        let event1 = make_event_at(ToolSource::Falco, Severity::High, entity.clone(), t1);
        engine.ingest(event1);

        // Second event at T + 90s (outside 60s window)
        let t2 = t1 + Duration::seconds(90);
        let event2 = make_event_at(ToolSource::Auditd, Severity::High, entity.clone(), t2);
        let result = engine.ingest(event2);

        // Window expired, so no correlation from the first event
        assert!(result.is_none());
    }

    #[test]
    fn test_severity_clamped_to_range() {
        let engine = CorrelationEngine::new(3);

        // Test with Info severity events
        let events = vec![
            make_event(
                ToolSource::Falco,
                Severity::Info,
                Entity::Process { pid: 1, name: None },
            ),
            make_event(
                ToolSource::Auditd,
                Severity::Info,
                Entity::Process { pid: 1, name: None },
            ),
        ];
        let score = engine.calculate_severity(&events, 2);
        // sum_of_max = 2 + 2 = 4, denom = 20, raw = 2
        assert!(score >= 1 && score <= 10);
    }
}
