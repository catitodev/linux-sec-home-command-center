// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

/**
 * TypeScript interfaces matching the Rust backend data models.
 */

// --- Authentication ---

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  expires_at: string;
}

export interface AuthError {
  error: string;
  locked_until?: string;
  retry_after_seconds?: number;
}

// --- App State ---

export type Language = 'pt-BR' | 'en-US';

export interface AppState {
  authenticated: boolean;
  sessionToken: string | null;
  offlineMode: boolean;
  paranoiaMode: boolean;
  language: Language;
}

// --- Security State ---

export type ToolStatus = 'running' | 'stopped' | 'error' | 'degraded' | 'not_installed';
export type ToolCategory = 'visibility' | 'protection' | 'detection';

export interface Tool {
  name: string;
  display_name: string;
  status: ToolStatus;
  category: ToolCategory;
  last_health_check: string | null;
  version: string | null;
}

export interface SecurityState {
  healthScore: number;
  tools: Tool[];
  activeAlerts: number;
  blockedConnections: number;
  quarantinedFiles: number;
  lastScanTime: string | null;
}

// --- Events ---

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical' | 'emergency';
export type EventType =
  | 'process_anomaly'
  | 'network_connection'
  | 'file_modification'
  | 'privilege_escalation'
  | 'malware_detection'
  | 'intrusion_attempt'
  | 'policy_violation'
  | 'configuration_change'
  | 'authentication_event'
  | 'device_event';

export interface SecurityEvent {
  id: string;
  created_at: string;
  source_tool: string;
  event_type: EventType;
  severity: number;
  entity_type: 'process' | 'ip' | 'file' | 'user';
  entity_id: string;
  description: string;
  correlated: boolean;
  correlation_id: string | null;
}

export interface EventFilters {
  tool: string | null;
  severity: number | null;
  event_type: EventType | null;
  time_from: string | null;
  time_to: string | null;
  search: string | null;
}

export interface EventState {
  events: SecurityEvent[];
  filters: EventFilters;
  loading: boolean;
}

// --- SSE Event Types ---

export type SSEEventType = 'alert' | 'tool_status' | 'scan_progress' | 'health_update';

export interface SSEAlertEvent {
  type: 'alert';
  data: SecurityEvent;
}

export interface SSEToolStatusEvent {
  type: 'tool_status';
  data: {
    tool_name: string;
    new_status: ToolStatus;
  };
}

export interface SSEScanProgressEvent {
  type: 'scan_progress';
  data: {
    scan_id: string;
    progress: number;
    current_path: string;
  };
}

export interface SSEHealthUpdateEvent {
  type: 'health_update';
  data: {
    score: number;
    active_alerts: number;
    blocked_connections: number;
  };
}

export type SSEEvent =
  | SSEAlertEvent
  | SSEToolStatusEvent
  | SSEScanProgressEvent
  | SSEHealthUpdateEvent;

// --- API Response Wrappers ---

export interface ApiResponse<T> {
  data: T;
}

export interface ApiError {
  error: string;
  code?: string;
  details?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
}
