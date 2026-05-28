// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

import { writable, derived } from 'svelte/store';
import type { SecurityState, Tool, ToolStatus } from '../types';

const initialState: SecurityState = {
  healthScore: 0,
  tools: [],
  activeAlerts: 0,
  blockedConnections: 0,
  quarantinedFiles: 0,
  lastScanTime: null,
};

// Load persisted state from localStorage
function loadPersistedState(): SecurityState {
  try {
    const saved = localStorage.getItem('lhcc_security_state');
    if (saved) {
      const parsed = JSON.parse(saved);
      return { ...initialState, ...parsed };
    }
  } catch {
    // Ignore parse errors
  }
  return initialState;
}

export const securityStore = writable<SecurityState>(loadPersistedState());

// Persist state changes to localStorage
securityStore.subscribe((state) => {
  try {
    localStorage.setItem('lhcc_security_state', JSON.stringify(state));
  } catch {
    // Storage full or unavailable
  }
});

// Derived stores
export const healthScore = derived(securityStore, ($sec) => $sec.healthScore);
export const tools = derived(securityStore, ($sec) => $sec.tools);
export const activeAlerts = derived(securityStore, ($sec) => $sec.activeAlerts);

export const runningTools = derived(securityStore, ($sec) =>
  $sec.tools.filter((t) => t.status === 'running')
);

export const degradedTools = derived(securityStore, ($sec) =>
  $sec.tools.filter((t) => t.status === 'error' || t.status === 'degraded')
);

// Actions
export function setHealthScore(score: number): void {
  securityStore.update((state) => ({
    ...state,
    healthScore: Math.max(0, Math.min(100, score)),
  }));
}

export function setTools(tools: Tool[]): void {
  securityStore.update((state) => ({
    ...state,
    tools,
  }));
}

export function updateToolStatus(toolName: string, status: ToolStatus): void {
  securityStore.update((state) => ({
    ...state,
    tools: state.tools.map((t) =>
      t.name === toolName ? { ...t, status } : t
    ),
  }));
}

export function setActiveAlerts(count: number): void {
  securityStore.update((state) => ({
    ...state,
    activeAlerts: count,
  }));
}

export function setBlockedConnections(count: number): void {
  securityStore.update((state) => ({
    ...state,
    blockedConnections: count,
  }));
}

export function setQuarantinedFiles(count: number): void {
  securityStore.update((state) => ({
    ...state,
    quarantinedFiles: count,
  }));
}

export function setLastScanTime(time: string): void {
  securityStore.update((state) => ({
    ...state,
    lastScanTime: time,
  }));
}

export function updateFromHealthEvent(data: {
  score: number;
  active_alerts: number;
  blocked_connections: number;
}): void {
  securityStore.update((state) => ({
    ...state,
    healthScore: data.score,
    activeAlerts: data.active_alerts,
    blockedConnections: data.blocked_connections,
  }));
}
