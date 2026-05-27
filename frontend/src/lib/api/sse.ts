// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

import { get } from 'svelte/store';
import { appStore } from '../stores/app';
import { updateToolStatus, updateFromHealthEvent } from '../stores/security';
import { addEvent } from '../stores/events';
import type { SecurityEvent, ToolStatus } from '../types';

/**
 * SSE (Server-Sent Events) client for real-time updates from the Backend_API.
 * Connects to GET /api/v1/events/stream with auto-reconnect and exponential backoff.
 */

const SSE_ENDPOINT = '/api/v1/events/stream';
const INITIAL_RETRY_MS = 1000;
const MAX_RETRY_MS = 30000;
const BACKOFF_MULTIPLIER = 2;

class SSEClient {
  private eventSource: EventSource | null = null;
  private retryMs: number = INITIAL_RETRY_MS;
  private retryTimeout: ReturnType<typeof setTimeout> | null = null;
  private connected: boolean = false;

  get isConnected(): boolean {
    return this.connected;
  }

  connect(): void {
    const state = get(appStore);
    if (!state.authenticated || !state.sessionToken) {
      return;
    }

    this.disconnect();

    // EventSource does not support custom headers natively.
    // The token is passed as a query parameter for SSE connections.
    const url = `${SSE_ENDPOINT}?token=${encodeURIComponent(state.sessionToken)}`;

    try {
      this.eventSource = new EventSource(url);

      this.eventSource.onopen = () => {
        this.connected = true;
        this.retryMs = INITIAL_RETRY_MS;
      };

      this.eventSource.onerror = () => {
        this.connected = false;
        this.eventSource?.close();
        this.eventSource = null;
        this.scheduleReconnect();
      };

      // Handle typed events
      this.eventSource.addEventListener('alert', (event: MessageEvent) => {
        this.handleAlert(event.data);
      });

      this.eventSource.addEventListener('tool_status', (event: MessageEvent) => {
        this.handleToolStatus(event.data);
      });

      this.eventSource.addEventListener('scan_progress', (event: MessageEvent) => {
        this.handleScanProgress(event.data);
      });

      this.eventSource.addEventListener('health_update', (event: MessageEvent) => {
        this.handleHealthUpdate(event.data);
      });
    } catch {
      this.scheduleReconnect();
    }
  }

  disconnect(): void {
    if (this.retryTimeout) {
      clearTimeout(this.retryTimeout);
      this.retryTimeout = null;
    }

    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }

    this.connected = false;
  }

  private scheduleReconnect(): void {
    if (this.retryTimeout) {
      clearTimeout(this.retryTimeout);
    }

    this.retryTimeout = setTimeout(() => {
      this.retryTimeout = null;
      this.connect();
    }, this.retryMs);

    // Exponential backoff with cap
    this.retryMs = Math.min(this.retryMs * BACKOFF_MULTIPLIER, MAX_RETRY_MS);
  }

  private handleAlert(data: string): void {
    try {
      const event: SecurityEvent = JSON.parse(data);
      addEvent(event);
    } catch {
      // Malformed event data — skip
    }
  }

  private handleToolStatus(data: string): void {
    try {
      const payload: { tool_name: string; new_status: ToolStatus } = JSON.parse(data);
      updateToolStatus(payload.tool_name, payload.new_status);
    } catch {
      // Malformed event data — skip
    }
  }

  private handleScanProgress(data: string): void {
    try {
      // Scan progress events are handled by scan-specific UI components.
      // For now, we just parse and validate the data.
      void JSON.parse(data);
      // Future: dispatch to scan store
    } catch {
      // Malformed event data — skip
    }
  }

  private handleHealthUpdate(data: string): void {
    try {
      const payload: { score: number; active_alerts: number; blocked_connections: number } =
        JSON.parse(data);
      updateFromHealthEvent(payload);
    } catch {
      // Malformed event data — skip
    }
  }
}

export const sseClient = new SSEClient();
