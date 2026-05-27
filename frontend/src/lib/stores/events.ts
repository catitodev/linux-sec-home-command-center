// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

import { writable, derived } from 'svelte/store';
import type { EventState, SecurityEvent, EventFilters } from '../types';

const initialFilters: EventFilters = {
  tool: null,
  severity: null,
  event_type: null,
  time_from: null,
  time_to: null,
  search: null,
};

const initialState: EventState = {
  events: [],
  filters: initialFilters,
  loading: false,
};

export const eventStore = writable<EventState>(initialState);

// Derived stores
export const events = derived(eventStore, ($ev) => $ev.events);
export const eventFilters = derived(eventStore, ($ev) => $ev.filters);
export const eventsLoading = derived(eventStore, ($ev) => $ev.loading);

export const filteredEvents = derived(eventStore, ($ev) => {
  let result = $ev.events;

  if ($ev.filters.tool) {
    result = result.filter((e) => e.source_tool === $ev.filters.tool);
  }
  if ($ev.filters.severity !== null) {
    result = result.filter((e) => e.severity >= ($ev.filters.severity ?? 0));
  }
  if ($ev.filters.event_type) {
    result = result.filter((e) => e.event_type === $ev.filters.event_type);
  }
  if ($ev.filters.search) {
    const query = $ev.filters.search.toLowerCase();
    result = result.filter(
      (e) =>
        e.description.toLowerCase().includes(query) ||
        e.entity_id.toLowerCase().includes(query)
    );
  }

  return result;
});

// Actions
export function setEvents(events: SecurityEvent[]): void {
  eventStore.update((state) => ({
    ...state,
    events,
  }));
}

export function addEvent(event: SecurityEvent): void {
  eventStore.update((state) => ({
    ...state,
    events: [event, ...state.events].slice(0, 1000), // Keep max 1000 events in memory
  }));
}

export function setFilters(filters: Partial<EventFilters>): void {
  eventStore.update((state) => ({
    ...state,
    filters: { ...state.filters, ...filters },
  }));
}

export function clearFilters(): void {
  eventStore.update((state) => ({
    ...state,
    filters: initialFilters,
  }));
}

export function setLoading(loading: boolean): void {
  eventStore.update((state) => ({
    ...state,
    loading,
  }));
}
