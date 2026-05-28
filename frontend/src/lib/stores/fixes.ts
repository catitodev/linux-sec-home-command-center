// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

import { writable } from 'svelte/store';

export interface FixItem {
  id: string;
  description: string;
  status: 'pending' | 'in-progress' | 'done' | 'failed';
}

export interface FixState {
  isActive: boolean;
  isMinimized: boolean;
  isComplete: boolean;
  items: FixItem[];
  logs: string[];
  progress: number;
}

const initialState: FixState = {
  isActive: false,
  isMinimized: false,
  isComplete: false,
  items: [],
  logs: [],
  progress: 0,
};

export const fixStore = writable<FixState>(initialState);

export function resetFixStore(): void {
  fixStore.set(initialState);
}
