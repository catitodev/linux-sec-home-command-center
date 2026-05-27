// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

import { writable, derived } from 'svelte/store';
import type { AppState, Language } from '../types';

const SESSION_TOKEN_KEY = 'scc_session_token';

function getStoredToken(): string | null {
  try {
    return sessionStorage.getItem(SESSION_TOKEN_KEY);
  } catch {
    return null;
  }
}

function storeToken(token: string | null): void {
  try {
    if (token) {
      sessionStorage.setItem(SESSION_TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(SESSION_TOKEN_KEY);
    }
  } catch {
    // Storage unavailable — continue without persistence
  }
}

const initialState: AppState = {
  authenticated: !!getStoredToken(),
  sessionToken: getStoredToken(),
  offlineMode: !navigator.onLine,
  paranoiaMode: false,
  language: 'pt-BR',
};

export const appStore = writable<AppState>(initialState);

// Derived stores for convenience
export const isAuthenticated = derived(appStore, ($app) => $app.authenticated);
export const isOffline = derived(appStore, ($app) => $app.offlineMode);
export const isParanoiaMode = derived(appStore, ($app) => $app.paranoiaMode);
export const currentLanguage = derived(appStore, ($app) => $app.language);

// Actions
export function login(token: string): void {
  storeToken(token);
  appStore.update((state) => ({
    ...state,
    authenticated: true,
    sessionToken: token,
  }));
}

export function logout(): void {
  storeToken(null);
  appStore.update((state) => ({
    ...state,
    authenticated: false,
    sessionToken: null,
  }));
}

export function setOfflineMode(offline: boolean): void {
  appStore.update((state) => ({
    ...state,
    offlineMode: offline,
  }));
}

export function setParanoiaMode(active: boolean): void {
  appStore.update((state) => ({
    ...state,
    paranoiaMode: active,
  }));
}

export function setLanguage(language: Language): void {
  appStore.update((state) => ({
    ...state,
    language,
  }));
}

// Listen for online/offline events
if (typeof window !== 'undefined') {
  window.addEventListener('online', () => setOfflineMode(false));
  window.addEventListener('offline', () => setOfflineMode(true));
}
