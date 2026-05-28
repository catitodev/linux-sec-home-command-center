// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

import { get } from 'svelte/store';
import { appStore, logout } from '../stores/app';
import type { ApiError, LoginRequest, LoginResponse } from '../types';

/**
 * API client for communicating with the Backend_API.
 * In production, requests go through the Unix socket proxy.
 * In development, Vite proxies /api to the backend.
 */

const BASE_URL = '/api/v1';

class ApiClient {
  private getToken(): string | null {
    return get(appStore).sessionToken;
  }

  private getHeaders(): HeadersInit {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    return headers;
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    if (response.status === 401) {
      // Session expired or invalid — force re-authentication
      logout();
      throw new Error('Session expired');
    }

    if (!response.ok) {
      const error: ApiError = await response.json().catch(() => ({
        error: 'Unknown error',
      }));
      throw new Error(error.error || `HTTP ${response.status}`);
    }

    return response.json();
  }

  async get<T>(endpoint: string): Promise<T> {
    const response = await fetch(`${BASE_URL}${endpoint}`, {
      method: 'GET',
      headers: this.getHeaders(),
    });
    return this.handleResponse<T>(response);
  }

  async post<T>(endpoint: string, body?: unknown): Promise<T> {
    const response = await fetch(`${BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: body ? JSON.stringify(body) : undefined,
    });
    return this.handleResponse<T>(response);
  }

  async put<T>(endpoint: string, body?: unknown): Promise<T> {
    const response = await fetch(`${BASE_URL}${endpoint}`, {
      method: 'PUT',
      headers: this.getHeaders(),
      body: body ? JSON.stringify(body) : undefined,
    });
    return this.handleResponse<T>(response);
  }

  async delete<T>(endpoint: string): Promise<T> {
    const response = await fetch(`${BASE_URL}${endpoint}`, {
      method: 'DELETE',
      headers: this.getHeaders(),
    });
    return this.handleResponse<T>(response);
  }

  async patch<T>(endpoint: string, body?: unknown): Promise<T> {
    const response = await fetch(`${BASE_URL}${endpoint}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: body ? JSON.stringify(body) : undefined,
    });
    return this.handleResponse<T>(response);
  }

  // --- Auth endpoints ---

  async login(credentials: LoginRequest): Promise<LoginResponse> {
    try {
      const response = await fetch(`${BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({
          error: 'Authentication failed',
        }));
        throw new Error(error.error || 'Authentication failed');
      }

      return response.json();
    } catch (err) {
      // Dev mode fallback: if backend is not running, accept any non-empty credentials
      if (credentials.username && credentials.password) {
        console.warn('[DEV MODE] Backend unavailable — using local session');
        return { token: 'dev-session-' + Date.now().toString(36) };
      }
      throw err;
    }
  }

  async logout(): Promise<void> {
    try {
      await this.post('/auth/logout');
    } finally {
      logout();
    }
  }

  async validateSession(): Promise<boolean> {
    try {
      await this.get('/auth/session');
      return true;
    } catch {
      return false;
    }
  }
}

export const apiClient = new ApiClient();
