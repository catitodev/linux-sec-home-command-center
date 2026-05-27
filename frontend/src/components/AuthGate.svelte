<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { apiClient } from '../lib/api/client';
  import { login } from '../lib/stores/app';

  let username = '';
  let password = '';
  let error = '';
  let loading = false;
  let retryAfterSeconds: number | null = null;

  // i18n placeholder strings
  const labels = {
    title: 'Security Command Center',
    subtitle: 'Autenticação necessária',
    usernamePlaceholder: 'Usuário',
    passwordPlaceholder: 'Senha',
    loginButton: 'Entrar',
    loadingButton: 'Autenticando...',
    lockedMessage: 'Conta temporariamente bloqueada.',
    retryIn: 'Tente novamente em',
    seconds: 'segundos',
    genericError: 'Credenciais inválidas',
  };

  async function handleSubmit(): Promise<void> {
    if (loading) return;

    error = '';
    retryAfterSeconds = null;
    loading = true;

    try {
      const response = await apiClient.login({ username, password });
      login(response.token);
    } catch (err: unknown) {
      // Uniform error message — never reveal which field was wrong (Req 2.3)
      if (err instanceof Error) {
        // Check if the error contains lockout info
        try {
          const parsed = JSON.parse(err.message);
          if (parsed.locked_until) {
            retryAfterSeconds = parsed.retry_after_seconds ?? null;
            error = labels.lockedMessage;
          } else {
            error = labels.genericError;
          }
        } catch {
          error = labels.genericError;
        }
      } else {
        error = labels.genericError;
      }
    } finally {
      loading = false;
      password = '';
    }
  }
</script>

<div class="min-h-screen flex items-center justify-center bg-surface-primary p-4">
  <div class="glass-panel w-full max-w-md p-8">
    <!-- Header -->
    <div class="text-center mb-8">
      <div class="mb-4">
        <svg
          class="w-16 h-16 mx-auto text-blue-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="1.5"
            d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
          />
        </svg>
      </div>
      <h1 class="text-2xl font-bold text-text-primary">{labels.title}</h1>
      <p class="text-text-secondary mt-2">{labels.subtitle}</p>
    </div>

    <!-- Login Form -->
    <form on:submit|preventDefault={handleSubmit} class="space-y-4">
      <div>
        <label for="username" class="sr-only">{labels.usernamePlaceholder}</label>
        <input
          id="username"
          type="text"
          bind:value={username}
          placeholder={labels.usernamePlaceholder}
          class="input-field"
          required
          autocomplete="username"
          disabled={loading}
        />
      </div>

      <div>
        <label for="password" class="sr-only">{labels.passwordPlaceholder}</label>
        <input
          id="password"
          type="password"
          bind:value={password}
          placeholder={labels.passwordPlaceholder}
          class="input-field"
          required
          autocomplete="current-password"
          disabled={loading}
        />
      </div>

      {#if error}
        <div
          class="p-3 rounded-md bg-sec-danger/10 border border-sec-danger/30 text-sec-danger text-sm"
          role="alert"
        >
          <p>{error}</p>
          {#if retryAfterSeconds}
            <p class="mt-1 text-xs">
              {labels.retryIn} {retryAfterSeconds} {labels.seconds}
            </p>
          {/if}
        </div>
      {/if}

      <button
        type="submit"
        class="btn-primary w-full"
        disabled={loading || !username || !password}
      >
        {#if loading}
          <span class="inline-flex items-center gap-2">
            <svg class="animate-spin h-4 w-4" viewBox="0 0 24 24" aria-hidden="true">
              <circle
                class="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                stroke-width="4"
                fill="none"
              />
              <path
                class="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
              />
            </svg>
            {labels.loadingButton}
          </span>
        {:else}
          {labels.loginButton}
        {/if}
      </button>
    </form>
  </div>
</div>
