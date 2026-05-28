<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import Sidebar from './Sidebar.svelte';
  import OfflineIndicator from './OfflineIndicator.svelte';
  import ParanoiaModeIndicator from './ParanoiaModeIndicator.svelte';
  import { isParanoiaMode } from '../lib/stores/app';
  import { sseClient } from '../lib/api/sse';
  import { apiClient } from '../lib/api/client';

  let currentRoute = '/';

  const labels = {
    logoutButton: 'Sair',
    title: 'Security Command Center',
  };

  // Listen for hash changes for simple routing
  function handleHashChange(): void {
    const hash = window.location.hash.slice(1) || '/';
    currentRoute = hash;
  }

  async function handleLogout(): Promise<void> {
    sseClient.disconnect();
    await apiClient.logout();
  }

  onMount(() => {
    // Start SSE connection for real-time updates
    sseClient.connect();

    // Set up hash-based routing
    handleHashChange();
    window.addEventListener('hashchange', handleHashChange);
  });

  onDestroy(() => {
    sseClient.disconnect();
    if (typeof window !== 'undefined') {
      window.removeEventListener('hashchange', handleHashChange);
    }
  });
</script>

<div class="flex h-screen overflow-hidden" class:pt-10={$isParanoiaMode}>
  <!-- Paranoia Mode Banner (fixed at top) -->
  <ParanoiaModeIndicator />

  <!-- Sidebar -->
  <Sidebar {currentRoute} />

  <!-- Main Content Area -->
  <div class="flex-1 flex flex-col overflow-hidden">
    <!-- Top Bar -->
    <header class="h-14 bg-surface-secondary border-b border-surface-tertiary flex items-center justify-between px-6">
      <div class="flex items-center gap-3">
        <img src="/logo.png" alt="LinuxSec" class="w-7 h-7 rounded-md" />
        <h1 class="text-lg font-semibold text-text-primary">{labels.title}</h1>
      </div>
      <div class="flex items-center gap-4">
        <button
          on:click={handleLogout}
          class="text-sm text-text-secondary hover:text-text-primary transition-colors duration-150"
          type="button"
        >
          {labels.logoutButton}
        </button>
      </div>
    </header>

    <!-- Page Content -->
    <main class="flex-1 overflow-y-auto p-6">
      <slot />
    </main>
  </div>

  <!-- Offline Indicator (floating) -->
  <OfflineIndicator />
</div>
