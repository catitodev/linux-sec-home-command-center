<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { onMount, onDestroy, setContext } from 'svelte';
  import Sidebar from './Sidebar.svelte';
  import OfflineIndicator from './OfflineIndicator.svelte';
  import ParanoiaModeIndicator from './ParanoiaModeIndicator.svelte';
  import LHCCAgent from './LHCCAgent.svelte';
  import FixProgressPanel from './FixProgressPanel.svelte';
  import { isParanoiaMode } from '../lib/stores/app';
  import { sseClient } from '../lib/api/sse';
  import { apiClient } from '../lib/api/client';
  import type { FixItem } from '../lib/stores/fixes';

  let currentRoute = '/';

  const labels = {
    logoutButton: 'Sair',
    title: 'Security Command Center',
  };

  let fixPanelRef: FixProgressPanel;

  // Provide fix process trigger to child components via context
  function startFixProcess(): void {
    const mockFixItems: FixItem[] = [
      { id: '1', description: 'Atualizar permissões de /etc/shadow', status: 'pending' },
      { id: '2', description: 'Desabilitar login root via SSH', status: 'pending' },
      { id: '3', description: 'Remover pacotes desnecessários', status: 'pending' },
      { id: '4', description: 'Configurar firewall UFW', status: 'pending' },
      { id: '5', description: 'Atualizar regras do AppArmor', status: 'pending' },
      { id: '6', description: 'Corrigir permissões de diretórios home', status: 'pending' },
      { id: '7', description: 'Habilitar auditd para monitoramento', status: 'pending' },
    ];

    fixPanelRef?.startFixes(mockFixItems);
  }

  setContext('startFixProcess', startFixProcess);

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

  <!-- LHCC Agent Chat (persistent across all pages) -->
  <LHCCAgent />

  <!-- Fix Progress Panel (persistent across all pages) -->
  <FixProgressPanel bind:this={fixPanelRef} />
</div>
