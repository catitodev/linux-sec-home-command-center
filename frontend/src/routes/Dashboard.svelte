<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { healthScore, activeAlerts, tools } from '../lib/stores/security';
  import { securityStore } from '../lib/stores/security';

  const labels = {
    title: 'Painel de Segurança',
    healthScore: 'Health Score',
    activeAlerts: 'Alertas Ativos',
    blockedConnections: 'Conexões Bloqueadas',
    quarantinedFiles: 'Arquivos em Quarentena',
    lastScan: 'Última Varredura',
    toolsRunning: 'Ferramentas Ativas',
    noData: 'Sem dados disponíveis',
    never: 'Nunca',
  };
</script>

<div class="space-y-6">
  <h2 class="text-2xl font-bold text-text-primary">{labels.title}</h2>

  <!-- Stats Grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
    <!-- Health Score -->
    <div class="glass-panel p-4">
      <p class="text-sm text-text-secondary">{labels.healthScore}</p>
      <p class="text-3xl font-bold mt-1
        {$healthScore >= 80 ? 'text-sec-safe' : $healthScore >= 50 ? 'text-sec-warning' : 'text-sec-danger'}">
        {$healthScore}
      </p>
    </div>

    <!-- Active Alerts -->
    <div class="glass-panel p-4">
      <p class="text-sm text-text-secondary">{labels.activeAlerts}</p>
      <p class="text-3xl font-bold mt-1 text-sec-warning">
        {$activeAlerts}
      </p>
    </div>

    <!-- Blocked Connections -->
    <div class="glass-panel p-4">
      <p class="text-sm text-text-secondary">{labels.blockedConnections}</p>
      <p class="text-3xl font-bold mt-1 text-text-primary">
        {$securityStore.blockedConnections}
      </p>
    </div>

    <!-- Quarantined Files -->
    <div class="glass-panel p-4">
      <p class="text-sm text-text-secondary">{labels.quarantinedFiles}</p>
      <p class="text-3xl font-bold mt-1 text-text-primary">
        {$securityStore.quarantinedFiles}
      </p>
    </div>
  </div>

  <!-- Tools Status -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.toolsRunning}</h3>
    {#if $tools.length === 0}
      <p class="text-text-muted">{labels.noData}</p>
    {:else}
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {#each $tools as tool}
          <div class="flex items-center gap-3 p-3 rounded-md bg-surface-tertiary/30">
            <span
              class="w-2 h-2 rounded-full flex-shrink-0
                {tool.status === 'running' ? 'bg-sec-safe' :
                 tool.status === 'degraded' ? 'bg-sec-warning' :
                 tool.status === 'error' ? 'bg-sec-danger' :
                 'bg-text-muted'}"
              aria-hidden="true"
            ></span>
            <div class="min-w-0">
              <p class="text-sm font-medium text-text-primary truncate">{tool.display_name}</p>
              <p class="text-xs text-text-muted capitalize">{tool.status}</p>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Last Scan -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-2">{labels.lastScan}</h3>
    <p class="text-text-secondary">
      {$securityStore.lastScanTime ?? labels.never}
    </p>
  </div>
</div>
