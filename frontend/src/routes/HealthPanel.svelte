<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { securityStore, healthScore, tools, activeAlerts } from '../lib/stores/security';

  const labels = {
    title: 'Painel de Saúde do Sistema',
    healthScore: 'Health Score',
    good: 'Bom',
    warning: 'Atenção',
    critical: 'Crítico',
    toolStatus: 'Status das Ferramentas',
    alertsToday: 'Alertas (24h)',
    blockedConns: 'Conexões Bloqueadas',
    quarantined: 'Arquivos em Quarentena',
    lastScan: 'Última Varredura',
    never: 'Nunca',
    running: 'Ativo',
    stopped: 'Parado',
    error: 'Erro',
    degraded: 'Degradado',
    notInstalled: 'Não instalado',
    noTools: 'Nenhuma ferramenta configurada',
  };

  function getScoreColor(score: number): string {
    if (score >= 80) return '#22c55e'; // green
    if (score >= 50) return '#eab308'; // yellow
    return '#ef4444'; // red
  }

  function getScoreLabel(score: number): string {
    if (score >= 80) return labels.good;
    if (score >= 50) return labels.warning;
    return labels.critical;
  }

  function getScoreTextClass(score: number): string {
    if (score >= 80) return 'text-sec-safe';
    if (score >= 50) return 'text-sec-warning';
    return 'text-sec-danger';
  }

  function getStatusLabel(status: string): string {
    switch (status) {
      case 'running': return labels.running;
      case 'stopped': return labels.stopped;
      case 'error': return labels.error;
      case 'degraded': return labels.degraded;
      case 'not_installed': return labels.notInstalled;
      default: return status;
    }
  }

  function getStatusIcon(status: string): string {
    switch (status) {
      case 'running': return '✓';
      case 'stopped': return '⏸';
      case 'error': return '✗';
      case 'degraded': return '⚠';
      case 'not_installed': return '—';
      default: return '?';
    }
  }

  // SVG circular progress calculations
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  $: offset = circumference - ($healthScore / 100) * circumference;
</script>

<div class="space-y-6">
  <h2 class="text-2xl font-bold text-text-primary">{labels.title}</h2>

  <!-- Health Score with Circular Progress Ring -->
  <div class="glass-panel p-6 flex flex-col items-center sm:flex-row sm:items-start gap-6">
    <div class="relative flex-shrink-0" role="img" aria-label="{labels.healthScore}: {$healthScore} de 100 - {getScoreLabel($healthScore)}">
      <svg class="w-32 h-32 transform -rotate-90" viewBox="0 0 120 120" aria-hidden="true">
        <!-- Background circle -->
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          stroke="currentColor"
          stroke-width="8"
          class="text-surface-tertiary"
        />
        <!-- Progress circle -->
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          stroke={getScoreColor($healthScore)}
          stroke-width="8"
          stroke-linecap="round"
          stroke-dasharray={circumference}
          stroke-dashoffset={offset}
          class="transition-all duration-700 ease-in-out"
        />
      </svg>
      <!-- Score text in center -->
      <div class="absolute inset-0 flex flex-col items-center justify-center">
        <span class="text-3xl font-bold {getScoreTextClass($healthScore)}">{$healthScore}</span>
        <span class="text-xs text-text-secondary">{getScoreLabel($healthScore)}</span>
      </div>
    </div>

    <!-- Summary Stats -->
    <div class="grid grid-cols-2 gap-4 flex-1 w-full">
      <div class="glass-panel p-4">
        <p class="text-sm text-text-secondary">{labels.alertsToday}</p>
        <p class="text-2xl font-bold mt-1 text-sec-warning" aria-live="polite">
          {$activeAlerts}
        </p>
      </div>
      <div class="glass-panel p-4">
        <p class="text-sm text-text-secondary">{labels.blockedConns}</p>
        <p class="text-2xl font-bold mt-1 text-text-primary" aria-live="polite">
          {$securityStore.blockedConnections}
        </p>
      </div>
      <div class="glass-panel p-4">
        <p class="text-sm text-text-secondary">{labels.quarantined}</p>
        <p class="text-2xl font-bold mt-1 text-text-primary" aria-live="polite">
          {$securityStore.quarantinedFiles}
        </p>
      </div>
      <div class="glass-panel p-4">
        <p class="text-sm text-text-secondary">{labels.lastScan}</p>
        <p class="text-lg font-medium mt-1 text-text-primary">
          {$securityStore.lastScanTime ?? labels.never}
        </p>
      </div>
    </div>
  </div>

  <!-- Tool Status Grid -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.toolStatus}</h3>
    {#if $tools.length === 0}
      <p class="text-text-muted">{labels.noTools}</p>
    {:else}
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3" role="list" aria-label={labels.toolStatus}>
        {#each $tools as tool (tool.name)}
          <div
            class="flex items-center gap-3 p-3 rounded-md bg-surface-tertiary/30 border border-surface-tertiary"
            role="listitem"
          >
            <!-- Status indicator: color + icon for WCAG -->
            <span
              class="w-6 h-6 rounded-full flex-shrink-0 flex items-center justify-center text-xs font-bold
                {tool.status === 'running' ? 'bg-sec-safe/20 text-sec-safe' :
                 tool.status === 'degraded' ? 'bg-sec-warning/20 text-sec-warning' :
                 tool.status === 'error' ? 'bg-sec-danger/20 text-sec-danger' :
                 tool.status === 'stopped' ? 'bg-text-muted/20 text-text-muted' :
                 'bg-surface-tertiary text-text-muted'}"
              aria-label="{getStatusLabel(tool.status)}"
            >
              {getStatusIcon(tool.status)}
            </span>
            <div class="min-w-0 flex-1">
              <p class="text-sm font-medium text-text-primary truncate">{tool.display_name}</p>
              <p class="text-xs text-text-muted">{getStatusLabel(tool.status)}</p>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>
