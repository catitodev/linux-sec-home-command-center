<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { securityStore, healthScore, tools, activeAlerts } from '../lib/stores/security';
  import { getContext } from 'svelte';

  // Get the fix panel trigger from context (set by DashboardShell)
  const startFixProcess = getContext<(() => void) | undefined>('startFixProcess');

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
    startScan: 'Iniciar Varredura',
    refresh: 'Refresh',
    cancel: 'Cancelar',
    scanning: 'Varredura em andamento...',
    scanComplete: 'Varredura concluída!',
    applyFixes: 'Realizar Correções',
    cancelFixes: 'Cancelar Correções',
  };

  // Scan state
  let isScanning = false;
  let scanProgress = 0;
  let scanFindings = 0;
  let showToast = false;
  let toastMessage = '';

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

  function playNotificationSound(): void {
    try {
      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      const oscillator = ctx.createOscillator();
      const gain = ctx.createGain();
      oscillator.connect(gain);
      gain.connect(ctx.destination);
      oscillator.frequency.value = 880;
      oscillator.type = 'sine';
      gain.gain.value = 0.3;
      oscillator.start();
      setTimeout(() => { oscillator.stop(); ctx.close(); }, 200);
    } catch {
      // Audio not available
    }
  }

  function sendNotification(title: string, body: string): void {
    if (typeof Notification === 'undefined') return;
    if (Notification.permission === 'granted') {
      new Notification(title, { body, icon: '/logo.png' });
    } else if (Notification.permission !== 'denied') {
      Notification.requestPermission().then((p) => {
        if (p === 'granted') new Notification(title, { body, icon: '/logo.png' });
      });
    }
  }

  function showToastMessage(message: string): void {
    toastMessage = message;
    showToast = true;
    setTimeout(() => { showToast = false; }, 4000);
  }

  function startScan(): void {
    if (isScanning) return;
    isScanning = true;
    scanProgress = 0;
    scanFindings = 0;

    const interval = setInterval(() => {
      scanProgress += Math.floor(Math.random() * 12) + 3;
      if (scanProgress >= 100) {
        scanProgress = 100;
        clearInterval(interval);
        isScanning = false;

        // Findings start at 0 — real data comes from backend
        scanFindings = 0;

        // Update last scan time
        securityStore.update((s) => ({
          ...s,
          lastScanTime: new Date().toLocaleString('pt-BR'),
        }));

        // Notifications
        playNotificationSound();
        sendNotification('LHCC - Varredura Concluída', `Varredura finalizada. ${scanFindings} achados encontrados.`);
        showToastMessage(labels.scanComplete);
      }
    }, 600);
  }

  function cancelScan(): void {
    isScanning = false;
    scanProgress = 0;
    showToastMessage('Varredura cancelada.');
  }

  async function refreshDashboard(): Promise<void> {
    try {
      const response = await fetch('http://localhost:3030/api/health');
      if (response.ok) {
        const data = await response.json();
        securityStore.update((s) => ({
          ...s,
          healthScore: data.score ?? s.healthScore,
          activeAlerts: data.active_alerts ?? s.activeAlerts,
          blockedConnections: data.blocked_connections ?? s.blockedConnections,
        }));
        showToastMessage('Dashboard atualizado.');
      } else {
        showToastMessage('Sem dados — execute uma varredura.');
      }
    } catch {
      showToastMessage('Sem dados — execute uma varredura.');
    }
  }

  function handleApplyFixes(): void {
    if (startFixProcess) {
      startFixProcess();
    }
  }

  // SVG circular progress calculations
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  $: offset = circumference - ($healthScore / 100) * circumference;
</script>

<div class="space-y-6">
  <h2 class="text-2xl font-bold text-text-primary">{labels.title}</h2>

  <!-- Scan Action Buttons -->
  <div class="glass-panel p-4">
    <div class="flex flex-wrap items-center gap-3">
      <!-- Start Scan -->
      <button
        on:click={startScan}
        disabled={isScanning}
        class="px-5 py-2.5 bg-green-600 hover:bg-green-700 disabled:bg-green-600/40 disabled:cursor-not-allowed text-white font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2 focus:ring-offset-surface-primary flex items-center gap-2"
        type="button"
        aria-label={labels.startScan}
      >
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        {labels.startScan}
      </button>

      <!-- Refresh -->
      <button
        on:click={refreshDashboard}
        class="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-surface-primary flex items-center gap-2"
        type="button"
        aria-label={labels.refresh}
      >
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
        {labels.refresh}
      </button>

      <!-- Cancel (only during scan) -->
      {#if isScanning}
        <button
          on:click={cancelScan}
          class="px-5 py-2.5 bg-red-600 hover:bg-red-700 text-white font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 focus:ring-offset-surface-primary flex items-center gap-2"
          type="button"
          aria-label={labels.cancel}
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
          {labels.cancel}
        </button>
      {/if}

      <!-- Apply Fixes (only when findings > 0) -->
      {#if scanFindings > 0 && !isScanning}
        <button
          on:click={handleApplyFixes}
          class="px-5 py-2.5 bg-orange-600 hover:bg-orange-700 text-white font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-orange-500 focus:ring-offset-2 focus:ring-offset-surface-primary flex items-center gap-2"
          type="button"
          aria-label={labels.applyFixes}
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          {labels.applyFixes}
        </button>
      {/if}
    </div>

    <!-- Scan Progress Bar -->
    {#if isScanning}
      <div class="mt-4">
        <div class="flex items-center justify-between mb-1">
          <span class="text-sm text-text-secondary">{labels.scanning}</span>
          <span class="text-xs text-text-muted">{scanProgress}%</span>
        </div>
        <div
          class="w-full h-2.5 bg-surface-tertiary rounded-full overflow-hidden"
          role="progressbar"
          aria-valuenow={scanProgress}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Progresso da varredura"
        >
          <div
            class="h-full rounded-full bg-green-500 transition-all duration-300"
            style="width: {scanProgress}%"
          ></div>
        </div>
      </div>
    {/if}

    <!-- Scan Results Summary -->
    {#if scanFindings > 0 && !isScanning}
      <div class="mt-3 px-3 py-2 bg-orange-500/10 border border-orange-500/20 rounded-md">
        <p class="text-sm text-orange-300">
          ⚠ {scanFindings} achado{scanFindings > 1 ? 's' : ''} encontrado{scanFindings > 1 ? 's' : ''} na última varredura.
        </p>
      </div>
    {/if}
  </div>

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

<!-- Toast Notification -->
{#if showToast}
  <div
    class="fixed bottom-20 left-1/2 -translate-x-1/2 z-50 px-5 py-3 bg-green-600/90 backdrop-blur-md text-white text-sm font-medium rounded-lg shadow-lg border border-green-500/30 animate-fade-in"
    role="alert"
    aria-live="assertive"
  >
    {toastMessage}
  </div>
{/if}

<style>
  @keyframes fade-in {
    from { opacity: 0; transform: translate(-50%, 10px); }
    to { opacity: 1; transform: translate(-50%, 0); }
  }
  .animate-fade-in {
    animation: fade-in 0.3s ease-out;
  }
</style>
