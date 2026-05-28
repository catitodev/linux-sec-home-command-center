<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { onMount } from 'svelte';

  const labels = {
    title: 'Painel de Varredura',
    startScan: 'Iniciar Varredura',
    scanning: 'Varredura em andamento...',
    scope: 'Escopo',
    scopeFull: 'Completa (Sistema)',
    scopeHome: 'Diretório Home',
    scopeCustom: 'Caminhos Personalizados',
    customPaths: 'Caminhos (um por linha)',
    progress: 'Progresso',
    results: 'Resultados',
    history: 'Histórico de Varreduras',
    noHistory: 'Nenhuma varredura realizada',
    noResults: 'Nenhum resultado disponível',
    findings: 'achados',
    date: 'Data',
    critical: 'Crítico',
    high: 'Alto',
    medium: 'Médio',
    low: 'Baixo',
    clean: 'Limpo',
  };

  type ScanScope = 'full' | 'home' | 'custom';

  interface ScanTool {
    name: string;
    displayName: string;
    progress: number;
    status: 'idle' | 'scanning' | 'done' | 'error';
  }

  interface ScanResult {
    tool: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    path: string;
  }

  interface ScanHistoryEntry {
    id: string;
    date: string;
    scope: ScanScope;
    findings: number;
    duration: string;
  }

  let scanScope: ScanScope = 'full';
  const scanScopeOptions: ScanScope[] = ['full', 'home', 'custom'];
  let customPaths = '';
  let isScanning = false;
  let serverOffline = false;

  let scanTools: ScanTool[] = [
    { name: 'clamav', displayName: 'ClamAV', progress: 0, status: 'idle' },
    { name: 'yara', displayName: 'YARA Rules', progress: 0, status: 'idle' },
    { name: 'chkrootkit', displayName: 'chkrootkit', progress: 0, status: 'idle' },
    { name: 'rkhunter', displayName: 'rkhunter', progress: 0, status: 'idle' },
  ];

  let scanResults: ScanResult[] = [];

  let scanHistory: ScanHistoryEntry[] = [];

  async function loadData(): Promise<void> {
    serverOffline = false;
    try {
      const response = await fetch('http://127.0.0.1:3030/api/health');
      if (!response.ok) throw new Error('Server error');
    } catch {
      serverOffline = true;
    }
  }

  onMount(() => {
    loadData();
  });

  function startScan(): void {
    if (isScanning) return;
    isScanning = true;
    scanResults = [];
    serverOffline = false;

    // Animate progress bars while waiting for the real scan
    scanTools = scanTools.map(t => ({ ...t, progress: 0, status: 'scanning' }));

    let elapsed = 0;
    const progressInterval = setInterval(() => {
      elapsed += 5;
      scanTools = scanTools.map(t => ({
        ...t,
        progress: Math.min(90, t.progress + Math.floor(Math.random() * 10) + 3),
      }));
    }, 800);

    const endpoint = scanScope === 'home' ? '/api/scan/quick' : '/api/scan/full';

    fetch(`http://127.0.0.1:3030${endpoint}`)
      .then(response => {
        if (!response.ok) throw new Error('Server error');
        return response.json();
      })
      .then(data => {
        clearInterval(progressInterval);
        scanTools = scanTools.map(t => ({ ...t, status: 'done', progress: 100 }));
        isScanning = false;

        // Map findings to scan results
        scanResults = (data.findings || []).map((f: any) => ({
          tool: f.engine || 'unknown',
          severity: f.severity || 'medium',
          description: f.threat || f.path || '',
          path: f.path || '',
        }));

        // Add to history
        scanHistory = [
          {
            id: Date.now().toString(),
            date: new Date().toLocaleString('pt-BR'),
            scope: scanScope,
            findings: scanResults.length,
            duration: data.duration || '-',
          },
          ...scanHistory,
        ];
      })
      .catch(() => {
        clearInterval(progressInterval);
        scanTools = scanTools.map(t => ({ ...t, status: 'error', progress: 0 }));
        isScanning = false;
        serverOffline = true;
      });
  }

  function getScopeLabel(scope: ScanScope): string {
    switch (scope) {
      case 'full': return labels.scopeFull;
      case 'home': return labels.scopeHome;
      case 'custom': return labels.scopeCustom;
    }
  }

  function getSeverityClass(severity: string): string {
    switch (severity) {
      case 'critical': return 'bg-sec-danger/20 text-sec-danger';
      case 'high': return 'bg-sec-warning/20 text-sec-warning';
      case 'medium': return 'bg-yellow-600/20 text-yellow-500';
      case 'low': return 'bg-blue-600/20 text-blue-400';
      default: return 'bg-surface-tertiary text-text-muted';
    }
  }

  function getSeverityLabel(severity: string): string {
    switch (severity) {
      case 'critical': return labels.critical;
      case 'high': return labels.high;
      case 'medium': return labels.medium;
      case 'low': return labels.low;
      default: return severity;
    }
  }
</script>

<div class="space-y-6">
  <h2 class="text-2xl font-bold text-text-primary">{labels.title}</h2>

  {#if serverOffline}
    <div class="glass-panel p-8 text-center">
      <p class="text-sec-warning">⚠ Servidor de varredura offline</p>
    </div>
  {/if}

  <!-- Scan Controls -->
  <div class="glass-panel p-6">
    <div class="flex flex-col sm:flex-row items-start sm:items-end gap-4">
      <!-- Scope Selector -->
      <fieldset class="flex-1">
        <legend class="text-sm font-medium text-text-secondary mb-2">{labels.scope}</legend>
        <div class="flex gap-3" role="radiogroup" aria-label={labels.scope}>
          {#each scanScopeOptions as scope}
            <label class="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                name="scan-scope"
                value={scope}
                bind:group={scanScope}
                class="text-blue-500 focus:ring-blue-500 focus:ring-2"
              />
              <span class="text-sm text-text-primary">{getScopeLabel(scope)}</span>
            </label>
          {/each}
        </div>
      </fieldset>

      <!-- Start Button -->
      <button
        on:click={startScan}
        disabled={isScanning}
        class="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 disabled:cursor-not-allowed text-white font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-surface-primary"
        type="button"
        aria-busy={isScanning}
      >
        {isScanning ? labels.scanning : labels.startScan}
      </button>
    </div>

    <!-- Custom Paths Input -->
    {#if scanScope === 'custom'}
      <div class="mt-4">
        <label for="custom-paths" class="text-sm text-text-secondary block mb-1">{labels.customPaths}</label>
        <textarea
          id="custom-paths"
          bind:value={customPaths}
          rows="3"
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
          placeholder="/home/user/downloads&#10;/tmp&#10;/var/log"
        ></textarea>
      </div>
    {/if}
  </div>

  <!-- Progress Bars -->
  {#if isScanning || scanTools.some(t => t.status === 'done')}
    <div class="glass-panel p-6">
      <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.progress}</h3>
      <div class="space-y-4">
        {#each scanTools as tool (tool.name)}
          <div>
            <div class="flex items-center justify-between mb-1">
              <span class="text-sm text-text-primary">{tool.displayName}</span>
              <span class="text-xs text-text-muted">{tool.progress}%</span>
            </div>
            <div
              class="w-full h-2 bg-surface-tertiary rounded-full overflow-hidden"
              role="progressbar"
              aria-valuenow={tool.progress}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="{tool.displayName} progresso"
            >
              <div
                class="h-full rounded-full transition-all duration-300 {tool.status === 'error' ? 'bg-sec-danger' : tool.progress >= 100 ? 'bg-sec-safe' : 'bg-blue-500'}"
                style="width: {tool.progress}%"
              ></div>
            </div>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  <!-- Scan Results -->
  {#if scanResults.length > 0}
    <div class="glass-panel p-6">
      <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.results}</h3>
      <div class="space-y-3">
        {#each scanResults as result}
          <div class="flex items-start gap-3 p-3 rounded-md bg-surface-tertiary/30 border border-surface-tertiary">
            <span class="text-xs font-medium px-2 py-0.5 rounded flex-shrink-0 {getSeverityClass(result.severity)}">
              {getSeverityLabel(result.severity)}
            </span>
            <div class="min-w-0 flex-1">
              <p class="text-sm text-text-primary">{result.description}</p>
              <p class="text-xs text-text-muted font-mono mt-1">{result.path}</p>
              <p class="text-xs text-text-muted mt-0.5">Ferramenta: {result.tool}</p>
            </div>
          </div>
        {/each}
      </div>
    </div>
  {:else if !isScanning && scanTools.some(t => t.status === 'done')}
    <div class="glass-panel p-6 text-center">
      <p class="text-sec-safe font-medium">✓ {labels.clean}</p>
    </div>
  {/if}

  <!-- Scan History -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.history}</h3>
    {#if scanHistory.length === 0}
      <p class="text-text-muted">{labels.noHistory}</p>
    {:else}
      <div class="space-y-2">
        {#each scanHistory as entry (entry.id)}
          <div class="flex items-center justify-between p-3 rounded-md bg-surface-tertiary/30 border border-surface-tertiary">
            <div>
              <p class="text-sm text-text-primary">{entry.date}</p>
              <p class="text-xs text-text-muted">{getScopeLabel(entry.scope)} • {entry.duration}</p>
            </div>
            <span class="text-sm font-medium {entry.findings > 0 ? 'text-sec-warning' : 'text-sec-safe'}">
              {entry.findings} {labels.findings}
            </span>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>
