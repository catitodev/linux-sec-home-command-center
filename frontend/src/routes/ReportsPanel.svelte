<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { onMount } from 'svelte';

  const labels = {
    title: 'Relatórios e Logs',
    generateReport: 'Gerar Relatório',
    generating: 'Gerando...',
    reportHistory: 'Histórico de Relatórios',
    noReports: 'Nenhum relatório gerado',
    download: 'Baixar',
    logViewer: 'Visualizador de Logs',
    filterOperation: 'Tipo de Operação',
    filterTime: 'Período',
    filterSeverity: 'Severidade',
    export: 'Exportar',
    exportJSON: 'Exportar JSON',
    exportCEF: 'Exportar CEF',
    all: 'Todos',
    noLogs: 'Nenhum log registrado',
    date: 'Data',
    type: 'Tipo',
    description: 'Descrição',
    severity: 'Severidade',
    last24h: 'Últimas 24h',
    last7d: 'Últimos 7 dias',
    last30d: 'Últimos 30 dias',
    scan: 'Varredura',
    ruleChange: 'Alteração de Regra',
    authentication: 'Autenticação',
    systemChange: 'Alteração de Sistema',
    info: 'Info',
    low: 'Baixa',
    medium: 'Média',
    high: 'Alta',
    critical: 'Crítica',
  };

  interface Report {
    id: string;
    date: string;
    name: string;
    size: string;
    format: string;
    content?: string;
    filepath?: string;
  }

  interface LogEntry {
    id: string;
    timestamp: string;
    operation: string;
    description: string;
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    user: string;
  }

  let isGenerating = false;
  let serverOffline = false;

  let reports: Report[] = [];

  let logs: LogEntry[] = [];

  let filterOperation = '';
  let filterTime = '';
  let filterSeverity = '';

  async function loadLogs(): Promise<void> {
    serverOffline = false;
    try {
      const response = await fetch('http://127.0.0.1:3030/api/logs');
      if (!response.ok) throw new Error('Server error');
      const data = await response.json();
      logs = data.logs || [];
    } catch {
      serverOffline = true;
      logs = [];
    }
  }

  onMount(() => {
    loadLogs();
  });

  $: filteredLogs = logs.filter(log => {
    if (filterOperation && log.operation !== filterOperation) return false;
    if (filterSeverity && log.severity !== filterSeverity) return false;
    if (filterTime) {
      const logDate = new Date(log.timestamp);
      const now = new Date();
      const diffMs = now.getTime() - logDate.getTime();
      const diffDays = diffMs / (1000 * 60 * 60 * 24);
      if (filterTime === '24h' && diffDays > 1) return false;
      if (filterTime === '7d' && diffDays > 7) return false;
      if (filterTime === '30d' && diffDays > 30) return false;
    }
    return true;
  });

  function generateReport(): void {
    if (isGenerating) return;
    isGenerating = true;

    fetch('http://127.0.0.1:3030/api/report/generate')
      .then(response => {
        if (!response.ok) throw new Error('Server error');
        return response.json();
      })
      .then(data => {
        reports = [
          {
            id: Date.now().toString(),
            date: data.date || new Date().toLocaleString('pt-BR'),
            name: data.filename || 'relatorio.txt',
            size: data.content ? `${(data.content.length / 1024).toFixed(1)} KB` : '-',
            format: 'TXT',
            content: data.content,
            filepath: data.filepath,
          },
          ...reports,
        ];
        isGenerating = false;
      })
      .catch(() => {
        serverOffline = true;
        isGenerating = false;
      });
  }

  function downloadReport(report: Report): void {
    if (report.content) {
      const blob = new Blob([report.content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = report.name;
      a.click();
      URL.revokeObjectURL(url);
    }
  }

  function exportJSON(): void {
    const data = JSON.stringify(filteredLogs, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security_logs.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportCEF(): void {
    const cefLines = filteredLogs.map(log =>
      `CEF:0|SecurityCommandCenter|SCC|1.0|${log.operation}|${log.description}|${getSeverityNumber(log.severity)}|src=${log.user} rt=${log.timestamp}`
    );
    const data = cefLines.join('\n');
    const blob = new Blob([data], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security_logs.cef';
    a.click();
    URL.revokeObjectURL(url);
  }

  function getSeverityNumber(severity: string): number {
    switch (severity) {
      case 'critical': return 9;
      case 'high': return 7;
      case 'medium': return 5;
      case 'low': return 3;
      default: return 1;
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
      default: return labels.info;
    }
  }

  function getOperationLabel(operation: string): string {
    switch (operation) {
      case 'scan': return labels.scan;
      case 'rule_change': return labels.ruleChange;
      case 'authentication': return labels.authentication;
      case 'system_change': return labels.systemChange;
      default: return operation;
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

  <!-- Generate Report -->
  <div class="glass-panel p-6">
    <div class="flex items-center justify-between">
      <h3 class="text-lg font-semibold text-text-primary">{labels.reportHistory}</h3>
      <button
        on:click={generateReport}
        disabled={isGenerating}
        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-surface-primary"
        type="button"
        aria-busy={isGenerating}
      >
        {isGenerating ? labels.generating : labels.generateReport}
      </button>
    </div>

    <!-- Report List -->
    {#if reports.length === 0}
      <p class="text-text-muted mt-4">{labels.noReports}</p>
    {:else}
      <div class="mt-4 space-y-2">
        {#each reports as report (report.id)}
          <div class="flex items-center justify-between p-3 rounded-md bg-surface-tertiary/30 border border-surface-tertiary">
            <div>
              <p class="text-sm text-text-primary font-mono">{report.name}</p>
              <p class="text-xs text-text-muted">{report.date} • {report.size} • {report.format}</p>
            </div>
            <button
              on:click={() => downloadReport(report)}
              class="px-3 py-1.5 text-xs bg-blue-600/20 text-blue-400 rounded hover:bg-blue-600/30 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
              type="button"
              aria-label="{labels.download} {report.name}"
            >
              {labels.download}
            </button>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Log Viewer -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.logViewer}</h3>

    <!-- Log Filters -->
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
      <div>
        <label for="log-filter-operation" class="sr-only">{labels.filterOperation}</label>
        <select
          id="log-filter-operation"
          bind:value={filterOperation}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterOperation}
        >
          <option value="">{labels.all} - {labels.filterOperation}</option>
          <option value="scan">{labels.scan}</option>
          <option value="rule_change">{labels.ruleChange}</option>
          <option value="authentication">{labels.authentication}</option>
          <option value="system_change">{labels.systemChange}</option>
        </select>
      </div>
      <div>
        <label for="log-filter-time" class="sr-only">{labels.filterTime}</label>
        <select
          id="log-filter-time"
          bind:value={filterTime}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterTime}
        >
          <option value="">{labels.all} - {labels.filterTime}</option>
          <option value="24h">{labels.last24h}</option>
          <option value="7d">{labels.last7d}</option>
          <option value="30d">{labels.last30d}</option>
        </select>
      </div>
      <div>
        <label for="log-filter-severity" class="sr-only">{labels.filterSeverity}</label>
        <select
          id="log-filter-severity"
          bind:value={filterSeverity}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterSeverity}
        >
          <option value="">{labels.all} - {labels.filterSeverity}</option>
          <option value="info">{labels.info}</option>
          <option value="low">{labels.low}</option>
          <option value="medium">{labels.medium}</option>
          <option value="high">{labels.high}</option>
          <option value="critical">{labels.critical}</option>
        </select>
      </div>
    </div>

    <!-- Export Buttons -->
    <div class="flex gap-2 mb-4">
      <button
        on:click={exportJSON}
        class="px-3 py-1.5 text-xs bg-surface-tertiary text-text-secondary hover:text-text-primary rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
        type="button"
      >
        {labels.exportJSON}
      </button>
      <button
        on:click={exportCEF}
        class="px-3 py-1.5 text-xs bg-surface-tertiary text-text-secondary hover:text-text-primary rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
        type="button"
      >
        {labels.exportCEF}
      </button>
    </div>

    <!-- Log Table -->
    {#if filteredLogs.length === 0}
      <p class="text-text-muted text-center py-4">{labels.noLogs}</p>
    {:else}
      <div class="overflow-x-auto">
        <table class="w-full text-sm" aria-label={labels.logViewer}>
          <thead>
            <tr class="border-b border-surface-tertiary text-left">
              <th class="pb-2 text-text-secondary font-medium">{labels.date}</th>
              <th class="pb-2 text-text-secondary font-medium">{labels.type}</th>
              <th class="pb-2 text-text-secondary font-medium">{labels.description}</th>
              <th class="pb-2 text-text-secondary font-medium">{labels.severity}</th>
            </tr>
          </thead>
          <tbody>
            {#each filteredLogs as log (log.id)}
              <tr class="border-b border-surface-tertiary/50">
                <td class="py-2 text-text-muted text-xs font-mono whitespace-nowrap">{log.timestamp}</td>
                <td class="py-2">
                  <span class="text-xs text-text-primary">{getOperationLabel(log.operation)}</span>
                </td>
                <td class="py-2 text-text-primary text-xs">{log.description}</td>
                <td class="py-2">
                  <span class="text-xs font-medium px-2 py-0.5 rounded {getSeverityClass(log.severity)}">
                    {getSeverityLabel(log.severity)}
                  </span>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
</div>
