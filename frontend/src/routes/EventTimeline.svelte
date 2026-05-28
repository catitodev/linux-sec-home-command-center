<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { filteredEvents, eventsLoading, setFilters, clearFilters } from '../lib/stores/events';
  import type { EventType } from '../lib/types';

  const labels = {
    title: 'Linha do Tempo de Eventos',
    filterTool: 'Ferramenta',
    filterSeverity: 'Severidade',
    filterType: 'Tipo de Evento',
    filterTimeFrom: 'De',
    filterTimeTo: 'Até',
    search: 'Buscar eventos...',
    clearFilters: 'Limpar Filtros',
    loadMore: 'Carregar Mais',
    noEvents: 'Nenhum evento registrado. O sistema está limpo ou aguardando a primeira varredura.',
    loading: 'Carregando eventos...',
    all: 'Todos',
    correlatedGroup: 'Incidente Correlacionado',
    expand: 'Expandir',
    collapse: 'Recolher',
  };

  const toolOptions = [
    { value: '', label: labels.all },
    { value: 'clamav', label: 'ClamAV' },
    { value: 'crowdsec', label: 'CrowdSec' },
    { value: 'auditd', label: 'Auditd' },
    { value: 'falco', label: 'Falco' },
    { value: 'opensnitch', label: 'OpenSnitch' },
    { value: 'osquery', label: 'OSQuery' },
    { value: 'aide', label: 'AIDE' },
    { value: 'lynis', label: 'Lynis' },
  ];

  const severityOptions = [
    { value: '', label: labels.all },
    { value: '1', label: 'Info' },
    { value: '2', label: 'Baixa' },
    { value: '3', label: 'Média' },
    { value: '4', label: 'Alta' },
    { value: '5', label: 'Crítica' },
    { value: '6', label: 'Emergência' },
  ];

  const eventTypeOptions: { value: string; label: string }[] = [
    { value: '', label: labels.all },
    { value: 'process_anomaly', label: 'Anomalia de Processo' },
    { value: 'network_connection', label: 'Conexão de Rede' },
    { value: 'file_modification', label: 'Modificação de Arquivo' },
    { value: 'privilege_escalation', label: 'Escalação de Privilégio' },
    { value: 'malware_detection', label: 'Detecção de Malware' },
    { value: 'intrusion_attempt', label: 'Tentativa de Intrusão' },
    { value: 'policy_violation', label: 'Violação de Política' },
    { value: 'configuration_change', label: 'Mudança de Configuração' },
    { value: 'authentication_event', label: 'Evento de Autenticação' },
    { value: 'device_event', label: 'Evento de Dispositivo' },
  ];

  let searchQuery = '';
  let selectedTool = '';
  let selectedSeverity = '';
  let selectedType = '';
  let visibleCount = 50;
  let expandedCorrelations: Set<string> = new Set();

  function handleSearch(): void {
    setFilters({ search: searchQuery || null });
  }

  function handleToolChange(): void {
    setFilters({ tool: selectedTool || null });
  }

  function handleSeverityChange(): void {
    setFilters({ severity: selectedSeverity ? parseInt(selectedSeverity) : null });
  }

  function handleTypeChange(): void {
    setFilters({ event_type: (selectedType as EventType) || null });
  }

  function handleClearFilters(): void {
    searchQuery = '';
    selectedTool = '';
    selectedSeverity = '';
    selectedType = '';
    clearFilters();
  }

  function loadMore(): void {
    visibleCount += 50;
  }

  function toggleCorrelation(id: string): void {
    if (expandedCorrelations.has(id)) {
      expandedCorrelations.delete(id);
    } else {
      expandedCorrelations.add(id);
    }
    expandedCorrelations = expandedCorrelations; // trigger reactivity
  }

  function getSeverityClass(severity: number): string {
    if (severity >= 5) return 'border-l-sec-danger bg-sec-danger/5';
    if (severity >= 4) return 'border-l-sec-warning bg-sec-warning/5';
    if (severity >= 3) return 'border-l-yellow-600/50';
    return 'border-l-surface-tertiary';
  }

  function getSeverityBadge(severity: number): string {
    if (severity >= 6) return 'Emergência';
    if (severity >= 5) return 'Crítica';
    if (severity >= 4) return 'Alta';
    if (severity >= 3) return 'Média';
    if (severity >= 2) return 'Baixa';
    return 'Info';
  }

  function getSeverityBadgeClass(severity: number): string {
    if (severity >= 5) return 'bg-sec-danger/20 text-sec-danger';
    if (severity >= 4) return 'bg-sec-warning/20 text-sec-warning';
    if (severity >= 3) return 'bg-yellow-600/20 text-yellow-500';
    return 'bg-blue-600/20 text-blue-400';
  }

  function formatTime(isoString: string): string {
    try {
      const date = new Date(isoString);
      return date.toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'medium' });
    } catch {
      return isoString;
    }
  }

  $: visibleEvents = $filteredEvents.slice(0, visibleCount);
  $: hasMore = $filteredEvents.length > visibleCount;

  // Group correlated events
  $: correlatedGroups = (() => {
    const groups = new Map<string, typeof visibleEvents>();
    const standalone: typeof visibleEvents = [];
    for (const event of visibleEvents) {
      if (event.correlated && event.correlation_id) {
        const existing = groups.get(event.correlation_id) || [];
        existing.push(event);
        groups.set(event.correlation_id, existing);
      } else {
        standalone.push(event);
      }
    }
    return { groups, standalone };
  })();
</script>

<div class="space-y-6">
  <h2 class="text-2xl font-bold text-text-primary">{labels.title}</h2>

  <!-- Filter Bar -->
  <div class="glass-panel p-4">
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
      <!-- Search -->
      <div class="lg:col-span-2">
        <label for="event-search" class="sr-only">{labels.search}</label>
        <input
          id="event-search"
          type="search"
          bind:value={searchQuery}
          on:input={handleSearch}
          placeholder={labels.search}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.search}
        />
      </div>

      <!-- Tool Filter -->
      <div>
        <label for="filter-tool" class="sr-only">{labels.filterTool}</label>
        <select
          id="filter-tool"
          bind:value={selectedTool}
          on:change={handleToolChange}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterTool}
        >
          {#each toolOptions as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
      </div>

      <!-- Severity Filter -->
      <div>
        <label for="filter-severity" class="sr-only">{labels.filterSeverity}</label>
        <select
          id="filter-severity"
          bind:value={selectedSeverity}
          on:change={handleSeverityChange}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterSeverity}
        >
          {#each severityOptions as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
      </div>

      <!-- Event Type Filter -->
      <div>
        <label for="filter-type" class="sr-only">{labels.filterType}</label>
        <select
          id="filter-type"
          bind:value={selectedType}
          on:change={handleTypeChange}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterType}
        >
          {#each eventTypeOptions as opt}
            <option value={opt.value}>{opt.label}</option>
          {/each}
        </select>
      </div>
    </div>

    <!-- Clear Filters -->
    <div class="mt-3 flex justify-end">
      <button
        on:click={handleClearFilters}
        class="text-sm text-blue-400 hover:text-blue-300 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 rounded px-2 py-1"
        type="button"
      >
        {labels.clearFilters}
      </button>
    </div>
  </div>

  <!-- Event List -->
  <div class="space-y-2" role="feed" aria-label={labels.title}>
    {#if $eventsLoading}
      <div class="glass-panel p-8 text-center">
        <p class="text-text-muted">{labels.loading}</p>
      </div>
    {:else if $filteredEvents.length === 0}
      <div class="glass-panel p-8 text-center">
        <p class="text-text-muted">{labels.noEvents}</p>
      </div>
    {:else}
      <!-- Correlated Groups -->
      {#each [...correlatedGroups.groups.entries()] as [correlationId, groupEvents]}
        <div class="glass-panel border-l-4 border-l-blue-500 overflow-hidden">
          <button
            on:click={() => toggleCorrelation(correlationId)}
            class="w-full p-4 flex items-center justify-between text-left hover:bg-surface-tertiary/30 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-inset"
            type="button"
            aria-expanded={expandedCorrelations.has(correlationId)}
          >
            <div class="flex items-center gap-3">
              <span class="text-xs font-medium bg-blue-600/20 text-blue-400 px-2 py-0.5 rounded">
                {labels.correlatedGroup}
              </span>
              <span class="text-sm text-text-secondary">{groupEvents.length} eventos</span>
            </div>
            <span class="text-text-muted text-sm" aria-hidden="true">
              {expandedCorrelations.has(correlationId) ? '▼' : '▶'}
            </span>
          </button>
          {#if expandedCorrelations.has(correlationId)}
            <div class="border-t border-surface-tertiary">
              {#each groupEvents as event (event.id)}
                <div class="p-4 border-b border-surface-tertiary/50 last:border-b-0 {getSeverityClass(event.severity)}" role="article">
                  <div class="flex items-start justify-between gap-4">
                    <div class="min-w-0 flex-1">
                      <div class="flex items-center gap-2 flex-wrap">
                        <span class="text-xs font-medium px-2 py-0.5 rounded {getSeverityBadgeClass(event.severity)}">
                          {getSeverityBadge(event.severity)}
                        </span>
                        <span class="text-xs text-text-muted">{event.source_tool}</span>
                        <span class="text-xs text-text-muted">•</span>
                        <time class="text-xs text-text-muted" datetime={event.created_at}>
                          {formatTime(event.created_at)}
                        </time>
                      </div>
                      <p class="text-sm text-text-primary mt-1">{event.description}</p>
                      <p class="text-xs text-text-muted mt-1">{event.entity_type}: {event.entity_id}</p>
                    </div>
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}

      <!-- Standalone Events -->
      {#each correlatedGroups.standalone as event (event.id)}
        <div
          class="glass-panel p-4 border-l-4 {getSeverityClass(event.severity)} {event.severity >= 5 ? 'animate-pulse-once' : ''}"
          role="article"
          aria-label="Evento: {event.description}"
        >
          <div class="flex items-start justify-between gap-4">
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="text-xs font-medium px-2 py-0.5 rounded {getSeverityBadgeClass(event.severity)}">
                  {getSeverityBadge(event.severity)}
                </span>
                <span class="text-xs text-text-muted">{event.source_tool}</span>
                <span class="text-xs text-text-muted">•</span>
                <time class="text-xs text-text-muted" datetime={event.created_at}>
                  {formatTime(event.created_at)}
                </time>
              </div>
              <p class="text-sm text-text-primary mt-1">{event.description}</p>
              <p class="text-xs text-text-muted mt-1">{event.entity_type}: {event.entity_id}</p>
            </div>
          </div>
        </div>
      {/each}

      <!-- Load More -->
      {#if hasMore}
        <div class="flex justify-center pt-4">
          <button
            on:click={loadMore}
            class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-surface-primary"
            type="button"
          >
            {labels.loadMore}
          </button>
        </div>
      {/if}
    {/if}
  </div>
</div>

<style>
  @keyframes pulse-once {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.7; }
  }
  :global(.animate-pulse-once) {
    animation: pulse-once 1.5s ease-in-out 2;
  }
</style>
