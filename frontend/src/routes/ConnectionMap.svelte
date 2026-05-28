<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { onMount, onDestroy } from 'svelte';

  const labels = {
    title: 'Mapa de Conexões de Rede',
    filterProcess: 'Filtrar por processo',
    filterDest: 'Filtrar por destino',
    filterPortMin: 'Porta mín.',
    filterPortMax: 'Porta máx.',
    apply: 'Aplicar',
    clear: 'Limpar',
    protocol: 'Protocolo',
    port: 'Porta',
    volume: 'Volume',
    duration: 'Duração',
    blocked: 'Bloqueado (CrowdSec)',
    autoRefresh: 'Atualização automática: 10s',
    noConnections: 'Nenhuma conexão ativa',
    placeholder: 'Implementação completa com D3.js em iteração futura',
    legend: 'Legenda',
    legendNormal: 'Conexão normal',
    legendBlocked: 'IP na blocklist',
    legendProcess: 'Processo',
  };

  // Mock connection data structure for visualization
  interface Connection {
    id: string;
    processName: string;
    processId: number;
    destIp: string;
    destPort: number;
    protocol: string;
    dataVolume: string;
    duration: string;
    blocked: boolean;
  }

  let connections: Connection[] = [];
  let serverOffline = false;

  let filterProcess = '';
  let filterDest = '';
  let filterPortMin = '';
  let filterPortMax = '';
  let refreshInterval: ReturnType<typeof setInterval> | null = null;

  async function loadData(): Promise<void> {
    serverOffline = false;
    try {
      const response = await fetch('http://127.0.0.1:3030/api/network/connections');
      if (!response.ok) throw new Error('Server error');
      const data = await response.json();
      connections = data.connections || [];
    } catch {
      serverOffline = true;
      connections = [];
    }
  }

  $: filteredConnections = connections.filter((conn) => {
    if (filterProcess && !conn.processName.toLowerCase().includes(filterProcess.toLowerCase())) return false;
    if (filterDest && !conn.destIp.includes(filterDest)) return false;
    if (filterPortMin && conn.destPort < parseInt(filterPortMin)) return false;
    if (filterPortMax && conn.destPort > parseInt(filterPortMax)) return false;
    return true;
  });

  function clearFilters(): void {
    filterProcess = '';
    filterDest = '';
    filterPortMin = '';
    filterPortMax = '';
  }

  // SVG graph layout calculations
  const svgWidth = 800;
  const svgHeight = 500;

  function getNodePositions(conns: Connection[]) {
    const processes = [...new Set(conns.map(c => c.processName))];
    const destinations = [...new Set(conns.map(c => c.destIp))];

    const processNodes = processes.map((name, i) => ({
      id: `proc-${name}`,
      label: name,
      x: 150,
      y: 60 + i * (svgHeight - 120) / Math.max(processes.length - 1, 1),
      type: 'process' as const,
    }));

    const destNodes = destinations.map((ip, i) => ({
      id: `dest-${ip}`,
      label: ip,
      x: svgWidth - 150,
      y: 60 + i * (svgHeight - 120) / Math.max(destinations.length - 1, 1),
      type: 'destination' as const,
    }));

    const edges = conns.map(c => ({
      from: `proc-${c.processName}`,
      to: `dest-${c.destIp}`,
      blocked: c.blocked,
      port: c.destPort,
      protocol: c.protocol,
    }));

    return { processNodes, destNodes, edges };
  }

  $: graph = getNodePositions(filteredConnections);

  function getNodeX(id: string): number {
    const node = [...graph.processNodes, ...graph.destNodes].find(n => n.id === id);
    return node?.x ?? 0;
  }

  function getNodeY(id: string): number {
    const node = [...graph.processNodes, ...graph.destNodes].find(n => n.id === id);
    return node?.y ?? 0;
  }

  onMount(() => {
    loadData();
    // Auto-refresh every 10 seconds
    refreshInterval = setInterval(() => {
      loadData();
    }, 10000);
  });

  onDestroy(() => {
    if (refreshInterval) {
      clearInterval(refreshInterval);
    }
  });
</script>

<div class="space-y-6">
  <div class="flex items-center justify-between">
    <h2 class="text-2xl font-bold text-text-primary">{labels.title}</h2>
    <span class="text-xs text-text-muted bg-surface-tertiary px-2 py-1 rounded">{labels.autoRefresh}</span>
  </div>

  <!-- Filter Controls -->
  <div class="glass-panel p-4">
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
      <div>
        <label for="filter-process" class="sr-only">{labels.filterProcess}</label>
        <input
          id="filter-process"
          type="text"
          bind:value={filterProcess}
          placeholder={labels.filterProcess}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterProcess}
        />
      </div>
      <div>
        <label for="filter-dest" class="sr-only">{labels.filterDest}</label>
        <input
          id="filter-dest"
          type="text"
          bind:value={filterDest}
          placeholder={labels.filterDest}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterDest}
        />
      </div>
      <div>
        <label for="filter-port-min" class="sr-only">{labels.filterPortMin}</label>
        <input
          id="filter-port-min"
          type="number"
          bind:value={filterPortMin}
          placeholder={labels.filterPortMin}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterPortMin}
        />
      </div>
      <div>
        <label for="filter-port-max" class="sr-only">{labels.filterPortMax}</label>
        <input
          id="filter-port-max"
          type="number"
          bind:value={filterPortMax}
          placeholder={labels.filterPortMax}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label={labels.filterPortMax}
        />
      </div>
      <div>
        <button
          on:click={clearFilters}
          class="w-full px-3 py-2 text-sm text-blue-400 hover:text-blue-300 border border-surface-tertiary rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
          type="button"
        >
          {labels.clear}
        </button>
      </div>
    </div>
  </div>

  <!-- SVG Network Graph -->
  <div class="glass-panel p-4 overflow-x-auto">
    <p class="text-xs text-text-muted mb-3 italic">{labels.placeholder}</p>

    {#if serverOffline}
      <div class="flex items-center justify-center h-64">
        <p class="text-sec-warning">⚠ Servidor de varredura offline</p>
      </div>
    {:else if filteredConnections.length === 0}
      <div class="flex items-center justify-center h-64">
        <p class="text-text-muted">Nenhuma conexão monitorada. Inicie o OpenSnitch para visualizar conexões.</p>
      </div>
    {:else}
      <svg
        viewBox="0 0 {svgWidth} {svgHeight}"
        class="w-full h-auto max-h-[500px]"
        role="img"
        aria-label={labels.title}
      >
        <!-- Edges -->
        {#each graph.edges as edge}
          <line
            x1={getNodeX(edge.from)}
            y1={getNodeY(edge.from)}
            x2={getNodeX(edge.to)}
            y2={getNodeY(edge.to)}
            stroke={edge.blocked ? '#ef4444' : '#6b7280'}
            stroke-width={edge.blocked ? 2.5 : 1.5}
            stroke-dasharray={edge.blocked ? '5,3' : 'none'}
            opacity="0.7"
          />
          <!-- Port label on edge -->
          <text
            x={(getNodeX(edge.from) + getNodeX(edge.to)) / 2}
            y={(getNodeY(edge.from) + getNodeY(edge.to)) / 2 - 8}
            text-anchor="middle"
            class="text-[10px] fill-text-muted"
          >
            {edge.protocol}:{edge.port}
          </text>
        {/each}

        <!-- Process Nodes -->
        {#each graph.processNodes as node}
          <g>
            <circle
              cx={node.x}
              cy={node.y}
              r="20"
              fill="#1e40af"
              opacity="0.8"
              stroke="#3b82f6"
              stroke-width="2"
            />
            <text
              x={node.x}
              y={node.y + 35}
              text-anchor="middle"
              class="text-xs fill-text-primary"
            >
              {node.label}
            </text>
          </g>
        {/each}

        <!-- Destination Nodes -->
        {#each graph.destNodes as node}
          {@const isBlocked = filteredConnections.some(c => c.destIp === node.label && c.blocked)}
          <g>
            <circle
              cx={node.x}
              cy={node.y}
              r="16"
              fill={isBlocked ? '#991b1b' : '#374151'}
              opacity="0.8"
              stroke={isBlocked ? '#ef4444' : '#6b7280'}
              stroke-width="2"
            />
            <text
              x={node.x}
              y={node.y + 30}
              text-anchor="middle"
              class="text-[10px] {isBlocked ? 'fill-sec-danger' : 'fill-text-secondary'}"
            >
              {node.label}
            </text>
            {#if isBlocked}
              <text
                x={node.x}
                y={node.y + 42}
                text-anchor="middle"
                class="text-[9px] fill-sec-danger font-bold"
              >
                ⚠ BLOQUEADO
              </text>
            {/if}
          </g>
        {/each}
      </svg>

      <!-- Legend -->
      <div class="mt-4 flex items-center gap-6 text-xs text-text-muted" aria-label={labels.legend}>
        <div class="flex items-center gap-2">
          <span class="w-3 h-3 rounded-full bg-blue-700 border border-blue-500" aria-hidden="true"></span>
          <span>{labels.legendProcess}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="w-6 h-0.5 bg-gray-500" aria-hidden="true"></span>
          <span>{labels.legendNormal}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="w-6 h-0.5 bg-red-500 border-dashed" aria-hidden="true"></span>
          <span>{labels.legendBlocked}</span>
        </div>
      </div>
    {/if}
  </div>

  <!-- Connection Details Table -->
  <div class="glass-panel p-4 overflow-x-auto">
    <table class="w-full text-sm" aria-label="Detalhes das conexões">
      <thead>
        <tr class="border-b border-surface-tertiary text-left">
          <th class="pb-2 text-text-secondary font-medium">Processo</th>
          <th class="pb-2 text-text-secondary font-medium">Destino</th>
          <th class="pb-2 text-text-secondary font-medium">{labels.protocol}</th>
          <th class="pb-2 text-text-secondary font-medium">{labels.port}</th>
          <th class="pb-2 text-text-secondary font-medium">{labels.volume}</th>
          <th class="pb-2 text-text-secondary font-medium">{labels.duration}</th>
          <th class="pb-2 text-text-secondary font-medium">Status</th>
        </tr>
      </thead>
      <tbody>
        {#each filteredConnections as conn (conn.id)}
          <tr class="border-b border-surface-tertiary/50 {conn.blocked ? 'bg-sec-danger/5' : ''}">
            <td class="py-2 text-text-primary">{conn.processName}</td>
            <td class="py-2 text-text-primary font-mono text-xs">{conn.destIp}</td>
            <td class="py-2 text-text-muted">{conn.protocol}</td>
            <td class="py-2 text-text-muted">{conn.destPort}</td>
            <td class="py-2 text-text-muted">{conn.dataVolume}</td>
            <td class="py-2 text-text-muted">{conn.duration}</td>
            <td class="py-2">
              {#if conn.blocked}
                <span class="text-xs font-medium bg-sec-danger/20 text-sec-danger px-2 py-0.5 rounded">
                  ⚠ {labels.blocked}
                </span>
              {:else}
                <span class="text-xs text-sec-safe">✓ OK</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>
