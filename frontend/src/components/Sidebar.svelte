<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { healthScore } from '../lib/stores/security';

  export let currentRoute: string = '/';

  // i18n placeholder labels
  const navItems = [
    { path: '/', label: 'Dashboard', icon: 'dashboard' },
    { path: '/events', label: 'Eventos', icon: 'events' },
    { path: '/network', label: 'Rede', icon: 'network' },
    { path: '/scan', label: 'Varredura', icon: 'scan' },
    { path: '/firewall', label: 'Firewall', icon: 'firewall' },
    { path: '/hardening', label: 'Hardening', icon: 'hardening' },
    { path: '/reports', label: 'Relatórios', icon: 'reports' },
    { path: '/settings', label: 'Configurações', icon: 'settings' },
  ];

  function getHealthColor(score: number): string {
    if (score >= 80) return 'text-sec-safe';
    if (score >= 50) return 'text-sec-warning';
    return 'text-sec-danger';
  }
</script>

<aside class="w-64 h-full bg-surface-secondary border-r border-surface-tertiary flex flex-col">
  <!-- Logo + Health Score Header -->
  <div class="p-4 border-b border-surface-tertiary">
    <div class="flex items-center gap-3 mb-3">
      <img src="/logo.png" alt="LinuxSec" class="w-8 h-8 rounded-md" />
      <span class="text-sm font-bold text-text-primary">LinuxSec</span>
    </div>
    <div class="flex items-center gap-3">
      <div class="relative w-12 h-12">
        <svg class="w-12 h-12 transform -rotate-90" viewBox="0 0 36 36" aria-hidden="true">
          <path
            class="text-surface-tertiary"
            stroke="currentColor"
            stroke-width="3"
            fill="none"
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
          />
          <path
            class={getHealthColor($healthScore)}
            stroke="currentColor"
            stroke-width="3"
            stroke-dasharray="{$healthScore}, 100"
            fill="none"
            d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
          />
        </svg>
        <span
          class="absolute inset-0 flex items-center justify-center text-xs font-bold {getHealthColor($healthScore)}"
        >
          {$healthScore}
        </span>
      </div>
      <div>
        <p class="text-sm font-medium text-text-primary">Health Score</p>
        <p class="text-xs text-text-secondary">
          {#if $healthScore >= 80}
            Bom
          {:else if $healthScore >= 50}
            Atenção
          {:else}
            Crítico
          {/if}
        </p>
      </div>
    </div>
  </div>

  <!-- Navigation -->
  <nav class="flex-1 overflow-y-auto py-4" aria-label="Navegação principal">
    <ul class="space-y-1 px-2">
      {#each navItems as item}
        <li>
          <a
            href="#{item.path}"
            class="flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors duration-150
              {currentRoute === item.path
                ? 'bg-blue-600/20 text-blue-400 font-medium'
                : 'text-text-secondary hover:text-text-primary hover:bg-surface-tertiary/50'}"
            aria-current={currentRoute === item.path ? 'page' : undefined}
          >
            <span class="w-5 h-5 flex items-center justify-center" aria-hidden="true">
              {#if item.icon === 'dashboard'}
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                </svg>
              {:else if item.icon === 'events'}
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              {:else if item.icon === 'scan'}
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              {:else if item.icon === 'firewall'}
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4h18M3 8h18M3 12h18M3 16h18M3 20h18" />
                </svg>
              {:else if item.icon === 'network'}
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
                </svg>
              {:else if item.icon === 'hardening'}
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              {:else if item.icon === 'reports'}
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              {:else if item.icon === 'settings'}
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
                </svg>
              {/if}
            </span>
            <span>{item.label}</span>
          </a>
        </li>
      {/each}
    </ul>
  </nav>

  <!-- Footer -->
  <div class="p-4 border-t border-surface-tertiary">
    <p class="text-xs text-text-muted text-center">
      Security Command Center v0.1.0
    </p>
  </div>
</aside>
