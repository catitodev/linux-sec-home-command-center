<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { currentLanguage, isParanoiaMode, setLanguage, setParanoiaMode } from '../lib/stores/app';
  import type { Language } from '../lib/types';

  const labels = {
    title: 'Configurações',
    notifications: 'Notificações',
    severityThreshold: 'Limiar de Severidade',
    quietHours: 'Horário Silencioso',
    quietFrom: 'De',
    quietTo: 'Até',
    perToolToggles: 'Notificações por Ferramenta',
    language: 'Idioma',
    theme: 'Tema',
    themeDark: 'Escuro',
    themeLight: 'Claro',
    themeSystem: 'Sistema',
    session: 'Sessão',
    sessionInfo: 'Informações da Sessão',
    sessionToken: 'Token ativo',
    sessionExpires: 'Expira em',
    paranoiaMode: 'Modo Paranoia',
    paranoiaModeDesc: 'Ativa monitoramento máximo, desabilita cache e aumenta frequência de verificações. Pode impactar performance.',
    paranoiaConfirm: 'Tem certeza que deseja ativar o Modo Paranoia?',
    paranoiaWarning: 'Este modo aumenta significativamente o uso de recursos do sistema.',
    confirm: 'Confirmar',
    cancel: 'Cancelar',
    enabled: 'Ativado',
    disabled: 'Desativado',
    low: 'Baixa',
    medium: 'Média',
    high: 'Alta',
    critical: 'Crítica',
    emergency: 'Emergência',
  };

  type Theme = 'dark' | 'light' | 'system';

  interface ToolNotification {
    name: string;
    displayName: string;
    enabled: boolean;
  }

  let severityThreshold = 3;
  let quietHoursFrom = '22:00';
  let quietHoursTo = '07:00';
  let selectedTheme: Theme = 'dark';
  let showParanoiaConfirm = false;

  let toolNotifications: ToolNotification[] = [
    { name: 'clamav', displayName: 'ClamAV', enabled: true },
    { name: 'crowdsec', displayName: 'CrowdSec', enabled: true },
    { name: 'auditd', displayName: 'Auditd', enabled: true },
    { name: 'falco', displayName: 'Falco', enabled: true },
    { name: 'opensnitch', displayName: 'OpenSnitch', enabled: false },
    { name: 'osquery', displayName: 'OSQuery', enabled: true },
    { name: 'aide', displayName: 'AIDE', enabled: true },
    { name: 'lynis', displayName: 'Lynis', enabled: false },
  ];

  function getSeverityLabel(value: number): string {
    switch (value) {
      case 1: return 'Info';
      case 2: return labels.low;
      case 3: return labels.medium;
      case 4: return labels.high;
      case 5: return labels.critical;
      case 6: return labels.emergency;
      default: return String(value);
    }
  }

  function handleLanguageChange(event: Event): void {
    const target = event.target as HTMLSelectElement;
    setLanguage(target.value as Language);
  }

  function toggleToolNotification(name: string): void {
    toolNotifications = toolNotifications.map(t =>
      t.name === name ? { ...t, enabled: !t.enabled } : t
    );
  }

  function requestParanoiaToggle(): void {
    if ($isParanoiaMode) {
      setParanoiaMode(false);
    } else {
      showParanoiaConfirm = true;
    }
  }

  function confirmParanoia(): void {
    setParanoiaMode(true);
    showParanoiaConfirm = false;
  }

  function cancelParanoia(): void {
    showParanoiaConfirm = false;
  }
</script>

<div class="space-y-6">
  <h2 class="text-2xl font-bold text-text-primary">{labels.title}</h2>

  <!-- Notification Preferences -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.notifications}</h3>

    <!-- Severity Threshold Slider -->
    <div class="mb-6">
      <label for="severity-threshold" class="text-sm text-text-secondary block mb-2">
        {labels.severityThreshold}: <span class="font-medium text-text-primary">{getSeverityLabel(severityThreshold)}</span>
      </label>
      <input
        id="severity-threshold"
        type="range"
        min="1"
        max="6"
        bind:value={severityThreshold}
        class="w-full h-2 bg-surface-tertiary rounded-lg appearance-none cursor-pointer accent-blue-500"
        aria-valuemin={1}
        aria-valuemax={6}
        aria-valuenow={severityThreshold}
        aria-valuetext={getSeverityLabel(severityThreshold)}
      />
      <div class="flex justify-between text-xs text-text-muted mt-1">
        <span>Info</span>
        <span>Emergência</span>
      </div>
    </div>

    <!-- Quiet Hours -->
    <div class="mb-6">
      <p class="text-sm text-text-secondary mb-2">{labels.quietHours}</p>
      <div class="flex items-center gap-3">
        <div>
          <label for="quiet-from" class="text-xs text-text-muted block mb-1">{labels.quietFrom}</label>
          <input
            id="quiet-from"
            type="time"
            bind:value={quietHoursFrom}
            class="px-3 py-1.5 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <span class="text-text-muted mt-4">—</span>
        <div>
          <label for="quiet-to" class="text-xs text-text-muted block mb-1">{labels.quietTo}</label>
          <input
            id="quiet-to"
            type="time"
            bind:value={quietHoursTo}
            class="px-3 py-1.5 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
      </div>
    </div>

    <!-- Per-Tool Toggles -->
    <div>
      <p class="text-sm text-text-secondary mb-3">{labels.perToolToggles}</p>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {#each toolNotifications as tool (tool.name)}
          <div class="flex items-center justify-between p-2 rounded-md bg-surface-tertiary/30">
            <span class="text-sm text-text-primary">{tool.displayName}</span>
            <button
              on:click={() => toggleToolNotification(tool.name)}
              class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 {tool.enabled ? 'bg-blue-600' : 'bg-surface-tertiary'}"
              type="button"
              role="switch"
              aria-checked={tool.enabled}
              aria-label="{tool.displayName}: {tool.enabled ? labels.enabled : labels.disabled}"
            >
              <span
                class="inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform {tool.enabled ? 'translate-x-4.5' : 'translate-x-0.5'}"
                aria-hidden="true"
              ></span>
            </button>
          </div>
        {/each}
      </div>
    </div>
  </div>

  <!-- Language & Theme -->
  <div class="glass-panel p-6">
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-6">
      <!-- Language -->
      <div>
        <label for="language-select" class="text-sm text-text-secondary block mb-2">{labels.language}</label>
        <select
          id="language-select"
          value={$currentLanguage}
          on:change={handleLanguageChange}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="pt-BR">Português (Brasil)</option>
          <option value="en-US">English (US)</option>
        </select>
      </div>

      <!-- Theme -->
      <div>
        <label for="theme-select" class="text-sm text-text-secondary block mb-2">{labels.theme}</label>
        <select
          id="theme-select"
          bind:value={selectedTheme}
          class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="dark">{labels.themeDark}</option>
          <option value="light">{labels.themeLight}</option>
          <option value="system">{labels.themeSystem}</option>
        </select>
      </div>
    </div>
  </div>

  <!-- Session Info -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.sessionInfo}</h3>
    <div class="space-y-2">
      <div class="flex items-center justify-between">
        <span class="text-sm text-text-secondary">{labels.sessionToken}</span>
        <span class="text-sm text-text-primary font-mono">••••••••</span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-sm text-text-secondary">{labels.sessionExpires}</span>
        <span class="text-sm text-text-primary">30 minutos</span>
      </div>
    </div>
  </div>

  <!-- Paranoia Mode -->
  <div class="glass-panel p-6 border {$isParanoiaMode ? 'border-sec-danger/50' : 'border-surface-tertiary'}">
    <div class="flex items-start justify-between gap-4">
      <div>
        <h3 class="text-lg font-semibold text-text-primary">{labels.paranoiaMode}</h3>
        <p class="text-sm text-text-muted mt-1">{labels.paranoiaModeDesc}</p>
      </div>
      <button
        on:click={requestParanoiaToggle}
        class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 flex-shrink-0 {$isParanoiaMode ? 'bg-sec-danger' : 'bg-surface-tertiary'}"
        type="button"
        role="switch"
        aria-checked={$isParanoiaMode}
        aria-label="{labels.paranoiaMode}: {$isParanoiaMode ? labels.enabled : labels.disabled}"
      >
        <span
          class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform {$isParanoiaMode ? 'translate-x-6' : 'translate-x-1'}"
          aria-hidden="true"
        ></span>
      </button>
    </div>
  </div>

  <!-- Paranoia Confirmation Dialog -->
  {#if showParanoiaConfirm}
    <div
      class="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      role="dialog"
      aria-modal="true"
      aria-labelledby="paranoia-dialog-title"
    >
      <div class="glass-panel p-6 max-w-md mx-4 border border-sec-danger/30">
        <h4 id="paranoia-dialog-title" class="text-lg font-semibold text-text-primary mb-2">
          {labels.paranoiaConfirm}
        </h4>
        <p class="text-sm text-text-muted mb-6">{labels.paranoiaWarning}</p>
        <div class="flex justify-end gap-3">
          <button
            on:click={cancelParanoia}
            class="px-4 py-2 text-sm text-text-secondary hover:text-text-primary bg-surface-tertiary rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
            type="button"
          >
            {labels.cancel}
          </button>
          <button
            on:click={confirmParanoia}
            class="px-4 py-2 text-sm text-white bg-sec-danger hover:bg-red-700 rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-sec-danger"
            type="button"
          >
            {labels.confirm}
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>
