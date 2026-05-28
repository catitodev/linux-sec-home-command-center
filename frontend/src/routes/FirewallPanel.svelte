<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { onMount } from 'svelte';

  const labels = {
    title: 'Firewall e Dispositivos',
    rulesTitle: 'Regras de Firewall Ativas',
    addRule: 'Adicionar Regra',
    removeRule: 'Remover',
    direction: 'Direção',
    source: 'Origem',
    destination: 'Destino',
    port: 'Porta',
    protocol: 'Protocolo',
    action: 'Ação',
    inbound: 'Entrada',
    outbound: 'Saída',
    allow: 'Permitir',
    deny: 'Negar',
    portAudit: 'Auditoria de Portas',
    portAuditDesc: 'Discrepâncias entre portas abertas e regras configuradas',
    noDiscrepancies: 'Nenhuma discrepância encontrada',
    usbDevices: 'Dispositivos USB',
    approve: 'Aprovar',
    block: 'Bloquear',
    connected: 'Conectado',
    disconnected: 'Desconectado',
    quarantine: 'Quarentena',
    restore: 'Restaurar',
    delete: 'Excluir',
    quarantinedAt: 'Quarentenado em',
    noQuarantined: 'Nenhum arquivo em quarentena',
    noRules: 'Nenhuma regra configurada',
    noDevices: 'Nenhum dispositivo USB detectado',
    cancel: 'Cancelar',
    save: 'Salvar',
    any: 'Qualquer',
  };

  interface FirewallRule {
    id: string;
    direction: 'inbound' | 'outbound';
    source: string;
    destination: string;
    port: string;
    protocol: string;
    action: 'allow' | 'deny';
  }

  interface PortDiscrepancy {
    port: number;
    protocol: string;
    issue: string;
  }

  interface UsbDevice {
    id: string;
    name: string;
    vendor: string;
    serial: string;
    status: 'connected' | 'disconnected';
    approved: boolean;
    lastSeen: string;
  }

  interface QuarantinedFile {
    id: string;
    path: string;
    reason: string;
    quarantinedAt: string;
    size: string;
  }

  let rules: FirewallRule[] = [];

  let portDiscrepancies: PortDiscrepancy[] = [];

  let usbDevices: UsbDevice[] = [];

  let quarantinedFiles: QuarantinedFile[] = [];

  let serverOffline = false;

  let showAddForm = false;
  let newRule: Omit<FirewallRule, 'id'> = {
    direction: 'inbound',
    source: '',
    destination: '',
    port: '',
    protocol: 'TCP',
    action: 'deny',
  };

  async function loadData(): Promise<void> {
    serverOffline = false;
    try {
      const response = await fetch('http://127.0.0.1:3030/api/firewall/status');
      if (!response.ok) throw new Error('Server error');
      const data = await response.json();
      // Parse UFW numbered output into rules
      if (data.output) {
        const lines = data.output.split('\n').filter((l: string) => l.match(/^\[\s*\d+\]/));
        rules = lines.map((l: string, i: number) => {
          const allowMatch = l.toLowerCase().includes('allow');
          const denyMatch = l.toLowerCase().includes('deny') || l.toLowerCase().includes('reject');
          const portMatch = l.match(/(\d+)(?:\/(\w+))?/);
          const inMatch = l.toLowerCase().includes('in');
          return {
            id: String(i),
            direction: inMatch ? 'inbound' as const : 'outbound' as const,
            source: l.match(/from\s+(\S+)/i)?.[1] || '*',
            destination: l.match(/to\s+(\S+)/i)?.[1] || '*',
            port: portMatch?.[1] || '*',
            protocol: portMatch?.[2]?.toUpperCase() || 'TCP',
            action: allowMatch ? 'allow' as const : 'deny' as const,
          };
        });
      }
    } catch {
      serverOffline = true;
    }
  }

  onMount(() => {
    loadData();
  });

  function addRule(): void {
    if (!newRule.port) return;
    rules = [...rules, { ...newRule, id: Date.now().toString() }];
    showAddForm = false;
    newRule = { direction: 'inbound', source: '', destination: '', port: '', protocol: 'TCP', action: 'deny' };
  }

  function removeRule(id: string): void {
    rules = rules.filter(r => r.id !== id);
  }

  function approveDevice(id: string): void {
    usbDevices = usbDevices.map(d => d.id === id ? { ...d, approved: true } : d);
  }

  function blockDevice(id: string): void {
    usbDevices = usbDevices.map(d => d.id === id ? { ...d, approved: false } : d);
  }

  function restoreFile(id: string): void {
    quarantinedFiles = quarantinedFiles.filter(f => f.id !== id);
  }

  function deleteFile(id: string): void {
    quarantinedFiles = quarantinedFiles.filter(f => f.id !== id);
  }
</script>

<div class="space-y-6">
  <h2 class="text-2xl font-bold text-text-primary">{labels.title}</h2>

  {#if serverOffline}
    <div class="glass-panel p-8 text-center">
      <p class="text-sec-warning">⚠ Servidor de varredura offline</p>
    </div>
  {/if}

  <!-- Firewall Rules Table -->
  <div class="glass-panel p-6">
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-lg font-semibold text-text-primary">{labels.rulesTitle}</h3>
      <button
        on:click={() => showAddForm = !showAddForm}
        class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
        type="button"
        aria-expanded={showAddForm}
      >
        {showAddForm ? labels.cancel : labels.addRule}
      </button>
    </div>

    <!-- Add Rule Form -->
    {#if showAddForm}
      <div class="mb-4 p-4 bg-surface-tertiary/30 rounded-md border border-surface-tertiary">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
          <div>
            <label for="new-direction" class="text-xs text-text-secondary block mb-1">{labels.direction}</label>
            <select
              id="new-direction"
              bind:value={newRule.direction}
              class="w-full px-2 py-1.5 bg-surface-tertiary border border-surface-tertiary rounded text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="inbound">{labels.inbound}</option>
              <option value="outbound">{labels.outbound}</option>
            </select>
          </div>
          <div>
            <label for="new-source" class="text-xs text-text-secondary block mb-1">{labels.source}</label>
            <input
              id="new-source"
              type="text"
              bind:value={newRule.source}
              placeholder="0.0.0.0/0"
              class="w-full px-2 py-1.5 bg-surface-tertiary border border-surface-tertiary rounded text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label for="new-dest" class="text-xs text-text-secondary block mb-1">{labels.destination}</label>
            <input
              id="new-dest"
              type="text"
              bind:value={newRule.destination}
              placeholder="*"
              class="w-full px-2 py-1.5 bg-surface-tertiary border border-surface-tertiary rounded text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label for="new-port" class="text-xs text-text-secondary block mb-1">{labels.port}</label>
            <input
              id="new-port"
              type="text"
              bind:value={newRule.port}
              placeholder="443"
              class="w-full px-2 py-1.5 bg-surface-tertiary border border-surface-tertiary rounded text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label for="new-protocol" class="text-xs text-text-secondary block mb-1">{labels.protocol}</label>
            <select
              id="new-protocol"
              bind:value={newRule.protocol}
              class="w-full px-2 py-1.5 bg-surface-tertiary border border-surface-tertiary rounded text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="*">{labels.any}</option>
            </select>
          </div>
          <div>
            <label for="new-action" class="text-xs text-text-secondary block mb-1">{labels.action}</label>
            <div class="flex gap-2">
              <select
                id="new-action"
                bind:value={newRule.action}
                class="flex-1 px-2 py-1.5 bg-surface-tertiary border border-surface-tertiary rounded text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="allow">{labels.allow}</option>
                <option value="deny">{labels.deny}</option>
              </select>
              <button
                on:click={addRule}
                class="px-3 py-1.5 bg-sec-safe/20 text-sec-safe text-sm rounded hover:bg-sec-safe/30 transition-colors focus:outline-none focus:ring-2 focus:ring-sec-safe"
                type="button"
                aria-label={labels.save}
              >
                ✓
              </button>
            </div>
          </div>
        </div>
      </div>
    {/if}

    <!-- Rules Table -->
    {#if rules.length === 0}
      <p class="text-text-muted">{labels.noRules}</p>
    {:else}
      <div class="overflow-x-auto">
        <table class="w-full text-sm" aria-label={labels.rulesTitle}>
          <thead>
            <tr class="border-b border-surface-tertiary text-left">
              <th class="pb-2 text-text-secondary font-medium">{labels.direction}</th>
              <th class="pb-2 text-text-secondary font-medium">{labels.source}</th>
              <th class="pb-2 text-text-secondary font-medium">{labels.destination}</th>
              <th class="pb-2 text-text-secondary font-medium">{labels.port}</th>
              <th class="pb-2 text-text-secondary font-medium">{labels.protocol}</th>
              <th class="pb-2 text-text-secondary font-medium">{labels.action}</th>
              <th class="pb-2 text-text-secondary font-medium"><span class="sr-only">Ações</span></th>
            </tr>
          </thead>
          <tbody>
            {#each rules as rule (rule.id)}
              <tr class="border-b border-surface-tertiary/50">
                <td class="py-2 text-text-primary">
                  <span class="text-xs px-2 py-0.5 rounded {rule.direction === 'inbound' ? 'bg-blue-600/20 text-blue-400' : 'bg-purple-600/20 text-purple-400'}">
                    {rule.direction === 'inbound' ? labels.inbound : labels.outbound}
                  </span>
                </td>
                <td class="py-2 text-text-muted font-mono text-xs">{rule.source || '*'}</td>
                <td class="py-2 text-text-muted font-mono text-xs">{rule.destination || '*'}</td>
                <td class="py-2 text-text-muted">{rule.port}</td>
                <td class="py-2 text-text-muted">{rule.protocol}</td>
                <td class="py-2">
                  <span class="text-xs font-medium px-2 py-0.5 rounded {rule.action === 'allow' ? 'bg-sec-safe/20 text-sec-safe' : 'bg-sec-danger/20 text-sec-danger'}">
                    {rule.action === 'allow' ? labels.allow : labels.deny}
                  </span>
                </td>
                <td class="py-2">
                  <button
                    on:click={() => removeRule(rule.id)}
                    class="text-xs text-sec-danger hover:text-red-400 transition-colors focus:outline-none focus:ring-2 focus:ring-sec-danger rounded px-1"
                    type="button"
                    aria-label="{labels.removeRule} regra porta {rule.port}"
                  >
                    {labels.removeRule}
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>

  <!-- Port Audit -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-2">{labels.portAudit}</h3>
    <p class="text-xs text-text-muted mb-4">{labels.portAuditDesc}</p>
    {#if portDiscrepancies.length === 0}
      <p class="text-sec-safe text-sm">✓ {labels.noDiscrepancies}</p>
    {:else}
      <div class="space-y-2">
        {#each portDiscrepancies as disc}
          <div class="flex items-center gap-3 p-3 rounded-md bg-sec-warning/5 border border-sec-warning/20">
            <span class="text-sec-warning" aria-hidden="true">⚠</span>
            <div>
              <p class="text-sm text-text-primary font-mono">{disc.protocol}:{disc.port}</p>
              <p class="text-xs text-text-muted">{disc.issue}</p>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- USB Devices -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.usbDevices}</h3>
    {#if usbDevices.length === 0}
      <p class="text-text-muted">{labels.noDevices}</p>
    {:else}
      <div class="space-y-3">
        {#each usbDevices as device (device.id)}
          <div class="flex items-center justify-between p-3 rounded-md bg-surface-tertiary/30 border border-surface-tertiary">
            <div class="flex items-center gap-3">
              <span
                class="w-2 h-2 rounded-full {device.status === 'connected' ? 'bg-sec-safe' : 'bg-text-muted'}"
                aria-label={device.status === 'connected' ? labels.connected : labels.disconnected}
              ></span>
              <div>
                <p class="text-sm text-text-primary">{device.name}</p>
                <p class="text-xs text-text-muted">{device.vendor} • {device.serial} • {device.lastSeen}</p>
              </div>
            </div>
            <div class="flex gap-2">
              {#if !device.approved}
                <button
                  on:click={() => approveDevice(device.id)}
                  class="px-3 py-1 text-xs bg-sec-safe/20 text-sec-safe rounded hover:bg-sec-safe/30 transition-colors focus:outline-none focus:ring-2 focus:ring-sec-safe"
                  type="button"
                  aria-label="{labels.approve} {device.name}"
                >
                  {labels.approve}
                </button>
              {/if}
              {#if device.approved}
                <button
                  on:click={() => blockDevice(device.id)}
                  class="px-3 py-1 text-xs bg-sec-danger/20 text-sec-danger rounded hover:bg-sec-danger/30 transition-colors focus:outline-none focus:ring-2 focus:ring-sec-danger"
                  type="button"
                  aria-label="{labels.block} {device.name}"
                >
                  {labels.block}
                </button>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Quarantine -->
  <div class="glass-panel p-6">
    <h3 class="text-lg font-semibold text-text-primary mb-4">{labels.quarantine}</h3>
    {#if quarantinedFiles.length === 0}
      <p class="text-text-muted">{labels.noQuarantined}</p>
    {:else}
      <div class="space-y-3">
        {#each quarantinedFiles as file (file.id)}
          <div class="flex items-center justify-between p-3 rounded-md bg-surface-tertiary/30 border border-surface-tertiary">
            <div class="min-w-0 flex-1">
              <p class="text-sm text-text-primary font-mono truncate">{file.path}</p>
              <p class="text-xs text-text-muted">{file.reason}</p>
              <p class="text-xs text-text-muted">{labels.quarantinedAt}: {file.quarantinedAt} • {file.size}</p>
            </div>
            <div class="flex gap-2 flex-shrink-0 ml-3">
              <button
                on:click={() => restoreFile(file.id)}
                class="px-3 py-1 text-xs bg-sec-warning/20 text-sec-warning rounded hover:bg-sec-warning/30 transition-colors focus:outline-none focus:ring-2 focus:ring-sec-warning"
                type="button"
                aria-label="{labels.restore} {file.path}"
              >
                {labels.restore}
              </button>
              <button
                on:click={() => deleteFile(file.id)}
                class="px-3 py-1 text-xs bg-sec-danger/20 text-sec-danger rounded hover:bg-sec-danger/30 transition-colors focus:outline-none focus:ring-2 focus:ring-sec-danger"
                type="button"
                aria-label="{labels.delete} {file.path}"
              >
                {labels.delete}
              </button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>
