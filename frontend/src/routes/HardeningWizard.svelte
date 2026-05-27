<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  const labels = {
    title: 'Hardening do Sistema',
    findings: 'Recomendações do Lynis',
    category: 'Categoria',
    priority: 'Prioridade',
    applyFix: 'Aplicar Correção',
    applied: 'Aplicado',
    critical: 'Crítico',
    high: 'Alto',
    medium: 'Médio',
    low: 'Baixo',
    auth: 'Autenticação',
    networking: 'Rede',
    filesystem: 'Sistema de Arquivos',
    kernel: 'Kernel',
    noFindings: 'Nenhuma recomendação pendente',
    responseRules: 'Regras de Resposta Automática',
    createRule: 'Criar Regra',
    ruleName: 'Nome da Regra',
    ruleCondition: 'Condição',
    ruleAction: 'Ação',
    enabled: 'Ativada',
    disabled: 'Desativada',
    noRules: 'Nenhuma regra configurada',
    cancel: 'Cancelar',
    save: 'Salvar',
  };

  type Priority = 'critical' | 'high' | 'medium' | 'low';
  type Category = 'auth' | 'networking' | 'filesystem' | 'kernel';

  interface LynisFinding {
    id: string;
    category: Category;
    priority: Priority;
    title: string;
    description: string;
    fixAvailable: boolean;
    applied: boolean;
  }

  interface ResponseRule {
    id: string;
    name: string;
    condition: string;
    action: string;
    enabled: boolean;
  }

  let findings: LynisFinding[] = [
    { id: '1', category: 'auth', priority: 'critical', title: 'SSH permite login como root', description: 'PermitRootLogin está habilitado em /etc/ssh/sshd_config', fixAvailable: true, applied: false },
    { id: '2', category: 'auth', priority: 'high', title: 'Senhas sem expiração configurada', description: 'PASS_MAX_DAYS não definido em /etc/login.defs', fixAvailable: true, applied: false },
    { id: '3', category: 'networking', priority: 'high', title: 'IPv6 habilitado sem uso', description: 'IPv6 está ativo mas não há endereços configurados', fixAvailable: true, applied: false },
    { id: '4', category: 'filesystem', priority: 'medium', title: 'Permissões amplas em /tmp', description: '/tmp não montado com noexec,nosuid', fixAvailable: true, applied: false },
    { id: '5', category: 'kernel', priority: 'medium', title: 'ASLR parcialmente habilitado', description: 'kernel.randomize_va_space = 1 (recomendado: 2)', fixAvailable: true, applied: false },
    { id: '6', category: 'kernel', priority: 'low', title: 'Core dumps habilitados', description: 'Processos podem gerar core dumps com informações sensíveis', fixAvailable: true, applied: false },
    { id: '7', category: 'filesystem', priority: 'high', title: 'Arquivos SUID desnecessários', description: 'Encontrados 12 binários com bit SUID que podem ser removidos', fixAvailable: false, applied: false },
  ];

  let responseRules: ResponseRule[] = [
    { id: '1', name: 'Bloquear IP após 5 tentativas', condition: 'auth_failure_count >= 5', action: 'block_ip', enabled: true },
    { id: '2', name: 'Quarentenar arquivo suspeito', condition: 'malware_detected == true', action: 'quarantine_file', enabled: true },
    { id: '3', name: 'Alertar sobre escalação de privilégio', condition: 'privilege_escalation == true', action: 'alert_critical', enabled: false },
  ];

  let showCreateRule = false;
  let newRule = { name: '', condition: '', action: '' };
  let selectedCategory: Category | 'all' = 'all';
  const categoryOptions: Category[] = ['auth', 'networking', 'filesystem', 'kernel'];

  $: filteredFindings = selectedCategory === 'all'
    ? findings
    : findings.filter(f => f.category === selectedCategory);

  // Group findings by category
  $: groupedFindings = (() => {
    const groups: Record<string, LynisFinding[]> = {};
    for (const finding of filteredFindings) {
      if (!groups[finding.category]) groups[finding.category] = [];
      groups[finding.category].push(finding);
    }
    return groups;
  })();

  function applyFix(id: string): void {
    findings = findings.map(f => f.id === id ? { ...f, applied: true } : f);
  }

  function toggleRule(id: string): void {
    responseRules = responseRules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r);
  }

  function createRule(): void {
    if (!newRule.name || !newRule.condition || !newRule.action) return;
    responseRules = [...responseRules, { ...newRule, id: Date.now().toString(), enabled: true }];
    showCreateRule = false;
    newRule = { name: '', condition: '', action: '' };
  }

  function getPriorityClass(priority: Priority): string {
    switch (priority) {
      case 'critical': return 'bg-sec-danger/20 text-sec-danger';
      case 'high': return 'bg-sec-warning/20 text-sec-warning';
      case 'medium': return 'bg-yellow-600/20 text-yellow-500';
      case 'low': return 'bg-blue-600/20 text-blue-400';
    }
  }

  function getPriorityLabel(priority: Priority): string {
    switch (priority) {
      case 'critical': return labels.critical;
      case 'high': return labels.high;
      case 'medium': return labels.medium;
      case 'low': return labels.low;
    }
  }

  function getCategoryLabel(category: string): string {
    switch (category) {
      case 'auth': return labels.auth;
      case 'networking': return labels.networking;
      case 'filesystem': return labels.filesystem;
      case 'kernel': return labels.kernel;
      default: return category;
    }
  }
</script>

<div class="space-y-6">
  <h2 class="text-2xl font-bold text-text-primary">{labels.title}</h2>

  <!-- Category Filter -->
  <div class="glass-panel p-4">
    <div class="flex flex-wrap gap-2" role="tablist" aria-label={labels.category}>
      <button
        on:click={() => selectedCategory = 'all'}
        class="px-3 py-1.5 text-sm rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500
          {selectedCategory === 'all' ? 'bg-blue-600 text-white' : 'bg-surface-tertiary text-text-secondary hover:text-text-primary'}"
        type="button"
        role="tab"
        aria-selected={selectedCategory === 'all'}
      >
        Todos
      </button>
      {#each categoryOptions as cat}
        <button
          on:click={() => selectedCategory = cat}
          class="px-3 py-1.5 text-sm rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500
            {selectedCategory === cat ? 'bg-blue-600 text-white' : 'bg-surface-tertiary text-text-secondary hover:text-text-primary'}"
          type="button"
          role="tab"
          aria-selected={selectedCategory === cat}
        >
          {getCategoryLabel(cat)}
        </button>
      {/each}
    </div>
  </div>

  <!-- Findings grouped by category -->
  <div class="space-y-4">
    {#each Object.entries(groupedFindings) as [category, categoryFindings]}
      <div class="glass-panel p-6">
        <h3 class="text-lg font-semibold text-text-primary mb-4">{getCategoryLabel(category)}</h3>
        <div class="space-y-3">
          {#each categoryFindings as finding (finding.id)}
            <div class="p-4 rounded-md bg-surface-tertiary/30 border border-surface-tertiary {finding.applied ? 'opacity-60' : ''}">
              <div class="flex items-start justify-between gap-4">
                <div class="min-w-0 flex-1">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span class="text-xs font-medium px-2 py-0.5 rounded {getPriorityClass(finding.priority)}">
                      {getPriorityLabel(finding.priority)}
                    </span>
                    <h4 class="text-sm font-medium text-text-primary">{finding.title}</h4>
                  </div>
                  <p class="text-xs text-text-muted mt-1">{finding.description}</p>
                </div>
                <div class="flex-shrink-0">
                  {#if finding.applied}
                    <span class="text-xs text-sec-safe font-medium">✓ {labels.applied}</span>
                  {:else if finding.fixAvailable}
                    <button
                      on:click={() => applyFix(finding.id)}
                      class="px-3 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
                      type="button"
                      aria-label="{labels.applyFix}: {finding.title}"
                    >
                      {labels.applyFix}
                    </button>
                  {/if}
                </div>
              </div>
            </div>
          {/each}
        </div>
      </div>
    {/each}

    {#if filteredFindings.length === 0}
      <div class="glass-panel p-8 text-center">
        <p class="text-sec-safe">✓ {labels.noFindings}</p>
      </div>
    {/if}
  </div>

  <!-- Response Rules -->
  <div class="glass-panel p-6">
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-lg font-semibold text-text-primary">{labels.responseRules}</h3>
      <button
        on:click={() => showCreateRule = !showCreateRule}
        class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
        type="button"
        aria-expanded={showCreateRule}
      >
        {showCreateRule ? labels.cancel : labels.createRule}
      </button>
    </div>

    <!-- Create Rule Form -->
    {#if showCreateRule}
      <div class="mb-4 p-4 bg-surface-tertiary/30 rounded-md border border-surface-tertiary">
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label for="rule-name" class="text-xs text-text-secondary block mb-1">{labels.ruleName}</label>
            <input
              id="rule-name"
              type="text"
              bind:value={newRule.name}
              placeholder="Nome da regra"
              class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <div>
            <label for="rule-condition" class="text-xs text-text-secondary block mb-1">{labels.ruleCondition}</label>
            <input
              id="rule-condition"
              type="text"
              bind:value={newRule.condition}
              placeholder="severity >= 4"
              class="w-full px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
            />
          </div>
          <div>
            <label for="rule-action" class="text-xs text-text-secondary block mb-1">{labels.ruleAction}</label>
            <div class="flex gap-2">
              <input
                id="rule-action"
                type="text"
                bind:value={newRule.action}
                placeholder="block_ip"
                class="flex-1 px-3 py-2 bg-surface-tertiary border border-surface-tertiary rounded-md text-sm text-text-primary placeholder-text-muted focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
              />
              <button
                on:click={createRule}
                class="px-3 py-2 bg-sec-safe/20 text-sec-safe rounded-md hover:bg-sec-safe/30 transition-colors focus:outline-none focus:ring-2 focus:ring-sec-safe"
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

    <!-- Rules List -->
    {#if responseRules.length === 0}
      <p class="text-text-muted">{labels.noRules}</p>
    {:else}
      <div class="space-y-2">
        {#each responseRules as rule (rule.id)}
          <div class="flex items-center justify-between p-3 rounded-md bg-surface-tertiary/30 border border-surface-tertiary">
            <div class="min-w-0 flex-1">
              <p class="text-sm text-text-primary">{rule.name}</p>
              <p class="text-xs text-text-muted font-mono">{rule.condition} → {rule.action}</p>
            </div>
            <button
              on:click={() => toggleRule(rule.id)}
              class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 {rule.enabled ? 'bg-blue-600' : 'bg-surface-tertiary'}"
              type="button"
              role="switch"
              aria-checked={rule.enabled}
              aria-label="{rule.name}: {rule.enabled ? labels.enabled : labels.disabled}"
            >
              <span
                class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform {rule.enabled ? 'translate-x-6' : 'translate-x-1'}"
                aria-hidden="true"
              ></span>
            </button>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>
