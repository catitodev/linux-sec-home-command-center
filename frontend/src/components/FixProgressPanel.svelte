<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { tick } from 'svelte';
  import { fixStore, resetFixStore } from '../lib/stores/fixes';
  import type { FixItem } from '../lib/stores/fixes';

  let logContainer: HTMLDivElement;

  $: isActive = $fixStore.isActive;
  $: isMinimized = $fixStore.isMinimized;
  $: isComplete = $fixStore.isComplete;
  $: items = $fixStore.items;
  $: logs = $fixStore.logs;
  $: progress = $fixStore.progress;

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

  function addLog(message: string): void {
    fixStore.update((s) => ({ ...s, logs: [...s.logs, `[${new Date().toLocaleTimeString('pt-BR')}] ${message}`] }));
    tick().then(() => {
      if (logContainer) {
        logContainer.scrollTop = logContainer.scrollHeight;
      }
    });
  }

  export function startFixes(fixItems: FixItem[]): void {
    fixStore.set({
      isActive: true,
      isMinimized: false,
      isComplete: false,
      items: fixItems,
      logs: [],
      progress: 0,
    });

    addLog('Iniciando processo de correções...');
    processNextFix(0, fixItems);
  }

  function processNextFix(index: number, fixItems: FixItem[]): void {
    if (index >= fixItems.length) {
      fixStore.update((s) => ({
        ...s,
        isComplete: true,
        progress: 100,
      }));
      addLog('✓ Todas as correções foram concluídas!');
      playNotificationSound();
      sendNotification('LHCC - Correções Concluídas', 'Todas as correções foram aplicadas com sucesso.');
      return;
    }

    // Mark current as in-progress
    fixStore.update((s) => ({
      ...s,
      items: s.items.map((item, i) =>
        i === index ? { ...item, status: 'in-progress' as const } : item
      ),
    }));
    addLog(`→ Aplicando: ${fixItems[index].description}`);

    // Simulate fix processing
    const duration = 1500 + Math.random() * 2000;
    setTimeout(() => {
      const success = Math.random() > 0.15; // 85% success rate
      fixStore.update((s) => ({
        ...s,
        items: s.items.map((item, i) =>
          i === index ? { ...item, status: success ? 'done' as const : 'failed' as const } : item
        ),
        progress: Math.round(((index + 1) / fixItems.length) * 100),
      }));

      if (success) {
        addLog(`  ✓ Concluído: ${fixItems[index].description}`);
      } else {
        addLog(`  ✗ Falhou: ${fixItems[index].description} — tentando alternativa...`);
      }

      processNextFix(index + 1, fixItems);
    }, duration);
  }

  function minimize(): void {
    fixStore.update((s) => ({ ...s, isMinimized: true }));
  }

  function expand(): void {
    fixStore.update((s) => ({ ...s, isMinimized: false }));
  }

  function close(): void {
    resetFixStore();
  }

  function getCompletedCount(): number {
    return items.filter((i) => i.status === 'done' || i.status === 'failed').length;
  }

  function getStatusIcon(status: FixItem['status']): string {
    switch (status) {
      case 'pending': return '○';
      case 'in-progress': return '◉';
      case 'done': return '✓';
      case 'failed': return '✗';
    }
  }

  function getStatusClass(status: FixItem['status']): string {
    switch (status) {
      case 'pending': return 'text-gray-500';
      case 'in-progress': return 'text-blue-400 animate-pulse';
      case 'done': return 'text-green-400';
      case 'failed': return 'text-red-400';
    }
  }
</script>

{#if isActive}
  {#if isMinimized}
    <!-- Minimized Bar -->
    <div class="fixed bottom-0 left-0 right-0 z-40">
      <button
        on:click={expand}
        class="w-full px-4 py-2 bg-gray-800/95 backdrop-blur-md border-t border-white/10 flex items-center justify-between hover:bg-gray-700/95 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-inset"
        type="button"
        aria-label="Expandir painel de correções"
      >
        <div class="flex items-center gap-3">
          <div class="w-2 h-2 rounded-full {isComplete ? 'bg-green-400' : 'bg-blue-400 animate-pulse'}"></div>
          <span class="text-sm text-gray-200">
            {#if isComplete}
              Correções concluídas! ({getCompletedCount()}/{items.length})
            {:else}
              Correções em andamento... ({getCompletedCount()}/{items.length})
            {/if}
          </span>
        </div>
        <div class="flex items-center gap-3">
          <div class="w-24 h-1.5 bg-gray-700 rounded-full overflow-hidden">
            <div
              class="h-full rounded-full transition-all duration-300 {isComplete ? 'bg-green-400' : 'bg-blue-500'}"
              style="width: {progress}%"
            ></div>
          </div>
          <span class="text-xs text-gray-400">{progress}%</span>
          <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7" />
          </svg>
        </div>
      </button>
    </div>
  {:else}
    <!-- Expanded Panel (slide-up modal) -->
    <div class="fixed inset-0 z-40 flex items-end justify-center" role="dialog" aria-label="Painel de Correções">
      <!-- Backdrop -->
      <button
        class="absolute inset-0 bg-black/40 backdrop-blur-sm border-0 cursor-default"
        on:click={minimize}
        type="button"
        aria-label="Minimizar painel"
        tabindex="-1"
      ></button>

      <!-- Panel -->
      <div class="relative w-full max-w-3xl max-h-[70vh] flex flex-col rounded-t-xl border border-white/10 border-b-0 shadow-2xl backdrop-blur-xl bg-gray-900/95 animate-slide-up">
        <!-- Header -->
        <header class="flex items-center justify-between px-5 py-3 border-b border-white/10 flex-shrink-0">
          <div class="flex items-center gap-3">
            <div class="w-2.5 h-2.5 rounded-full {isComplete ? 'bg-green-400' : 'bg-blue-400 animate-pulse'}"></div>
            <h2 class="text-base font-semibold text-white">
              {isComplete ? 'Correções Concluídas' : 'Realizando Correções'}
            </h2>
          </div>
          <div class="flex items-center gap-2">
            <button
              on:click={minimize}
              class="p-1.5 rounded-md hover:bg-white/10 text-gray-400 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
              aria-label="Minimizar"
              type="button"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
              </svg>
            </button>
            {#if isComplete}
              <button
                on:click={close}
                class="p-1.5 rounded-md hover:bg-white/10 text-gray-400 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
                aria-label="Fechar"
                type="button"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            {/if}
          </div>
        </header>

        <!-- Progress Bar -->
        <div class="px-5 py-2 border-b border-white/5 flex-shrink-0">
          <div class="flex items-center justify-between mb-1">
            <span class="text-xs text-gray-400">Progresso geral</span>
            <span class="text-xs text-gray-400">{progress}%</span>
          </div>
          <div
            class="w-full h-2 bg-gray-800 rounded-full overflow-hidden"
            role="progressbar"
            aria-valuenow={progress}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Progresso das correções"
          >
            <div
              class="h-full rounded-full transition-all duration-300 {isComplete ? 'bg-green-400' : 'bg-blue-500'}"
              style="width: {progress}%"
            ></div>
          </div>
        </div>

        <!-- Content -->
        <div class="flex-1 overflow-hidden flex flex-col sm:flex-row min-h-0">
          <!-- Fix Items List -->
          <div class="sm:w-1/2 overflow-y-auto border-b sm:border-b-0 sm:border-r border-white/5 p-4">
            <h3 class="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">Itens</h3>
            <ul class="space-y-1.5" aria-label="Lista de correções">
              {#each items as item (item.id)}
                <li class="flex items-start gap-2 px-2 py-1.5 rounded {item.status === 'in-progress' ? 'bg-blue-500/10' : ''}">
                  <span class="flex-shrink-0 text-sm {getStatusClass(item.status)}" aria-hidden="true">
                    {getStatusIcon(item.status)}
                  </span>
                  <span class="text-sm {item.status === 'done' ? 'text-gray-400 line-through' : item.status === 'failed' ? 'text-red-300' : 'text-gray-200'}">
                    {item.description}
                  </span>
                </li>
              {/each}
            </ul>
          </div>

          <!-- Log Output -->
          <div class="sm:w-1/2 overflow-hidden flex flex-col p-4">
            <h3 class="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">Log</h3>
            <div
              bind:this={logContainer}
              class="flex-1 overflow-y-auto bg-black/40 rounded-md p-3 font-mono text-xs text-gray-300 border border-white/5 min-h-[120px]"
              aria-label="Log de saída das correções"
              aria-live="polite"
            >
              {#each logs as log}
                <p class="leading-relaxed">{log}</p>
              {/each}
            </div>
          </div>
        </div>

        <!-- Footer -->
        {#if isComplete}
          <footer class="px-5 py-3 border-t border-white/10 flex items-center justify-between flex-shrink-0">
            <span class="text-sm text-green-400 font-medium">✓ Correções concluídas!</span>
            <button
              on:click={close}
              class="px-4 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
              type="button"
            >
              Fechar
            </button>
          </footer>
        {/if}
      </div>
    </div>
  {/if}
{/if}

<style>
  @keyframes slide-up {
    from {
      transform: translateY(100%);
      opacity: 0;
    }
    to {
      transform: translateY(0);
      opacity: 1;
    }
  }

  .animate-slide-up {
    animation: slide-up 0.3s ease-out;
  }
</style>
