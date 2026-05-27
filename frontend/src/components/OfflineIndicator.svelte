<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { isOffline } from '../lib/stores/app';

  const labels = {
    offline: 'Modo offline — sem conexão com a internet',
  };
</script>

{#if $isOffline}
  <div
    class="fixed bottom-4 right-4 z-50 flex items-center gap-2 px-4 py-2 rounded-lg bg-sec-warning/20 border border-sec-warning/50 text-sec-warning text-sm shadow-lg"
    role="status"
    aria-live="polite"
  >
    <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        stroke-width="2"
        d="M18.364 5.636a9 9 0 010 12.728M5.636 5.636a9 9 0 000 12.728M12 12h.01"
      />
    </svg>
    <span>{labels.offline}</span>
  </div>
{/if}
