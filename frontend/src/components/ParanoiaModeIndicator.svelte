<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { isParanoiaMode } from '../lib/stores/app';

  const labels = {
    active: 'MODO PARANOIA ATIVO',
    description: 'Proteções máximas habilitadas — monitoramento intensivo',
  };
</script>

{#if $isParanoiaMode}
  <div
    class="fixed top-0 left-0 right-0 z-50 bg-paranoia text-white px-4 py-2 text-center text-sm font-bold shadow-lg animate-pulse"
    role="alert"
    aria-live="assertive"
  >
    <div class="flex items-center justify-center gap-2">
      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
        />
      </svg>
      <span>{labels.active}</span>
      <span class="hidden sm:inline text-paranoia-glow font-normal">— {labels.description}</span>
    </div>
  </div>
{/if}
