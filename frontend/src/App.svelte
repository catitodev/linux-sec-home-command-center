<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { onMount } from 'svelte';
  import { isAuthenticated } from './lib/stores/app';
  import AuthGate from './components/AuthGate.svelte';
  import DashboardShell from './components/DashboardShell.svelte';
  import HealthPanel from './routes/HealthPanel.svelte';
  import EventTimeline from './routes/EventTimeline.svelte';
  import ConnectionMap from './routes/ConnectionMap.svelte';
  import ScanPanel from './routes/ScanPanel.svelte';
  import FirewallPanel from './routes/FirewallPanel.svelte';
  import HardeningWizard from './routes/HardeningWizard.svelte';
  import SettingsPanel from './routes/SettingsPanel.svelte';
  import ReportsPanel from './routes/ReportsPanel.svelte';

  let currentRoute = '/';

  function handleHashChange(): void {
    const hash = window.location.hash.slice(1) || '/';
    currentRoute = hash;
  }

  onMount(() => {
    handleHashChange();
    window.addEventListener('hashchange', handleHashChange);
    return () => {
      window.removeEventListener('hashchange', handleHashChange);
    };
  });
</script>

{#if $isAuthenticated}
  <DashboardShell>
    {#if currentRoute === '/'}
      <HealthPanel />
    {:else if currentRoute === '/events'}
      <EventTimeline />
    {:else if currentRoute === '/network'}
      <ConnectionMap />
    {:else if currentRoute === '/scan'}
      <ScanPanel />
    {:else if currentRoute === '/firewall'}
      <FirewallPanel />
    {:else if currentRoute === '/hardening'}
      <HardeningWizard />
    {:else if currentRoute === '/settings'}
      <SettingsPanel />
    {:else if currentRoute === '/reports'}
      <ReportsPanel />
    {:else}
      <HealthPanel />
    {/if}
  </DashboardShell>
{:else}
  <AuthGate />
{/if}
