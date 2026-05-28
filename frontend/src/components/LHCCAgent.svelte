<!-- Copyright 2024-2026 catitodev -->
<!-- Licensed under the Apache License, Version 2.0 -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script lang="ts">
  import { onMount, onDestroy, tick } from 'svelte';

  interface ChatMessage {
    id: string;
    role: 'user' | 'agent';
    content: string;
    timestamp: Date;
  }

  let isExpanded = false;
  let inputValue = '';
  let messages: ChatMessage[] = [];
  let isTyping = false;
  let messagesContainer: HTMLDivElement;

  const mockResponses: string[] = [
    'Dica de segurança: Mantenha seu sistema sempre atualizado com `sudo apt update && sudo apt upgrade`.',
    'Recomendo verificar as permissões de arquivos sensíveis com `find / -perm -777 -type f 2>/dev/null`.',
    'Para melhorar a segurança SSH, desabilite o login root em /etc/ssh/sshd_config.',
    'Configure o firewall UFW com `sudo ufw enable` e permita apenas portas necessárias.',
    'Verifique processos suspeitos com `ps aux | grep -v "\\[" | sort -nrk 3,3 | head -20`.',
    'Habilite autenticação de dois fatores (2FA) para acesso ao sistema sempre que possível.',
    'Use o ClamAV para varreduras regulares: `sudo freshclam && sudo clamscan -r /home`.',
    'Monitore logs de autenticação com `journalctl -u sshd --since "1 hour ago"`.',
    'Configure o fail2ban para proteger contra ataques de força bruta.',
    'Revise as regras do AppArmor/SELinux para garantir confinamento adequado de aplicações.',
  ];

  function generateId(): string {
    return Date.now().toString(36) + Math.random().toString(36).slice(2);
  }

  function toggleChat(): void {
    isExpanded = !isExpanded;
    if (isExpanded) {
      tick().then(() => scrollToBottom());
    }
  }

  function scrollToBottom(): void {
    if (messagesContainer) {
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
  }

  async function sendMessage(): Promise<void> {
    const text = inputValue.trim();
    if (!text || isTyping) return;

    const userMessage: ChatMessage = {
      id: generateId(),
      role: 'user',
      content: text,
      timestamp: new Date(),
    };

    messages = [...messages, userMessage];
    inputValue = '';
    isTyping = true;

    await tick();
    scrollToBottom();

    // Simulate agent thinking delay
    setTimeout(() => {
      const response = mockResponses[Math.floor(Math.random() * mockResponses.length)];
      const agentMessage: ChatMessage = {
        id: generateId(),
        role: 'agent',
        content: response,
        timestamp: new Date(),
      };
      messages = [...messages, agentMessage];
      isTyping = false;
      tick().then(() => scrollToBottom());
    }, 1200 + Math.random() * 800);
  }

  function handleKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  }

  function handleGlobalKeydown(event: KeyboardEvent): void {
    if (event.ctrlKey && event.shiftKey && event.key === 'I') {
      event.preventDefault();
      toggleChat();
    }
  }

  function formatTime(date: Date): string {
    return date.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
  }

  onMount(() => {
    window.addEventListener('keydown', handleGlobalKeydown);
  });

  onDestroy(() => {
    if (typeof window !== 'undefined') {
      window.removeEventListener('keydown', handleGlobalKeydown);
    }
  });
</script>

<!-- Chat Widget Container -->
<div class="fixed bottom-4 right-4 z-50" aria-label="LHCC Agent Chat" role="complementary">
  {#if isExpanded}
    <!-- Expanded Chat Panel -->
    <div
      class="w-[400px] h-[500px] flex flex-col rounded-xl border border-white/10 shadow-2xl overflow-hidden backdrop-blur-xl bg-gray-900/80"
      role="dialog"
      aria-label="Chat com LHCC Agent"
    >
      <!-- Header -->
      <header class="flex items-center justify-between px-4 py-3 bg-gray-800/90 border-b border-white/10">
        <div class="flex items-center gap-2">
          <div class="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center">
            <span class="text-white text-xs font-bold">LC</span>
          </div>
          <div>
            <h2 class="text-sm font-semibold text-white">LHCC Agent</h2>
            <span class="text-xs text-green-400">Online</span>
          </div>
        </div>
        <button
          on:click={toggleChat}
          class="p-1.5 rounded-md hover:bg-white/10 transition-colors text-gray-400 hover:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
          aria-label="Minimizar chat"
          type="button"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
          </svg>
        </button>
      </header>

      <!-- Messages Area -->
      <div
        bind:this={messagesContainer}
        class="flex-1 overflow-y-auto p-4 space-y-3"
        aria-live="polite"
        aria-label="Histórico de mensagens"
      >
        {#if messages.length === 0}
          <div class="flex flex-col items-center justify-center h-full text-center px-4">
            <div class="w-12 h-12 rounded-full bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center mb-3">
              <span class="text-white text-lg font-bold">LC</span>
            </div>
            <p class="text-sm text-gray-300 mb-1">Olá! Sou o LHCC Agent.</p>
            <p class="text-xs text-gray-500">Posso ajudar com dicas de segurança, análise de vulnerabilidades e configurações do sistema.</p>
          </div>
        {/if}

        {#each messages as message (message.id)}
          <div class="flex {message.role === 'user' ? 'justify-end' : 'justify-start'}">
            <div
              class="max-w-[80%] px-3 py-2 rounded-lg text-sm {message.role === 'user'
                ? 'bg-blue-600 text-white rounded-br-sm'
                : 'bg-gray-700/80 text-gray-100 rounded-bl-sm border border-white/5'}"
            >
              <p class="whitespace-pre-wrap break-words">{message.content}</p>
              <span class="block text-[10px] mt-1 {message.role === 'user' ? 'text-blue-200' : 'text-gray-500'}">
                {formatTime(message.timestamp)}
              </span>
            </div>
          </div>
        {/each}

        {#if isTyping}
          <div class="flex justify-start">
            <div class="bg-gray-700/80 border border-white/5 px-4 py-2 rounded-lg rounded-bl-sm">
              <div class="flex gap-1" aria-label="Agente digitando">
                <span class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 0ms"></span>
                <span class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 150ms"></span>
                <span class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 300ms"></span>
              </div>
            </div>
          </div>
        {/if}
      </div>

      <!-- Input Area -->
      <div class="p-3 border-t border-white/10 bg-gray-800/60">
        <div class="flex items-center gap-2">
          <input
            type="text"
            bind:value={inputValue}
            on:keydown={handleKeydown}
            placeholder="Digite sua mensagem..."
            class="flex-1 px-3 py-2 bg-gray-700/60 border border-white/10 rounded-lg text-sm text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            aria-label="Mensagem para o LHCC Agent"
            disabled={isTyping}
          />
          <button
            on:click={sendMessage}
            disabled={!inputValue.trim() || isTyping}
            class="p-2 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:cursor-not-allowed text-white transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500"
            aria-label="Enviar mensagem"
            type="button"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </button>
        </div>
        <p class="text-[10px] text-gray-600 mt-1.5 text-center">Ctrl+Shift+I para abrir/fechar</p>
      </div>
    </div>
  {:else}
    <!-- Collapsed Floating Button -->
    <button
      on:click={toggleChat}
      class="flex items-center gap-2 px-4 py-2.5 rounded-full shadow-lg border border-white/10 backdrop-blur-xl bg-gray-900/80 hover:bg-gray-800/90 transition-all duration-200 hover:scale-105 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-gray-900 group"
      aria-label="Abrir LHCC Agent Chat (Ctrl+Shift+I)"
      type="button"
    >
      <div class="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center flex-shrink-0">
        <span class="text-white text-[10px] font-bold">LC</span>
      </div>
      <span class="text-sm font-medium text-gray-200 group-hover:text-white transition-colors">LHCC Agent</span>
    </button>
  {/if}
</div>
