<div align="center">

[🇧🇷 Português](#-português) | [🇺🇸 English](#-english)

```
╔══════════════════════════════════════════════════════════════╗
║   _     _                    ____                           ║
║  | |   (_)_ __  _   ___  __/ ___|  ___  ___                ║
║  | |   | | '_ \| | | \ \/ /\___ \ / _ \/ __|               ║
║  | |___| | | | | |_| |>  <  ___) |  __/ (__                ║
║  |_____|_|_| |_|\__,_/_/\_\|____/ \___|\___|               ║
║                                                              ║
║          Home Command Center                                 ║
║          ━━━━━━━━━━━━━━━━━━━━                               ║
║   🛡️  Security Dashboard for Linux Home Users  🛡️           ║
╚══════════════════════════════════════════════════════════════╝
```

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/Made_with-Rust_🦀-orange.svg)](https://www.rust-lang.org/)
[![Frontend](https://img.shields.io/badge/UI-Svelte-FF3E00.svg)](https://svelte.dev/)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624.svg?logo=linux&logoColor=black)](https://kernel.org)
[![Version](https://img.shields.io/badge/Version-1.0.0-green.svg)](https://github.com/catitodev/linux-sec-home-command-center)
[![Tests](https://img.shields.io/badge/Tests-396_passing-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Made with 🦀 Rust + Svelte | Open Source | Privacy-First | Offline-Capable**

🔗 **Repository:** [github.com/catitodev/linux-sec-home-command-center](https://github.com/catitodev/linux-sec-home-command-center)

</div>

---

# 🇧🇷 Português

> **Centro de Comando de Segurança para Linux** — Um painel unificado e leve para monitorar, proteger e gerenciar a segurança do seu sistema Linux doméstico, com assistente de IA integrado.

## 📑 Índice

- [Sobre](#sobre)
- [Funcionalidades](#-funcionalidades)
- [Stack Tecnológica](#-stack-tecnológica)
- [Arquitetura](#-arquitetura)
- [Requisitos do Sistema](#-requisitos-do-sistema)
- [Início Rápido](#-início-rápido)
- [Testes](#-testes)
- [Uso](#-uso)
- [IronClaw — Assistente IA](#-ironclaw--assistente-ia)
- [Filosofia de Segurança](#-filosofia-de-segurança)
- [Distribuições Suportadas](#-distribuições-suportadas)
- [Configuração](#-configuração)
- [Contribuindo](#-contribuindo)
- [Roadmap](#-roadmap)
- [FAQ](#-faq)
- [Licença](#-licença)
- [Autor](#-autor)
- [Agradecimentos](#-agradecimentos)

---

## Sobre

O **Linux Security Home Command Center** é uma aplicação desktop que centraliza o monitoramento e gerenciamento de segurança para usuários domésticos de Linux. Projetado para ser leve, funcionar offline e respeitar sua privacidade, ele transforma a complexidade da segurança Linux em uma interface intuitiva e acessível.

Diferente de soluções corporativas complexas, este projeto foca no usuário doméstico que quer proteger seu sistema sem precisar ser um especialista em segurança.

### Por que este projeto?

- 🏠 **Feito para casa** — Não é uma ferramenta enterprise adaptada; foi pensado para o desktop doméstico
- 🔒 **Privacidade primeiro** — Seus dados nunca saem do seu computador
- 📡 **Funciona offline** — Não depende de serviços em nuvem
- 🪶 **Leve** — Consome poucos recursos, roda até em hardware modesto
- 🎯 **Simples** — Interface clara, sem jargão desnecessário

---

## ✨ Funcionalidades

| Categoria | Funcionalidade | Status |
|-----------|---------------|--------|
| 🛡️ Firewall | Gerenciamento visual de regras (UFW/nftables) | ✅ Implementado |
| 📊 Monitor | Dashboard de processos e conexões em tempo real | ✅ Implementado |
| 🔐 Senhas | Auditoria de força de senhas e SSH | ✅ Implementado |
| 🌐 Rede | Mapa de conexões e detecção de anomalias | ✅ Implementado |
| 📦 Pacotes | Verificação de integridade (supply chain) | ✅ Implementado |
| 🤖 IA | Assistente IronClaw (LLM local + API externa) | ✅ Implementado |
| 🔑 SSH | Auditoria de configuração e monitoramento | ✅ Implementado |
| 📝 Logs | Análise de logs com correlação de eventos | ✅ Implementado |
| 💾 Backup | Snapshots Btrfs e rollback | ✅ Implementado |
| 🚨 Alertas | Notificações e resposta automática | ✅ Implementado |
| 🦠 Antivírus | ClamAV + YARA com regras customizadas | ✅ Implementado |
| 🔍 Rootkit | Detecção com chkrootkit + rkhunter | ✅ Implementado |
| 📁 Integridade | Monitoramento AIDE de arquivos críticos | ✅ Implementado |
| 🏰 Hardening | Auditoria Lynis com Health Score | ✅ Implementado |
| 🔒 USB | Controle de dispositivos (USBGuard) | ✅ Implementado |
| 🧪 Sandbox | Isolamento de apps (Firejail) | ✅ Implementado |
| 🌍 DNS | DNS criptografado (dnscrypt-proxy) | ✅ Implementado |
| 🕵️ Secrets | Scan de credenciais em Git (TruffleHog + Gitleaks) | ✅ Implementado |

---

## 🔧 Stack Tecnológica

| Camada | Tecnologia |
|--------|-----------|
| **Backend** | Rust (binário estático, musl libc) |
| **Frontend** | Svelte + TypeScript + TailwindCSS |
| **Banco de Dados** | SQLite + SQLCipher (criptografado) |
| **IPC** | D-Bus + Polkit |
| **IA** | Ollama / llama.cpp (LLM local) |
| **Transporte** | Unix domain socket (sem exposição TCP) |

---

## 🏗️ Arquitetura

```mermaid
graph TB
    subgraph Frontend["🖥️ Frontend (Svelte + TailwindCSS)"]
        UI[8 Dashboard Views]
        IC[IronClaw AI Panel]
        SSE[SSE Real-time Updates]
    end

    subgraph Backend["⚙️ Backend API (Rust)"]
        API[HTTP Server - Unix Socket]
        Auth[PAM Auth + Sessions]
        Correlator[Event Correlation Engine]
        Response[Automated Response Engine]
        Tools[16 Tool Adapters]
        DB[(SQLCipher DB)]
    end

    subgraph Daemon["🔐 Privileged Daemon (Rust)"]
        DBus[D-Bus + Polkit]
        Whitelist[Operation Whitelist]
        Integrity[Self-Integrity Verification]
    end

    subgraph SecurityTools["🐧 Security Tools"]
        T1[osquery · Falco · auditd · OpenSnitch]
        T2[CrowdSec · UFW · USBGuard · Firejail]
        T3[ClamAV · YARA · AIDE · Lynis]
        T4[AppArmor/SELinux · dnscrypt-proxy]
        T5[TruffleHog · Gitleaks · chkrootkit · rkhunter]
    end

    UI --> API
    IC --> API
    SSE --> API
    API --> Auth
    API --> Correlator
    API --> Response
    API --> Tools
    API --> DB
    API --> DBus
    DBus --> Whitelist
    DBus --> Integrity
    Tools --> T1
    Tools --> T2
    Tools --> T3
    Tools --> T4
    Tools --> T5
```

> 📐 Arquitetura de 3 camadas: Frontend (Svelte + TailwindCSS) → Backend API (Rust, Unix socket) → Daemon Privilegiado (D-Bus + Polkit)

---

## 💻 Requisitos do Sistema

<details>
<summary><strong>📋 Três perfis de instalação</strong></summary>

| Recurso | 🟢 Mínimo (Pendrive) | 🟡 Padrão | 🔵 Completo (com LLM) |
|---------|----------------------|-----------|------------------------|
| **CPU** | 1 core | 2 cores | 4+ cores |
| **RAM** | 1 GB | 4 GB | 8 GB |
| **Disco** | 4 GB | 16 GB | 32 GB+ |
| **Rede** | Opcional | Opcional | Recomendado |
| **Modo** | Portátil (pendrive) | Desktop completo | Desktop + IA local |

### 🟢 Perfil Mínimo (Modo Pendrive)
- Ideal para uso portátil em pendrive
- Todas as funcionalidades de segurança
- Sem modelo de IA local

### 🟡 Perfil Padrão (Recomendado)
- Interface gráfica completa com 8 views
- Todos os 16 módulos de segurança
- Funciona em qualquer desktop Linux moderno

### 🔵 Perfil Completo (com LLM)
- Inclui assistente IronClaw com modelo de IA local (Ollama/llama.cpp)
- Análise avançada de ameaças com correlação de eventos
- Detecção de anomalias baseada em baseline

</details>

---

## 🚀 Início Rápido

### Instalação a partir do código-fonte

```bash
# Clonar o repositório
git clone https://github.com/catitodev/linux-sec-home-command-center.git
cd linux-sec-home-command-center

# Compilar o backend
cargo build --release

# Compilar o frontend
cd frontend && npm install && npm run build
```

### Primeira Execução

```bash
# Executar com interface gráfica
lshcc

# Executar em modo terminal
lshcc --tui

# Executar verificação rápida de segurança
lshcc --quick-scan

# Ver todas as opções
lshcc --help
```

---

## 🧪 Testes

```
396 testes unitários | 0 falhas | 3 crates Rust + 1 doc-test
```

```bash
# Executar todos os testes do workspace (396 testes, 0 falhas)
cargo test --workspace

# Verificar tipos do frontend (0 erros, 0 warnings)
cd frontend && npx svelte-check
```

---

## 📖 Uso

<details>
<summary><strong>Comandos principais</strong></summary>

```bash
# Dashboard interativo (padrão)
lshcc

# Verificar status geral de segurança
lshcc status

# Gerenciar firewall
lshcc firewall --status
lshcc firewall --enable
lshcc firewall --add-rule "allow 22/tcp"

# Monitorar conexões de rede
lshcc network --monitor
lshcc network --scan-ports

# Auditoria de segurança
lshcc audit --full
lshcc audit --quick

# Consultar assistente IA
lshcc ai "como proteger meu SSH?"

# Exportar relatório
lshcc report --format pdf --output ~/relatorio-seguranca.pdf
```

</details>

---

## 🤖 IronClaw — Assistente IA

O **IronClaw** é o assistente de inteligência artificial integrado ao Home Command Center. Ele funciona **100% offline** usando modelos de linguagem locais (Ollama/llama.cpp).

### Capacidades

- 💬 Responde perguntas sobre segurança Linux em linguagem natural
- 🔍 Analisa configurações e sugere melhorias
- 🚨 Explica alertas de segurança em termos simples
- 📚 Fornece tutoriais passo-a-passo personalizados
- 🛡️ Recomenda configurações baseadas no seu perfil de uso

### Filosofia do IronClaw

> O IronClaw nunca executa ações automaticamente. Ele **sugere** e **explica**, mas a decisão final é sempre do usuário.

```bash
# Iniciar conversa com IronClaw
lshcc ai

# Pergunta direta
lshcc ai "meu sistema está seguro?"

# Análise de configuração específica
lshcc ai --analyze /etc/ssh/sshd_config
```

---

## 🔐 Filosofia de Segurança

<div align="center">

| Princípio | Descrição |
|-----------|-----------|
| 🏠 **Local-first** | Dados processados e armazenados apenas localmente |
| 👁️ **Transparência** | Código aberto, auditável, sem telemetria |
| 🎓 **Educativo** | Explica o "porquê" de cada recomendação |
| ⚡ **Mínimo privilégio** | Solicita permissões apenas quando necessário |
| 🔄 **Não-destrutivo** | Nunca altera configurações sem confirmação explícita |

</div>

---

## 🐧 Distribuições Suportadas

<details>
<summary><strong>Lista de distribuições testadas</strong></summary>

| Distribuição | Versão | Status | Notas |
|-------------|--------|--------|-------|
| Ubuntu | 22.04+ | ✅ Suportado | Referência principal |
| Debian | 12+ | ✅ Suportado | |
| Fedora | 38+ | ✅ Suportado | |
| Arch Linux | Rolling | ✅ Suportado | |
| Linux Mint | 21+ | ✅ Suportado | |
| openSUSE | Leap 15.5+ | 🧪 Experimental | |
| Manjaro | Latest | 🧪 Experimental | |
| Pop!_OS | 22.04+ | 🧪 Experimental | |

> 💡 Em teoria, qualquer distribuição Linux com kernel 5.10+ e systemd deve funcionar.

</details>

---

## ⚙️ Configuração

O arquivo de configuração principal fica em `~/.config/lshcc/config.toml`:

```toml
[general]
language = "pt-BR"          # Idioma da interface
theme = "dark"              # dark | light | system
notifications = true        # Habilitar notificações desktop

[security]
scan_interval = 3600        # Intervalo de scan automático (segundos)
firewall_backend = "ufw"    # ufw | iptables | nftables
log_retention_days = 30     # Dias para manter logs

[ai]
enabled = false             # Habilitar assistente IronClaw
model = "local"             # local | none
max_memory_mb = 512         # Memória máxima para o modelo

[portable]
mode = false                # Modo pendrive
data_path = "./data"        # Caminho para dados em modo portátil
```

---

## 🤝 Contribuindo

Contribuições são muito bem-vindas! Veja como participar:

1. 🍴 Faça um fork do projeto
2. 🌿 Crie uma branch para sua feature (`git checkout -b feature/minha-feature`)
3. 💾 Commit suas mudanças (`git commit -m 'feat: adiciona minha feature'`)
4. 📤 Push para a branch (`git push origin feature/minha-feature`)
5. 🔃 Abra um Pull Request

<details>
<summary><strong>📋 Diretrizes de contribuição</strong></summary>

- Siga o estilo de código existente (use `cargo fmt` e `cargo clippy`)
- Adicione testes para novas funcionalidades
- Atualize a documentação quando necessário
- Use [Conventional Commits](https://www.conventionalcommits.org/) para mensagens de commit
- Seja respeitoso e construtivo nas discussões

</details>

> 📄 Veja [`CONTRIBUTING.md`](CONTRIBUTING.md) para diretrizes detalhadas.

---

## 🗺️ Roadmap

- [x] Estrutura inicial do projeto
- [x] Definição da arquitetura
- [x] **v0.1** — Dashboard básico + monitor de processos
- [x] **v0.2** — Gerenciamento de firewall (UFW)
- [x] **v0.3** — Scanner de rede e portas
- [x] **v0.4** — Auditoria de senhas e permissões
- [x] **v0.5** — Análise de logs inteligente
- [x] **v0.6** — Integração IronClaw (IA local)
- [x] **v0.7** — Modo pendrive portátil
- [x] **v0.8** — Sistema de alertas e notificações
- [x] **v0.9** — Relatórios e exportação
- [x] **v1.0** — Release estável 🎉

---

## ❓ FAQ

<details>
<summary><strong>Preciso ser root para usar?</strong></summary>

Não para a maioria das funções. Operações privilegiadas são mediadas pelo daemon via D-Bus + Polkit, solicitando autorização apenas quando necessário.

</details>

<details>
<summary><strong>Funciona sem internet?</strong></summary>

Sim! O projeto foi desenhado para funcionar 100% offline. A conexão com internet é opcional e usada apenas para verificar atualizações de segurança (quando habilitado).

</details>

<details>
<summary><strong>É seguro instalar?</strong></summary>

O código é 100% aberto e auditável. Não há telemetria, coleta de dados ou conexões externas não autorizadas. Você pode compilar a partir do código-fonte e verificar por si mesmo.

</details>

<details>
<summary><strong>Substitui um antivírus?</strong></summary>

Ele integra ClamAV e YARA para varredura de malware, além de detecção de rootkits. É um centro de comando completo que orquestra múltiplas ferramentas de segurança.

</details>

<details>
<summary><strong>Funciona em servidores?</strong></summary>

Sim, no modo CLI/TUI. A interface gráfica requer um ambiente desktop, mas todas as funcionalidades estão disponíveis via terminal.

</details>

---

## 📄 Licença

Este projeto é licenciado sob a **Apache License 2.0** — veja o arquivo [`LICENSE`](LICENSE) para detalhes.

```
Copyright 2024-2026 catitodev

Licensed under the Apache License, Version 2.0
```

---

## 👤 Autor

**catitodev**

- GitHub: [@catitodev](https://github.com/catitodev)

---

## 🙏 Agradecimentos

- À comunidade Rust por ferramentas e bibliotecas incríveis
- À comunidade Svelte pela framework frontend elegante
- A todos os projetos open source de segurança que inspiraram este trabalho
- A todos os contribuidores e testadores

---
---


# 🇺🇸 English

> **Linux Security Home Command Center** — A unified, lightweight dashboard to monitor, protect, and manage your home Linux system's security, with an integrated AI assistant.

## 📑 Table of Contents

- [About](#about)
- [Key Features](#-key-features)
- [Tech Stack](#-tech-stack)
- [Architecture](#-architecture-overview)
- [System Requirements](#-system-requirements)
- [Quick Start](#-quick-start-1)
- [Running Tests](#-running-tests)
- [Usage](#-usage)
- [IronClaw AI Assistant](#-ironclaw--ai-assistant)
- [Security Philosophy](#-security-philosophy)
- [Supported Distributions](#-supported-distributions)
- [Configuration](#-configuration)
- [Contributing](#-contributing-1)
- [Roadmap](#-roadmap-1)
- [FAQ](#-faq-1)
- [License](#-license)
- [Author](#-author)
- [Acknowledgments](#-acknowledgments)

---

## About

**Linux Security Home Command Center** is a desktop application that centralizes security monitoring and management for Linux home users. Designed to be lightweight, work offline, and respect your privacy, it transforms the complexity of Linux security into an intuitive, accessible interface.

Unlike complex enterprise solutions, this project focuses on the home user who wants to protect their system without needing to be a security expert.

### Why this project?

- 🏠 **Built for home** — Not an adapted enterprise tool; designed for the home desktop
- 🔒 **Privacy first** — Your data never leaves your computer
- 📡 **Works offline** — No cloud service dependencies
- 🪶 **Lightweight** — Low resource consumption, runs even on modest hardware
- 🎯 **Simple** — Clean interface, no unnecessary jargon

---

## ✨ Key Features

| Category | Feature | Status |
|----------|---------|--------|
| 🛡️ Firewall | Visual rule management (UFW/nftables) | ✅ Implemented |
| 📊 Monitor | Real-time process and connection dashboard | ✅ Implemented |
| 🔐 Passwords | Password strength and SSH audit | ✅ Implemented |
| 🌐 Network | Connection mapping and anomaly detection | ✅ Implemented |
| 📦 Packages | Integrity verification (supply chain) | ✅ Implemented |
| 🤖 AI | IronClaw Assistant (local LLM + external API) | ✅ Implemented |
| 🔑 SSH | Configuration audit and monitoring | ✅ Implemented |
| 📝 Logs | Log analysis with event correlation | ✅ Implemented |
| 💾 Backup | Btrfs snapshots and rollback | ✅ Implemented |
| 🚨 Alerts | Notifications and automated response | ✅ Implemented |
| 🦠 Antivirus | ClamAV + YARA with custom rules | ✅ Implemented |
| 🔍 Rootkit | Detection with chkrootkit + rkhunter | ✅ Implemented |
| 📁 Integrity | AIDE monitoring of critical files | ✅ Implemented |
| 🏰 Hardening | Lynis audit with Health Score | ✅ Implemented |
| 🔒 USB | Device control (USBGuard) | ✅ Implemented |
| 🧪 Sandbox | App isolation (Firejail) | ✅ Implemented |
| 🌍 DNS | Encrypted DNS (dnscrypt-proxy) | ✅ Implemented |
| 🕵️ Secrets | Git credential scanning (TruffleHog + Gitleaks) | ✅ Implemented |

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Rust (static binary, musl libc) |
| **Frontend** | Svelte + TypeScript + TailwindCSS |
| **Database** | SQLite + SQLCipher (encrypted) |
| **IPC** | D-Bus + Polkit |
| **AI** | Ollama / llama.cpp (local LLM) |
| **Transport** | Unix domain socket (no TCP exposure) |

---

## 🏗️ Architecture Overview

```mermaid
graph TB
    subgraph Frontend["🖥️ Frontend (Svelte + TailwindCSS)"]
        UI[8 Dashboard Views]
        IC[IronClaw AI Panel]
        SSE[SSE Real-time Updates]
    end

    subgraph Backend["⚙️ Backend API (Rust)"]
        API[HTTP Server - Unix Socket]
        Auth[PAM Auth + Sessions]
        Correlator[Event Correlation Engine]
        Response[Automated Response Engine]
        Tools[16 Tool Adapters]
        DB[(SQLCipher DB)]
    end

    subgraph Daemon["🔐 Privileged Daemon (Rust)"]
        DBus[D-Bus + Polkit]
        Whitelist[Operation Whitelist]
        Integrity[Self-Integrity Verification]
    end

    subgraph SecurityTools["🐧 Security Tools"]
        T1[osquery · Falco · auditd · OpenSnitch]
        T2[CrowdSec · UFW · USBGuard · Firejail]
        T3[ClamAV · YARA · AIDE · Lynis]
        T4[AppArmor/SELinux · dnscrypt-proxy]
        T5[TruffleHog · Gitleaks · chkrootkit · rkhunter]
    end

    UI --> API
    IC --> API
    SSE --> API
    API --> Auth
    API --> Correlator
    API --> Response
    API --> Tools
    API --> DB
    API --> DBus
    DBus --> Whitelist
    DBus --> Integrity
    Tools --> T1
    Tools --> T2
    Tools --> T3
    Tools --> T4
    Tools --> T5
```

> 📐 3-tier architecture: Frontend (Svelte + TailwindCSS) → Backend API (Rust, Unix socket) → Privileged Daemon (D-Bus + Polkit)

---

## 💻 System Requirements

<details>
<summary><strong>📋 Three installation profiles</strong></summary>

| Resource | 🟢 Minimal (Pendrive) | 🟡 Standard | 🔵 Full (with LLM) |
|----------|----------------------|-------------|---------------------|
| **CPU** | 1 core | 2 cores | 4+ cores |
| **RAM** | 1 GB | 4 GB | 8 GB |
| **Disk** | 4 GB | 16 GB | 32 GB+ |
| **Network** | Optional | Optional | Recommended |
| **Mode** | Portable (pendrive) | Full desktop | Desktop + local AI |

### 🟢 Minimal Profile (Pendrive Mode)
- Ideal for portable use on USB drives
- All security features included
- No local AI model

### 🟡 Standard Profile (Recommended)
- Full graphical interface with 8 views
- All 16 security modules
- Works on any modern Linux desktop

### 🔵 Full Profile (with LLM)
- Includes IronClaw assistant with local AI model (Ollama/llama.cpp)
- Advanced threat analysis with event correlation
- Baseline-based anomaly detection

</details>

---

## 🚀 Quick Start

### Installation from source

```bash
# Clone the repository
git clone https://github.com/catitodev/linux-sec-home-command-center.git
cd linux-sec-home-command-center

# Build the backend
cargo build --release

# Build the frontend
cd frontend && npm install && npm run build
```

### First Run

```bash
# Run with graphical interface
lshcc

# Run in terminal mode
lshcc --tui

# Run quick security check
lshcc --quick-scan

# See all options
lshcc --help
```

---

## 🧪 Running Tests

```
396 unit tests | 0 failures | 3 Rust crates + 1 doc-test
```

```bash
# Run all workspace tests (396 tests, 0 failures)
cargo test --workspace

# Check frontend types (0 errors, 0 warnings)
cd frontend && npx svelte-check
```

---

## 📖 Usage

<details>
<summary><strong>Main commands</strong></summary>

```bash
# Interactive dashboard (default)
lshcc

# Check overall security status
lshcc status

# Manage firewall
lshcc firewall --status
lshcc firewall --enable
lshcc firewall --add-rule "allow 22/tcp"

# Monitor network connections
lshcc network --monitor
lshcc network --scan-ports

# Security audit
lshcc audit --full
lshcc audit --quick

# Query AI assistant
lshcc ai "how do I secure my SSH?"

# Export report
lshcc report --format pdf --output ~/security-report.pdf
```

</details>

---

## 🤖 IronClaw — AI Assistant

**IronClaw** is the artificial intelligence assistant integrated into the Home Command Center. It works **100% offline** using local language models (Ollama/llama.cpp).

### Capabilities

- 💬 Answers Linux security questions in natural language
- 🔍 Analyzes configurations and suggests improvements
- 🚨 Explains security alerts in simple terms
- 📚 Provides personalized step-by-step tutorials
- 🛡️ Recommends settings based on your usage profile

### IronClaw Philosophy

> IronClaw never executes actions automatically. It **suggests** and **explains**, but the final decision is always the user's.

```bash
# Start conversation with IronClaw
lshcc ai

# Direct question
lshcc ai "is my system secure?"

# Analyze specific configuration
lshcc ai --analyze /etc/ssh/sshd_config
```

---

## 🔐 Security Philosophy

<div align="center">

| Principle | Description |
|-----------|-------------|
| 🏠 **Local-first** | Data processed and stored only locally |
| 👁️ **Transparency** | Open source, auditable, no telemetry |
| 🎓 **Educational** | Explains the "why" behind every recommendation |
| ⚡ **Least privilege** | Requests permissions only when necessary |
| 🔄 **Non-destructive** | Never changes settings without explicit confirmation |

</div>

---

## 🐧 Supported Distributions

<details>
<summary><strong>List of tested distributions</strong></summary>

| Distribution | Version | Status | Notes |
|-------------|---------|--------|-------|
| Ubuntu | 22.04+ | ✅ Supported | Primary reference |
| Debian | 12+ | ✅ Supported | |
| Fedora | 38+ | ✅ Supported | |
| Arch Linux | Rolling | ✅ Supported | |
| Linux Mint | 21+ | ✅ Supported | |
| openSUSE | Leap 15.5+ | 🧪 Experimental | |
| Manjaro | Latest | 🧪 Experimental | |
| Pop!_OS | 22.04+ | 🧪 Experimental | |

> 💡 In theory, any Linux distribution with kernel 5.10+ and systemd should work.

</details>

---

## ⚙️ Configuration

The main configuration file is located at `~/.config/lshcc/config.toml`:

```toml
[general]
language = "en"             # Interface language
theme = "dark"              # dark | light | system
notifications = true        # Enable desktop notifications

[security]
scan_interval = 3600        # Auto-scan interval (seconds)
firewall_backend = "ufw"    # ufw | iptables | nftables
log_retention_days = 30     # Days to keep logs

[ai]
enabled = false             # Enable IronClaw assistant
model = "local"             # local | none
max_memory_mb = 512         # Maximum memory for the model

[portable]
mode = false                # USB drive mode
data_path = "./data"        # Data path in portable mode
```

---

## 🤝 Contributing

Contributions are very welcome! Here's how to participate:

1. 🍴 Fork the project
2. 🌿 Create a branch for your feature (`git checkout -b feature/my-feature`)
3. 💾 Commit your changes (`git commit -m 'feat: add my feature'`)
4. 📤 Push to the branch (`git push origin feature/my-feature`)
5. 🔃 Open a Pull Request

<details>
<summary><strong>📋 Contribution guidelines</strong></summary>

- Follow existing code style (use `cargo fmt` and `cargo clippy`)
- Add tests for new features
- Update documentation when necessary
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages
- Be respectful and constructive in discussions

</details>

> 📄 See [`CONTRIBUTING.md`](CONTRIBUTING.md) for detailed guidelines.

---

## 🗺️ Roadmap

- [x] Initial project structure
- [x] Architecture definition
- [x] **v0.1** — Basic dashboard + process monitor
- [x] **v0.2** — Firewall management (UFW)
- [x] **v0.3** — Network and port scanner
- [x] **v0.4** — Password and permissions audit
- [x] **v0.5** — Intelligent log analysis
- [x] **v0.6** — IronClaw integration (local AI)
- [x] **v0.7** — Portable pendrive mode
- [x] **v0.8** — Alerts and notifications system
- [x] **v0.9** — Reports and export
- [x] **v1.0** — Stable release 🎉

---

## ❓ FAQ

<details>
<summary><strong>Do I need root to use it?</strong></summary>

Not for most functions. Privileged operations are mediated by the daemon via D-Bus + Polkit, requesting authorization only when necessary.

</details>

<details>
<summary><strong>Does it work without internet?</strong></summary>

Yes! The project was designed to work 100% offline. Internet connection is optional and used only to check for security updates (when enabled).

</details>

<details>
<summary><strong>Is it safe to install?</strong></summary>

The code is 100% open and auditable. There is no telemetry, data collection, or unauthorized external connections. You can build from source and verify for yourself.

</details>

<details>
<summary><strong>Does it replace an antivirus?</strong></summary>

It integrates ClamAV and YARA for malware scanning, plus rootkit detection. It's a complete command center that orchestrates multiple security tools.

</details>

<details>
<summary><strong>Does it work on servers?</strong></summary>

Yes, in CLI/TUI mode. The graphical interface requires a desktop environment, but all features are available via terminal.

</details>

---

## 📄 License

This project is licensed under the **Apache License 2.0** — see the [`LICENSE`](LICENSE) file for details.

```
Copyright 2024-2026 catitodev

Licensed under the Apache License, Version 2.0
```

---

## 👤 Author

**catitodev**

- GitHub: [@catitodev](https://github.com/catitodev)

---

## 🙏 Acknowledgments

- The Rust community for amazing tools and libraries
- The Svelte community for the elegant frontend framework
- All open source security projects that inspired this work
- All contributors and testers

---

<div align="center">

**⭐ If this project helps you, consider giving it a star! ⭐**

Made with ❤️ and 🦀 by [catitodev](https://github.com/catitodev)

</div>
