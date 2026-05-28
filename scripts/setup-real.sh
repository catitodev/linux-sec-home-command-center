#!/bin/bash
# Copyright 2024-2026 catitodev
# Licensed under the Apache License, Version 2.0
#
# SETUP REAL — Instala todas as ferramentas de segurança e configura o sistema
# Execute com: sudo bash scripts/setup-real.sh

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Execute com sudo: sudo bash scripts/setup-real.sh${NC}"
    exit 1
fi

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  🛡️  LHCC — Instalação de Ferramentas Reais         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Atualizar repositórios
echo -e "${YELLOW}[1/7] Atualizando repositórios...${NC}"
apt-get update -qq

# 2. Instalar ferramentas de segurança
echo -e "${YELLOW}[2/7] Instalando ClamAV, Lynis, chkrootkit, rkhunter, AIDE, auditd, UFW...${NC}"
apt-get install -y -qq \
    clamav clamav-daemon clamav-freshclam \
    lynis \
    chkrootkit \
    rkhunter \
    aide \
    auditd \
    ufw \
    yara

echo -e "${GREEN}      ✓ Ferramentas de segurança instaladas${NC}"

# 3. Atualizar assinaturas do ClamAV
echo -e "${YELLOW}[3/7] Atualizando assinaturas do ClamAV (pode demorar)...${NC}"
systemctl stop clamav-freshclam 2>/dev/null || true
freshclam 2>/dev/null || echo "      (freshclam pode falhar na primeira vez — normal)"
systemctl start clamav-freshclam 2>/dev/null || true
echo -e "${GREEN}      ✓ ClamAV configurado${NC}"

# 4. Configurar UFW
echo -e "${YELLOW}[4/7] Configurando firewall UFW...${NC}"
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
echo -e "${GREEN}      ✓ UFW ativado (deny incoming, allow outgoing)${NC}"

# 5. Configurar auditd
echo -e "${YELLOW}[5/7] Configurando auditd...${NC}"
systemctl enable auditd
systemctl start auditd
echo -e "${GREEN}      ✓ auditd ativo${NC}"

# 6. Inicializar AIDE
echo -e "${YELLOW}[6/7] Inicializando baseline AIDE (pode demorar ~2min)...${NC}"
aideinit 2>/dev/null || aide --init 2>/dev/null || echo "      (AIDE init pode precisar de configuração manual)"
echo -e "${GREEN}      ✓ AIDE inicializado${NC}"

# 7. Instalar Ollama (LLM local para o LHCC Agent)
echo -e "${YELLOW}[7/7] Instalando Ollama (IA local)...${NC}"
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
    echo -e "${GREEN}      ✓ Ollama instalado${NC}"
else
    echo -e "${GREEN}      ✓ Ollama já instalado${NC}"
fi

# Baixar modelo leve
echo -e "${YELLOW}      Baixando modelo de IA (tinyllama ~637MB)...${NC}"
sudo -u "$SUDO_USER" ollama pull tinyllama 2>/dev/null || echo "      (Execute manualmente: ollama pull tinyllama)"

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Instalação completa!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Ferramentas instaladas:"
echo "    • ClamAV + YARA (antivírus)"
echo "    • Lynis (auditoria de hardening)"
echo "    • chkrootkit + rkhunter (detecção de rootkits)"
echo "    • AIDE (integridade de arquivos)"
echo "    • auditd (auditoria do kernel)"
echo "    • UFW (firewall)"
echo "    • Ollama + tinyllama (IA local para LHCC Agent)"
echo ""
echo "  Próximo passo: clique no ícone LinuxSec na área de trabalho"
echo "  ou execute: ./scripts/start.sh"
echo ""
