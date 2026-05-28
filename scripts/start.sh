#!/bin/bash
# Copyright 2024-2026 catitodev
# Licensed under the Apache License, Version 2.0
# SPDX-License-Identifier: Apache-2.0
#
# Linux Security Home Command Center — Startup Script
# Inicia o Backend API + Frontend Dashboard localmente

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SOCKET_DIR="/tmp/security-command-center"
SOCKET_PATH="$SOCKET_DIR/api.sock"
FRONTEND_PORT=5173
PID_FILE="/tmp/lshcc.pid"

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════╗"
echo "║  🛡️  Linux Security Home Command Center             ║"
echo "║      Starting local instance...                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verificar se Rust está instalado
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}[ERRO] Rust/Cargo não encontrado. Instale via: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
    exit 1
fi

# Verificar se Node.js está instalado
if ! command -v node &> /dev/null; then
    echo -e "${RED}[ERRO] Node.js não encontrado. Instale via: sudo apt install nodejs npm${NC}"
    exit 1
fi

# Criar diretório do socket
mkdir -p "$SOCKET_DIR"

# Compilar o backend (se necessário)
echo -e "${YELLOW}[1/4] Compilando backend (Rust)...${NC}"
cd "$PROJECT_DIR"
if [ ! -f "target/release/backend-api" ] || [ "$1" == "--rebuild" ]; then
    cargo build --release --bin backend-api 2>&1 | tail -3
    echo -e "${GREEN}      ✓ Backend compilado${NC}"
else
    echo -e "${GREEN}      ✓ Backend já compilado (use --rebuild para recompilar)${NC}"
fi

# Instalar dependências do frontend (se necessário)
echo -e "${YELLOW}[2/4] Preparando frontend (Svelte)...${NC}"
cd "$PROJECT_DIR/frontend"
if [ ! -d "node_modules" ]; then
    npm install --silent 2>&1 | tail -1
    echo -e "${GREEN}      ✓ Dependências instaladas${NC}"
else
    echo -e "${GREEN}      ✓ Dependências já instaladas${NC}"
fi

# Iniciar o Backend API
echo -e "${YELLOW}[3/4] Iniciando Backend API...${NC}"
cd "$PROJECT_DIR"
export SCC_SOCKET_PATH="$SOCKET_PATH"
./target/release/backend-api &
BACKEND_PID=$!
echo "$BACKEND_PID" > "$PID_FILE"
sleep 1

# Verificar se o backend iniciou
if kill -0 $BACKEND_PID 2>/dev/null; then
    echo -e "${GREEN}      ✓ Backend rodando (PID: $BACKEND_PID, Socket: $SOCKET_PATH)${NC}"
else
    echo -e "${RED}      ✗ Falha ao iniciar o backend${NC}"
    exit 1
fi

# Iniciar o Frontend (dev server)
echo -e "${YELLOW}[4/4] Iniciando Dashboard (http://localhost:$FRONTEND_PORT)...${NC}"
cd "$PROJECT_DIR/frontend"
npx vite --port $FRONTEND_PORT --open &
FRONTEND_PID=$!
echo "$FRONTEND_PID" >> "$PID_FILE"

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Linux Security Home Command Center está rodando!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  🌐 Dashboard: ${GREEN}http://localhost:$FRONTEND_PORT${NC}"
echo -e "  ⚙️  Backend:   ${GREEN}$SOCKET_PATH${NC}"
echo -e "  🤖 IronClaw:  ${GREEN}Ctrl+Shift+I no dashboard${NC}"
echo ""
echo -e "  Para parar: ${YELLOW}./scripts/stop.sh${NC} ou ${YELLOW}Ctrl+C${NC}"
echo ""

# Aguardar Ctrl+C
trap "echo ''; echo -e '${YELLOW}Parando...${NC}'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; rm -f $PID_FILE; echo -e '${GREEN}✓ Parado${NC}'; exit 0" INT TERM

wait
