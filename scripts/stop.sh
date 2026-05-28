#!/bin/bash
# Copyright 2024-2026 catitodev
# Licensed under the Apache License, Version 2.0
# SPDX-License-Identifier: Apache-2.0
#
# Linux Security Home Command Center — Stop Script

PID_FILE="/tmp/lshcc.pid"

if [ -f "$PID_FILE" ]; then
    echo "🛑 Parando Linux Security Home Command Center..."
    while read pid; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            echo "   ✓ Processo $pid encerrado"
        fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
    echo "✅ Parado com sucesso"
else
    echo "ℹ️  Nenhuma instância rodando (PID file não encontrado)"
fi

# Limpar socket
rm -f /tmp/security-command-center/api.sock
