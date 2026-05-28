#!/bin/bash
# Copyright 2024-2026 catitodev
# Licensed under the Apache License, Version 2.0
# SPDX-License-Identifier: Apache-2.0
#
# Instala o ícone na área de trabalho e no menu de aplicações

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DESKTOP_FILE="$HOME/.local/share/applications/lshcc.desktop"
DESKTOP_LINK="$HOME/Desktop/lshcc.desktop"
ICON_PATH="$PROJECT_DIR/assets/icon.png"

# Criar ícone PNG a partir do SVG (se ImageMagick disponível)
if command -v convert &> /dev/null && [ -f "$PROJECT_DIR/assets/logo-animated.svg" ]; then
    convert "$PROJECT_DIR/assets/logo-animated.svg" -resize 128x128 "$ICON_PATH" 2>/dev/null || true
fi

# Se não conseguiu converter, usar um ícone genérico
if [ ! -f "$ICON_PATH" ]; then
    ICON_PATH="security-high"
fi

# Criar arquivo .desktop
mkdir -p "$HOME/.local/share/applications"

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=LinuxSec Command Center
GenericName=Security Dashboard
Comment=Centro de Comando de Segurança para Linux
Exec=bash $PROJECT_DIR/scripts/start.sh
Icon=$ICON_PATH
Terminal=false
Categories=System;Security;Monitor;
Keywords=security;firewall;antivirus;monitor;linux;
StartupNotify=true
StartupWMClass=lshcc
EOF

# Copiar para a área de trabalho
if [ -d "$HOME/Desktop" ]; then
    cp "$DESKTOP_FILE" "$DESKTOP_LINK"
    chmod +x "$DESKTOP_LINK"
    # Marcar como confiável (GNOME)
    gio set "$DESKTOP_LINK" metadata::trusted true 2>/dev/null || true
    echo "✅ Ícone criado na Área de Trabalho"
elif [ -d "$HOME/Área de Trabalho" ]; then
    cp "$DESKTOP_FILE" "$HOME/Área de Trabalho/lshcc.desktop"
    chmod +x "$HOME/Área de Trabalho/lshcc.desktop"
    gio set "$HOME/Área de Trabalho/lshcc.desktop" metadata::trusted true 2>/dev/null || true
    echo "✅ Ícone criado na Área de Trabalho"
fi

echo "✅ Atalho instalado no menu de aplicações"
echo ""
echo "Agora você pode:"
echo "  • Clicar no ícone 🛡️ na área de trabalho"
echo "  • Buscar 'LinuxSec' no menu de aplicações"
echo "  • Ou executar: $PROJECT_DIR/scripts/start.sh"
