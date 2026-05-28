#!/bin/bash
# LHCC — Fix dpkg errors and install all security tools
# Execute: sudo bash "/home/catitodev/1. Linux_security_homecommandcenter/scripts/fix-and-install.sh"

set -e
export DEBIAN_FRONTEND=noninteractive

echo "╔══════════════════════════════════════════════════════╗"
echo "║  🛡️  LHCC — Corrigindo e Instalando Tudo            ║"
echo "╚══════════════════════════════════════════════════════╝"

# Step 1: Fix broken dpkg
echo "[1/5] Corrigindo pacotes quebrados..."
dpkg --configure -a 2>/dev/null || true
apt-get install -f -y 2>/dev/null || true

# Step 2: Remove problematic postfix if it's causing issues
echo "[2/5] Removendo postfix (não necessário)..."
apt-get remove -y postfix 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true

# Step 3: Install security tools one by one (so one failure doesn't block others)
echo "[3/5] Instalando ferramentas de segurança..."

for pkg in clamav clamav-daemon lynis chkrootkit rkhunter auditd yara; do
    echo "  → Instalando $pkg..."
    apt-get install -y --no-install-recommends "$pkg" 2>/dev/null && echo "    ✓ $pkg instalado" || echo "    ✗ $pkg falhou (continuando...)"
done

# Step 4: Update ClamAV signatures
echo "[4/5] Atualizando assinaturas ClamAV..."
systemctl stop clamav-freshclam 2>/dev/null || true
freshclam 2>/dev/null && echo "  ✓ Assinaturas atualizadas" || echo "  ⚠ freshclam falhou (normal na primeira vez)"
systemctl start clamav-freshclam 2>/dev/null || true

# Step 5: Verify what got installed
echo "[5/5] Verificando instalação..."
echo ""
echo "═══════════════════════════════════════"
echo "  RESULTADO:"
echo "═══════════════════════════════════════"
which clamscan >/dev/null 2>&1 && echo "  ✓ ClamAV" || echo "  ✗ ClamAV"
which chkrootkit >/dev/null 2>&1 && echo "  ✓ chkrootkit" || echo "  ✗ chkrootkit"
which rkhunter >/dev/null 2>&1 && echo "  ✓ rkhunter" || echo "  ✗ rkhunter"
which lynis >/dev/null 2>&1 && echo "  ✓ Lynis" || echo "  ✗ Lynis"
which yara >/dev/null 2>&1 && echo "  ✓ YARA" || echo "  ✗ YARA"
which auditctl >/dev/null 2>&1 && echo "  ✓ auditd" || echo "  ✗ auditd"
which ufw >/dev/null 2>&1 && echo "  ✓ UFW" || echo "  ✗ UFW"
which ollama >/dev/null 2>&1 && echo "  ✓ Ollama" || echo "  ✗ Ollama"
echo "═══════════════════════════════════════"
echo ""
echo "Pronto! Agora recarregue o dashboard (F5)."
