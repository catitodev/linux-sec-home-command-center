#!/usr/bin/env node
// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
//
// LHCC Real Scan Server — executes security tools and returns results
// Runs on localhost:3030 — called by the frontend dashboard

const http = require('http');
const { execSync, exec } = require('child_process');

const PORT = 3030;

function runCommand(cmd, timeout = 60000) {
  try {
    const result = execSync(cmd, { timeout, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
    return { success: true, output: result.trim() };
  } catch (err) {
    return { success: false, output: err.stderr?.trim() || err.message || 'Command failed' };
  }
}

function corsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');
}

const server = http.createServer((req, res) => {
  corsHeaders(res);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = req.url;

  // Health check
  if (url === '/api/health') {
    const tools = [];
    const checks = [
      { name: 'clamav', cmd: 'which clamscan' },
      { name: 'chkrootkit', cmd: 'which chkrootkit' },
      { name: 'rkhunter', cmd: 'which rkhunter' },
      { name: 'lynis', cmd: 'which lynis' },
      { name: 'ufw', cmd: 'which ufw' },
      { name: 'auditd', cmd: 'which auditctl' },
      { name: 'yara', cmd: 'which yara' },
      { name: 'ollama', cmd: 'which ollama' },
    ];

    for (const check of checks) {
      const result = runCommand(check.cmd);
      tools.push({ name: check.name, display_name: check.name, status: result.success ? 'running' : 'not_installed' });
    }

    const activeCount = tools.filter(t => t.status === 'running').length;
    const score = Math.round((activeCount / tools.length) * 100);

    res.writeHead(200);
    res.end(JSON.stringify({ score, tools, active_alerts: 0, blocked_connections: 0 }));
    return;
  }

  // Quick scan (ClamAV on /home)
  if (url === '/api/scan/quick') {
    console.log('[SCAN] Starting quick scan on /home...');
    const startTime = Date.now();

    exec('clamscan -r --infected --no-summary /home 2>/dev/null | head -50', { timeout: 120000 }, (err, stdout, stderr) => {
      const duration = ((Date.now() - startTime) / 1000).toFixed(1);
      const lines = stdout.trim().split('\n').filter(l => l.includes('FOUND'));
      const findings = lines.map(l => {
        const parts = l.split(':');
        return { path: parts[0]?.trim(), threat: parts[1]?.trim()?.replace(' FOUND', ''), engine: 'ClamAV', severity: 'high' };
      });

      console.log(`[SCAN] Complete: ${findings.length} findings in ${duration}s`);
      res.writeHead(200);
      res.end(JSON.stringify({ findings, duration: `${duration}s`, tool: 'ClamAV', scope: '/home' }));
    });
    return;
  }

  // Full scan (ClamAV + chkrootkit + rkhunter)
  if (url === '/api/scan/full') {
    console.log('[SCAN] Starting full scan...');
    const startTime = Date.now();
    const allFindings = [];

    // ClamAV
    const clamResult = runCommand('clamscan -r --infected --no-summary /home /tmp /var/tmp 2>/dev/null | head -50', 180000);
    if (clamResult.success) {
      const lines = clamResult.output.split('\n').filter(l => l.includes('FOUND'));
      lines.forEach(l => {
        const parts = l.split(':');
        allFindings.push({ path: parts[0]?.trim(), threat: parts[1]?.trim()?.replace(' FOUND', ''), engine: 'ClamAV', severity: 'high' });
      });
    }

    // chkrootkit
    const chkResult = runCommand('chkrootkit 2>/dev/null | grep -i "INFECTED\\|SUSPECT"', 60000);
    if (chkResult.success && chkResult.output) {
      chkResult.output.split('\n').forEach(l => {
        if (l.trim()) allFindings.push({ path: l.trim(), threat: 'Rootkit indicator', engine: 'chkrootkit', severity: 'critical' });
      });
    }

    // rkhunter
    const rkResult = runCommand('rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | grep -i "Warning"', 120000);
    if (rkResult.success && rkResult.output) {
      rkResult.output.split('\n').forEach(l => {
        if (l.trim()) allFindings.push({ path: l.trim(), threat: 'Security warning', engine: 'rkhunter', severity: 'medium' });
      });
    }

    const duration = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`[SCAN] Full scan complete: ${allFindings.length} findings in ${duration}s`);

    res.writeHead(200);
    res.end(JSON.stringify({ findings: allFindings, duration: `${duration}s`, tools: ['ClamAV', 'chkrootkit', 'rkhunter'], scope: 'full' }));
    return;
  }

  // Lynis audit
  if (url === '/api/audit/lynis') {
    console.log('[AUDIT] Running Lynis...');
    const result = runCommand('lynis audit system --no-colors --quick 2>/dev/null | grep -E "\\[WARNING\\]|Hardening index"', 120000);
    const lines = result.output.split('\n').filter(l => l.trim());
    const warnings = lines.filter(l => l.includes('WARNING')).map(l => ({ description: l.trim(), severity: 'medium' }));
    const indexLine = lines.find(l => l.includes('Hardening index'));
    const hardeningIndex = indexLine ? parseInt(indexLine.match(/\d+/)?.[0] || '0') : 0;

    res.writeHead(200);
    res.end(JSON.stringify({ hardening_index: hardeningIndex, warnings, total_warnings: warnings.length }));
    return;
  }

  // UFW status
  if (url === '/api/firewall/status') {
    const result = runCommand('ufw status numbered 2>/dev/null');
    res.writeHead(200);
    res.end(JSON.stringify({ output: result.output, active: result.output.includes('active') }));
    return;
  }

  // System info
  if (url === '/api/system/info') {
    const hostname = runCommand('hostname').output;
    const kernel = runCommand('uname -r').output;
    const uptime = runCommand('uptime -p').output;
    const users = runCommand('who | wc -l').output;

    res.writeHead(200);
    res.end(JSON.stringify({ hostname, kernel, uptime, active_users: parseInt(users) || 1 }));
    return;
  }

  // Network connections (ss command)
  if (url === '/api/network/connections') {
    const result = runCommand('ss -tnp state established 2>/dev/null | tail -20');
    const lines = result.output.split('\n').filter(l => l.trim() && !l.startsWith('Recv'));
    const connections = lines.map((l, i) => {
      const parts = l.trim().split(/\s+/);
      const local = parts[3] || '';
      const remote = parts[4] || '';
      const process = (parts[5] || '').match(/"([^"]+)"/)?.[1] || 'unknown';
      return {
        id: String(i),
        processName: process,
        processId: 0,
        destIp: remote.split(':')[0] || remote,
        destPort: parseInt(remote.split(':').pop()) || 0,
        protocol: 'TCP',
        dataVolume: '-',
        duration: '-',
        blocked: false
      };
    });
    res.writeHead(200);
    res.end(JSON.stringify({ connections }));
    return;
  }

  // Events/logs from journalctl
  if (url === '/api/events') {
    const result = runCommand('journalctl --since "24 hours ago" -p warning --no-pager -o json 2>/dev/null | tail -20');
    const events = result.output.split('\n').filter(l => l.trim()).map((l, i) => {
      try {
        const j = JSON.parse(l);
        return {
          id: String(i),
          source_tool: j.SYSLOG_IDENTIFIER || 'system',
          severity: 4,
          description: j.MESSAGE || '',
          entity_type: 'system',
          entity_id: j._PID || '',
          created_at: new Date(parseInt(j.__REALTIME_TIMESTAMP) / 1000).toISOString(),
          correlated: false,
          correlation_id: null
        };
      } catch { return null; }
    }).filter(Boolean);
    res.writeHead(200);
    res.end(JSON.stringify({ events }));
    return;
  }

  // Hardening recommendations from Lynis
  if (url === '/api/hardening') {
    const result = runCommand('lynis show suggestions 2>/dev/null | head -30', 30000);
    const lines = result.output.split('\n').filter(l => l.trim());
    const findings = lines.map((l, i) => ({
      id: String(i),
      category: l.includes('SSH') || l.includes('auth') ? 'auth' : l.includes('network') || l.includes('firewall') ? 'networking' : l.includes('file') || l.includes('perm') ? 'filesystem' : 'kernel',
      priority: 'medium',
      title: l.trim().substring(0, 80),
      description: l.trim(),
      fixAvailable: false,
      applied: false
    }));
    res.writeHead(200);
    res.end(JSON.stringify({ findings, hardening_index: 0 }));
    return;
  }

  // Generate report (creates a real text file)
  if (url === '/api/report/generate') {
    const fs = require('fs');
    const date = new Date().toISOString().slice(0, 10);
    const reportDir = '/tmp/lhcc-reports';
    if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });

    const hostname = runCommand('hostname').output;
    const kernel = runCommand('uname -r').output;
    const uptime = runCommand('uptime -p').output;
    const ufwStatus = runCommand('ufw status 2>/dev/null').output;

    const report = `
═══════════════════════════════════════════════════════
  LHCC — Relatório de Segurança
  Data: ${new Date().toLocaleString('pt-BR')}
═══════════════════════════════════════════════════════

SISTEMA:
  Hostname: ${hostname}
  Kernel: ${kernel}
  Uptime: ${uptime}

FIREWALL (UFW):
${ufwStatus || '  Não configurado'}

FERRAMENTAS INSTALADAS:
  ClamAV: ${runCommand('which clamscan').success ? '✓' : '✗'}
  chkrootkit: ${runCommand('which chkrootkit').success ? '✓' : '✗'}
  rkhunter: ${runCommand('which rkhunter').success ? '✓' : '✗'}
  Lynis: ${runCommand('which lynis').success ? '✓' : '✗'}
  YARA: ${runCommand('which yara').success ? '✓' : '✗'}
  auditd: ${runCommand('which auditctl').success ? '✓' : '✗'}

═══════════════════════════════════════════════════════
  Gerado por Linux Security Home Command Center v1.0
  https://github.com/catitodev/linux-sec-home-command-center
═══════════════════════════════════════════════════════
`;

    const filename = `relatorio_seguranca_${date}.txt`;
    const filepath = `${reportDir}/${filename}`;
    fs.writeFileSync(filepath, report);

    res.writeHead(200);
    res.end(JSON.stringify({ filename, filepath, content: report, date: new Date().toLocaleString('pt-BR') }));
    return;
  }

  // Download report
  if (url.startsWith('/api/report/download/')) {
    const fs = require('fs');
    const filename = url.split('/').pop();
    const filepath = `/tmp/lhcc-reports/${filename}`;
    if (fs.existsSync(filepath)) {
      const content = fs.readFileSync(filepath, 'utf-8');
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.writeHead(200);
      res.end(content);
    } else {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'Report not found' }));
    }
    return;
  }

  // Logs from journalctl (for Reports page)
  if (url === '/api/logs') {
    const result = runCommand('journalctl --since "7 days ago" --no-pager -o short 2>/dev/null | grep -iE "(error|warning|failed|denied|blocked)" | tail -30');
    const logs = result.output.split('\n').filter(l => l.trim()).map((l, i) => ({
      id: String(i),
      timestamp: l.substring(0, 15),
      operation: l.includes('error') ? 'system_change' : l.includes('denied') ? 'authentication' : 'scan',
      description: l.substring(16).trim().substring(0, 100),
      severity: l.toLowerCase().includes('error') ? 'high' : l.toLowerCase().includes('warning') ? 'medium' : 'low',
      user: 'system'
    }));
    res.writeHead(200);
    res.end(JSON.stringify({ logs }));
    return;
  }

  // 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`🛡️  LHCC Scan Server running on http://127.0.0.1:${PORT}`);
  console.log('   Endpoints: /api/health, /api/scan/quick, /api/scan/full, /api/audit/lynis');
  console.log('   /api/firewall/status, /api/network/connections, /api/events');
  console.log('   /api/hardening, /api/report/generate, /api/report/download/:file, /api/logs');
});
