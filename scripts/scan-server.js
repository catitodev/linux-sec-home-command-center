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

  // 404
  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`🛡️  LHCC Scan Server running on http://127.0.0.1:${PORT}`);
  console.log('   Endpoints: /api/health, /api/scan/quick, /api/scan/full, /api/audit/lynis, /api/firewall/status');
});
