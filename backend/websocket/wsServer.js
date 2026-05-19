const WebSocket = require('ws');
const { generateEvent, generateThreatWave } = require('../simulation/eventGenerator');
const { analyzeEvent } = require('../ai/threatDetector');

let wss = null;
const connectedClients = new Set();

// Global state broadcast to all clients
let stats = {
  totalEvents:    0,
  criticalAlerts: 0,
  highAlerts:     0,
  blockedAttacks: 0,
  activeThreats:  0,
  avgRiskScore:   0,
  riskHistory:    [], // last 20 data points
  started:        new Date().toISOString(),
};

function broadcast(data) {
  if (!wss) return;
  const msg = JSON.stringify(data);
  connectedClients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      try { client.send(msg); } catch { connectedClients.delete(client); }
    }
  });
}

function updateStats(event, analysis) {
  stats.totalEvents++;
  if (event.severity === 'CRITICAL') stats.criticalAlerts++;
  if (event.severity === 'HIGH')     stats.highAlerts++;
  if (Math.random() > 0.4)          stats.blockedAttacks++;
  stats.activeThreats = Math.max(0, stats.activeThreats + (Math.random() > 0.7 ? 1 : -1));
  stats.activeThreats = Math.min(stats.activeThreats, 25);

  // Rolling avg risk
  const risk = analysis?.analysis?.compositeRiskScore || 0;
  stats.riskHistory.push({ t: Date.now(), v: risk });
  if (stats.riskHistory.length > 30) stats.riskHistory.shift();
  stats.avgRiskScore = parseFloat(
    (stats.riskHistory.reduce((s, r) => s + r.v, 0) / stats.riskHistory.length).toFixed(3)
  );
}

function setupWebSocket(server) {
  wss = new WebSocket.Server({ server, path: '/ws' });

  wss.on('connection', (ws, req) => {
    connectedClients.add(ws);
    console.log(`[WS] Client connected. Total: ${connectedClients.size}`);

    // Send current stats immediately on connect
    ws.send(JSON.stringify({ type: 'STATS_UPDATE', payload: stats }));

    ws.on('close', () => {
      connectedClients.delete(ws);
      console.log(`[WS] Client disconnected. Total: ${connectedClients.size}`);
    });

    ws.on('error', (err) => {
      console.error('[WS] Error:', err.message);
      connectedClients.delete(ws);
    });

    // Handle client → server messages (e.g., subscribe filters)
    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw);
        if (msg.type === 'PING') ws.send(JSON.stringify({ type: 'PONG', ts: Date.now() }));
      } catch { /* ignore */ }
    });
  });

  // ─── Streaming loop ────────────────────────────────────────────────────────
  // Regular events every 2–5 seconds
  function streamEvent() {
    if (connectedClients.size > 0) {
      const event    = generateEvent();
      const analysis = analyzeEvent(event);
      updateStats(event, analysis);

      broadcast({ type: 'SECURITY_EVENT', payload: { ...event, analysis } });
      broadcast({ type: 'STATS_UPDATE',   payload: stats });
    }

    // Random interval 2000–5000ms
    const next = Math.floor(Math.random() * 3000) + 2000;
    setTimeout(streamEvent, next);
  }

  // Occasional threat wave bursts
  function streamThreatWave() {
    if (connectedClients.size > 0 && Math.random() > 0.6) {
      const wave = generateThreatWave();
      wave.forEach(event => {
        const analysis = analyzeEvent(event);
        updateStats(event, analysis);
        broadcast({ type: 'THREAT_WAVE', payload: { ...event, analysis, isWave: true } });
      });
      broadcast({ type: 'STATS_UPDATE', payload: stats });
    }
    setTimeout(streamThreatWave, Math.floor(Math.random() * 30000) + 20000);
  }

  streamEvent();
  streamThreatWave();

  // Stats heartbeat every 10s
  setInterval(() => {
    if (connectedClients.size > 0) {
      broadcast({ type: 'HEARTBEAT', payload: { ts: Date.now(), clients: connectedClients.size, ...stats } });
    }
  }, 10000);

  console.log('[WS] WebSocket server running on /ws');
  return wss;
}

function getStats() { return stats; }
function getConnectedCount() { return connectedClients.size; }

module.exports = { setupWebSocket, getStats, getConnectedCount, broadcast };
