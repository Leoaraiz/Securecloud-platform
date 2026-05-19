const express = require('express');
const { generateBatch, EVENT_TYPES } = require('../simulation/eventGenerator');
const { analyzeEvent, aggregateRisk } = require('../ai/threatDetector');
const { generateCopilotAnalysis, chatResponse } = require('../ai/copilot');
const { generateZeroTrustSnapshot, evaluateRequest } = require('../services/zeroTrust');
const { analyzeAllPolicies } = require('../services/iamAnalyzer');
const { modelUserBehavior, predictAttackWindows } = require('../simulation/behaviorModel');
const { getStats, getConnectedCount } = require('../websocket/wsServer');

const router = express.Router();

// ─── Health ───────────────────────────────────────────────────────────────────
router.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '2.0.0', wsClients: getConnectedCount(), ts: new Date().toISOString() });
});

// ─── Dashboard stats ─────────────────────────────────────────────────────────
router.get('/dashboard/stats', (req, res) => {
  res.json({ success: true, data: getStats() });
});

// ─── Recent events ────────────────────────────────────────────────────────────
router.get('/events', (req, res) => {
  const count = Math.min(parseInt(req.query.count) || 50, 200);
  const events = generateBatch(count);
  const analyzed = events.map(e => ({ ...e, analysis: analyzeEvent(e) }));
  const risk = aggregateRisk(events);
  res.json({ success: true, data: { events: analyzed, aggregateRisk: risk, count: analyzed.length } });
});

// ─── Single event analysis ────────────────────────────────────────────────────
router.post('/events/analyze', (req, res) => {
  const event = req.body;
  if (!event || !event.type) return res.status(400).json({ error: 'Event payload required' });
  const analysis = analyzeEvent(event);
  const copilot  = generateCopilotAnalysis(event, analysis);
  res.json({ success: true, data: { event, analysis, copilot } });
});

// ─── AI Copilot ───────────────────────────────────────────────────────────────
router.post('/ai/analyze', (req, res) => {
  const { eventId, eventType, severity, confidenceScore, source, target, geo, affectedAssets, riskScore, mitre } = req.body;
  if (!eventType) return res.status(400).json({ error: 'eventType required' });
  const fakeEvent = { eventId, type: eventType, label: eventType, severity, confidenceScore, source, target, geo, affectedAssets, riskScore, mitre };
  const analysis = analyzeEvent(fakeEvent);
  const copilot  = generateCopilotAnalysis(fakeEvent, analysis);
  res.json({ success: true, data: { analysis, copilot } });
});

router.post('/ai/chat', (req, res) => {
  const { query, context } = req.body;
  if (!query || typeof query !== 'string') return res.status(400).json({ error: 'query required' });
  const safeQuery = query.slice(0, 1000); // input length limit
  const response = chatResponse(safeQuery, context || {});
  res.json({ success: true, data: { query: safeQuery, response, model: 'SecureCloud-Copilot-v4.1', ts: new Date().toISOString() } });
});

// ─── Zero Trust ───────────────────────────────────────────────────────────────
router.get('/zero-trust/snapshot', (req, res) => {
  const snapshot = generateZeroTrustSnapshot();
  const summary = {
    trusted:    snapshot.filter(s => s.riskClassification === 'TRUSTED').length,
    conditional: snapshot.filter(s => s.riskClassification === 'CONDITIONAL_ACCESS').length,
    elevated:   snapshot.filter(s => s.riskClassification === 'ELEVATED_RISK').length,
    blocked:    snapshot.filter(s => s.riskClassification === 'BLOCKED').length,
    avgTrust:   parseFloat((snapshot.reduce((s, r) => s + r.trustScore, 0) / snapshot.length).toFixed(3)),
  };
  res.json({ success: true, data: { sessions: snapshot, summary } });
});

router.post('/zero-trust/evaluate', (req, res) => {
  const result = evaluateRequest(req.body);
  res.json({ success: true, data: result });
});

// ─── IAM Analyzer ─────────────────────────────────────────────────────────────
router.get('/iam/analyze', (req, res) => {
  const result = analyzeAllPolicies();
  res.json({ success: true, data: result });
});

// ─── User Behavior ────────────────────────────────────────────────────────────
router.get('/behavior/users', (req, res) => {
  const users = modelUserBehavior();
  res.json({ success: true, data: { users } });
});

router.get('/behavior/attack-windows', (req, res) => {
  const windows = predictAttackWindows();
  const peakHour = windows.reduce((max, w) => w.probability > max.probability ? w : max, windows[0]);
  res.json({ success: true, data: { windows, peakHour, generatedAt: new Date().toISOString() } });
});

// ─── Threat Intelligence ─────────────────────────────────────────────────────
router.get('/intelligence/threat-types', (req, res) => {
  const breakdown = EVENT_TYPES.map(t => ({
    type: t.type, label: t.label, weight: t.weight, mitre: t.mitre,
    count: Math.floor(Math.random() * 200 + 10),
  }));
  res.json({ success: true, data: { breakdown } });
});

router.get('/intelligence/attack-prediction', (req, res) => {
  const windows = predictAttackWindows();
  const current = windows[new Date().getHours()];
  res.json({
    success: true,
    data: {
      currentHour: current,
      nextHighRisk: windows.filter(w => w.probability > 0.55).slice(0, 3),
      overallProbability: parseFloat((windows.reduce((s, w) => s + w.probability, 0) / 24).toFixed(3)),
      windows,
    },
  });
});

module.exports = router;
