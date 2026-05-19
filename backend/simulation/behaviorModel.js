// Simulates user behavior patterns for anomaly scoring

const USERS = [
  { id: 'u001', name: 'alice.chen', role: 'developer', baseHour: 9, baseDuration: 8, riskBase: 0.1 },
  { id: 'u002', name: 'bob.smith', role: 'admin', baseHour: 8, baseDuration: 10, riskBase: 0.2 },
  { id: 'u003', name: 'carol.dev', role: 'developer', baseHour: 10, baseDuration: 7, riskBase: 0.05 },
  { id: 'u004', name: 'dave.ops', role: 'devops', baseHour: 7, baseDuration: 12, riskBase: 0.15 },
  { id: 'u005', name: 'eve.analyst', role: 'analyst', baseHour: 9, baseDuration: 8, riskBase: 0.08 },
  { id: 'u006', name: 'service-account-ci', role: 'service', baseHour: 0, baseDuration: 24, riskBase: 0.25 },
];

// Session store
const sessionStore = new Map();

function getCurrentHour() { return new Date().getHours(); }

function scoreLoginBehavior(userId) {
  const user = USERS.find(u => u.id === userId) || USERS[0];
  const hour = getCurrentHour();
  const expectedStart = user.baseHour;
  const expectedEnd = (user.baseHour + user.baseDuration) % 24;

  // Outside working hours?
  const isOffHours = hour < expectedStart || hour > expectedEnd;
  const offHourPenalty = isOffHours ? 0.4 : 0;

  // Too many sessions?
  const sessions = sessionStore.get(userId) || 0;
  const sessionPenalty = Math.min(sessions * 0.1, 0.3);

  sessionStore.set(userId, sessions + 1);
  setTimeout(() => {
    const s = sessionStore.get(userId) || 1;
    sessionStore.set(userId, Math.max(s - 1, 0));
  }, 3600000); // decay after 1h

  const anomalyScore = Math.min(user.riskBase + offHourPenalty + sessionPenalty, 1);
  return {
    userId, username: user.name, role: user.role,
    anomalyScore: parseFloat(anomalyScore.toFixed(3)),
    isOffHours, sessions: sessions + 1,
    riskFactors: [
      isOffHours && 'Off-hours access',
      sessions > 2 && 'Multiple concurrent sessions',
      user.role === 'admin' && 'Admin role',
    ].filter(Boolean),
  };
}

function modelUserBehavior() {
  return USERS.map(u => {
    const hour = getCurrentHour();
    const isActive = hour >= u.baseHour && hour <= (u.baseHour + u.baseDuration) % 24;
    const loginFreq = isActive ? Math.floor(Math.random() * 5) + 1 : 0;
    const anomaly = parseFloat((u.riskBase + (isActive ? 0 : 0.2) + Math.random() * 0.1).toFixed(3));
    return {
      ...u,
      isActive,
      loginFreq,
      anomalyScore: Math.min(anomaly, 1),
      lastSeen: isActive ? `${Math.floor(Math.random() * 30)}m ago` : `${Math.floor(Math.random() * 8) + 1}h ago`,
      riskLevel: anomaly > 0.6 ? 'HIGH' : anomaly > 0.3 ? 'MEDIUM' : 'LOW',
    };
  });
}

// Predict time-risk windows
function predictAttackWindows() {
  const hours = Array.from({ length: 24 }, (_, h) => {
    // Higher risk at night and early morning (attacker time zones)
    const nightRisk = (h < 6 || h > 22) ? 0.3 : 0;
    const lunchRisk = (h >= 12 && h <= 13) ? 0.1 : 0; // staff distracted
    const baseRisk = 0.15 + Math.random() * 0.2;
    const probability = Math.min(baseRisk + nightRisk + lunchRisk, 1);
    return { hour: h, probability: parseFloat(probability.toFixed(3)), label: `${h}:00` };
  });
  return hours;
}

module.exports = { scoreLoginBehavior, modelUserBehavior, predictAttackWindows, USERS };
