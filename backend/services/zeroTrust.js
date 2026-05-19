/**
 * Zero Trust Security Evaluation Engine
 * Formula: Trust = Identity × Device × Behavior × Context
 */

const DEVICE_PROFILES = [
  { id: 'dev-corp-001', type: 'Corporate Laptop', os: 'macOS 14', compliant: true,  encrypted: true,  mdm: true,  score: 0.95 },
  { id: 'dev-corp-002', type: 'Corporate Windows', os: 'Windows 11', compliant: true, encrypted: true, mdm: true, score: 0.92 },
  { id: 'dev-byod-003', type: 'Personal iPhone', os: 'iOS 17', compliant: false, encrypted: true, mdm: false, score: 0.60 },
  { id: 'dev-byod-004', type: 'Personal Android', os: 'Android 13', compliant: false, encrypted: false, mdm: false, score: 0.35 },
  { id: 'dev-unknown-005', type: 'Unknown Device', os: 'Unknown', compliant: false, encrypted: false, mdm: false, score: 0.10 },
];

const CONTEXT_FACTORS = {
  'Corporate VPN':   0.95,
  'Office Network':  0.90,
  'Home Network':    0.65,
  'Public WiFi':     0.30,
  'Tor/VPN Exit':    0.05,
  'Cloud Instance':  0.70,
};

function evaluateIdentity(user) {
  let score = 0.5;
  if (user?.mfaEnabled)      score += 0.25;
  if (user?.ssoFederated)    score += 0.15;
  if (user?.riskLevel === 'LOW')    score += 0.10;
  if (user?.riskLevel === 'HIGH')   score -= 0.20;
  if (user?.riskLevel === 'CRITICAL') score -= 0.40;
  return Math.min(Math.max(parseFloat(score.toFixed(3)), 0), 1);
}

function evaluateDevice(deviceId) {
  const device = DEVICE_PROFILES.find(d => d.id === deviceId) || DEVICE_PROFILES[4];
  return { score: device.score, profile: device };
}

function evaluateBehavior(behaviorAnomaly) {
  // inverse of anomaly = behavior trust
  return parseFloat((1 - Math.min(behaviorAnomaly, 1)).toFixed(3));
}

function evaluateContext(networkContext) {
  const score = CONTEXT_FACTORS[networkContext] ?? 0.50;
  return parseFloat(score.toFixed(3));
}

function evaluateRequest(requestCtx) {
  const {
    user = {},
    deviceId = 'dev-unknown-005',
    behaviorAnomaly = 0.5,
    networkContext = 'Home Network',
  } = requestCtx;

  const identityScore  = evaluateIdentity(user);
  const deviceEval     = evaluateDevice(deviceId);
  const deviceScore    = deviceEval.score;
  const behaviorScore  = evaluateBehavior(behaviorAnomaly);
  const contextScore   = evaluateContext(networkContext);

  // Trust = product of all four scores
  const rawTrust = identityScore * deviceScore * behaviorScore * contextScore;
  const trustScore = parseFloat(rawTrust.toFixed(4));

  const riskClass = trustScore > 0.6 ? 'TRUSTED'
                  : trustScore > 0.3 ? 'CONDITIONAL_ACCESS'
                  : trustScore > 0.1 ? 'ELEVATED_RISK'
                  :                    'BLOCKED';

  const action = {
    TRUSTED:            'Allow — Full access granted',
    CONDITIONAL_ACCESS: 'Allow — Step-up MFA required',
    ELEVATED_RISK:      'Restrict — Limited access, enhanced logging',
    BLOCKED:            'Deny — Access blocked, security alert triggered',
  }[riskClass];

  return {
    trustScore,
    riskClassification: riskClass,
    action,
    breakdown: {
      identityTrust:  identityScore,
      deviceTrust:    deviceScore,
      behaviorTrust:  behaviorScore,
      contextTrust:   contextScore,
    },
    deviceProfile: deviceEval.profile,
    policyViolations: [
      !deviceEval.profile.compliant && 'Device is not compliance-registered',
      !deviceEval.profile.encrypted && 'Device disk encryption not verified',
      !deviceEval.profile.mdm && 'Device not enrolled in MDM',
      behaviorAnomaly > 0.5 && 'Anomalous behavioral pattern detected',
      contextScore < 0.4 && 'Untrusted network context',
    ].filter(Boolean),
    evaluatedAt: new Date().toISOString(),
  };
}

// Generate a batch of simulated evaluations for dashboard
function generateZeroTrustSnapshot() {
  const { modelUserBehavior } = require('../simulation/behaviorModel');
  const users = modelUserBehavior();
  const networks = Object.keys(CONTEXT_FACTORS);

  return users.map(u => {
    const device = DEVICE_PROFILES[Math.floor(Math.random() * DEVICE_PROFILES.length)];
    const network = networks[Math.floor(Math.random() * networks.length)];
    const result = evaluateRequest({
      user: { ...u, mfaEnabled: Math.random() > 0.3, ssoFederated: Math.random() > 0.5, riskLevel: u.riskLevel },
      deviceId: device.id,
      behaviorAnomaly: u.anomalyScore,
      networkContext: network,
    });
    return { user: u, network, device: device.type, ...result };
  });
}

module.exports = { evaluateRequest, generateZeroTrustSnapshot, DEVICE_PROFILES, CONTEXT_FACTORS };
