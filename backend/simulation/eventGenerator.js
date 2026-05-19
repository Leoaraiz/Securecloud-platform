const { v4: uuidv4 } = require('uuid');

// ─── Event type definitions ───────────────────────────────────────────────────
const EVENT_TYPES = [
  {
    type: 'BRUTE_FORCE_LOGIN',
    label: 'Brute Force Login Attack',
    severities: ['HIGH', 'CRITICAL'],
    weight: 0.18,
    sources: ['185.220.101.x', '45.142.212.x', '194.165.16.x', '62.102.148.x'],
    targets: ['admin', 'root', 'sysadmin', 'administrator', 'ubuntu'],
    mitre: 'T1110.001',
  },
  {
    type: 'NETWORK_SCAN',
    label: 'Network Port Scan Detected',
    severities: ['MEDIUM', 'HIGH'],
    weight: 0.14,
    sources: ['10.0.0.x', '192.168.x.x', '172.16.x.x'],
    targets: ['VPC Subnet', 'Internal Network', 'DMZ'],
    mitre: 'T1046',
  },
  {
    type: 'API_ABUSE',
    label: 'API Rate Limit Violation',
    severities: ['MEDIUM', 'HIGH'],
    weight: 0.12,
    sources: ['api-gateway', 'load-balancer', 'edge-proxy'],
    targets: ['/api/v1/auth', '/api/v1/data', '/graphql', '/admin'],
    mitre: 'T1499.002',
  },
  {
    type: 'PRIVILEGE_ESCALATION',
    label: 'Privilege Escalation Attempt',
    severities: ['HIGH', 'CRITICAL'],
    weight: 0.10,
    sources: ['internal-user', 'service-account', 'iam-role'],
    targets: ['admin-role', 'root', 'sudo', 'AdministratorAccess'],
    mitre: 'T1548',
  },
  {
    type: 'MALWARE_DETECTION',
    label: 'Malware Signature Detected',
    severities: ['CRITICAL'],
    weight: 0.07,
    sources: ['endpoint-123', 'workstation-45', 'container-89'],
    targets: ['filesystem', 'memory', 'network-buffer'],
    mitre: 'T1059',
  },
  {
    type: 'DATA_EXFILTRATION',
    label: 'Suspicious Data Exfiltration',
    severities: ['HIGH', 'CRITICAL'],
    weight: 0.08,
    sources: ['s3-bucket', 'database-01', 'file-server'],
    targets: ['external-ip', 'unknown-endpoint', 'tor-exit-node'],
    mitre: 'T1048',
  },
  {
    type: 'CREDENTIAL_STUFFING',
    label: 'Credential Stuffing Attack',
    severities: ['HIGH', 'CRITICAL'],
    weight: 0.10,
    sources: ['botnet-c2', '195.x.x.x', '103.x.x.x'],
    targets: ['login-portal', 'sso-endpoint', 'auth-service'],
    mitre: 'T1110.004',
  },
  {
    type: 'ANOMALOUS_BEHAVIOR',
    label: 'Anomalous User Behavior',
    severities: ['LOW', 'MEDIUM', 'HIGH'],
    weight: 0.11,
    sources: ['user-session', 'iam-user', 'federated-identity'],
    targets: ['sensitive-data', 'admin-panel', 'billing-api'],
    mitre: 'T1078',
  },
  {
    type: 'IAM_POLICY_CHANGE',
    label: 'Critical IAM Policy Modified',
    severities: ['HIGH', 'CRITICAL'],
    weight: 0.06,
    sources: ['root-account', 'admin-user', 'ci-cd-role'],
    targets: ['AdministratorAccess', 'PowerUserAccess', 'iam:*'],
    mitre: 'T1098',
  },
  {
    type: 'ZERO_DAY_ATTEMPT',
    label: 'Zero-Day Exploit Attempt',
    severities: ['CRITICAL'],
    weight: 0.04,
    sources: ['apt-group', 'nation-state-actor', 'sophisticated-threat'],
    targets: ['web-application', 'api-gateway', 'kernel'],
    mitre: 'T1203',
  },
];

const SEVERITY_WEIGHTS = { LOW: 0.20, MEDIUM: 0.35, HIGH: 0.30, CRITICAL: 0.15 };
const GEOLOCATIONS = [
  { country: 'Russia', city: 'Moscow', lat: 55.75, lon: 37.62 },
  { country: 'China', city: 'Beijing', lat: 39.90, lon: 116.41 },
  { country: 'North Korea', city: 'Pyongyang', lat: 39.03, lon: 125.75 },
  { country: 'Iran', city: 'Tehran', lat: 35.69, lon: 51.39 },
  { country: 'USA', city: 'Unknown', lat: 37.09, lon: -95.71 },
  { country: 'Germany', city: 'Frankfurt', lat: 50.11, lon: 8.68 },
  { country: 'Netherlands', city: 'Amsterdam', lat: 52.37, lon: 4.90 },
  { country: 'Brazil', city: 'São Paulo', lat: -23.55, lon: -46.63 },
];

// Weighted random selection
function weightedRandom(items, key = 'weight') {
  const total = items.reduce((s, i) => s + (i[key] || 1), 0);
  let r = Math.random() * total;
  for (const item of items) { r -= (item[key] || 1); if (r <= 0) return item; }
  return items[items.length - 1];
}

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function rand(min, max) { return Math.random() * (max - min) + min; }
function randInt(min, max) { return Math.floor(rand(min, max + 1)); }

// Replace .x placeholders with actual octets
function resolveIp(template) {
  return template.replace(/x/g, () => randInt(1, 254));
}

// ─── Main event generator ────────────────────────────────────────────────────
function generateEvent(overrides = {}) {
  const def = weightedRandom(EVENT_TYPES);
  const severities = def.severities;
  const severity = severities[Math.floor(Math.random() * severities.length)];
  const geo = pick(GEOLOCATIONS);

  const confidenceScore = parseFloat(rand(0.55, 0.99).toFixed(2));
  const riskScore = computeRiskScore(severity, confidenceScore, def.weight);

  const sourceRaw = pick(def.sources);
  const source = sourceRaw.includes('.x') || sourceRaw.includes('x.x')
    ? resolveIp(sourceRaw)
    : sourceRaw;

  return {
    eventId:         uuidv4(),
    type:            def.type,
    label:           def.label,
    severity,
    timestamp:       new Date().toISOString(),
    confidenceScore,
    riskScore,
    source,
    target:          pick(def.targets),
    geo,
    mitre:           def.mitre,
    ttps:            [`${def.mitre}`, `TA00${randInt(1, 11)}`],
    affectedAssets:  randInt(1, 12),
    status:          'ACTIVE',
    ...overrides,
  };
}

// ─── Risk computation ─────────────────────────────────────────────────────────
function computeRiskScore(severity, confidence, typeWeight) {
  const sevMap = { LOW: 0.25, MEDIUM: 0.50, HIGH: 0.75, CRITICAL: 1.0 };
  const behaviorAnomaly = sevMap[severity] * confidence;
  const networkRisk     = typeWeight * 2.5 * confidence;
  const accessRisk      = rand(0.1, 0.9) * sevMap[severity];
  const raw = (behaviorAnomaly * 0.4) + (networkRisk * 0.3) + (accessRisk * 0.3);
  return parseFloat(Math.min(raw, 1).toFixed(3));
}

// ─── Batch generation ────────────────────────────────────────────────────────
function generateBatch(count = 50) {
  return Array.from({ length: count }, () => generateEvent());
}

// ─── Time-based threat burst (simulate attack waves) ─────────────────────────
function generateThreatWave() {
  const waveSize = randInt(3, 8);
  const baseType = pick(EVENT_TYPES);
  return Array.from({ length: waveSize }, () =>
    generateEvent({ type: baseType.type, label: baseType.label, severity: 'CRITICAL' })
  );
}

module.exports = { generateEvent, generateBatch, generateThreatWave, EVENT_TYPES, SEVERITY_WEIGHTS };
