/**
 * AI Threat Detection Simulation Engine
 * Uses statistical probability models — NOT real ML
 */

const THREAT_CATEGORIES = {
  BRUTE_FORCE_LOGIN:    { networkRisk: 0.8, accessRisk: 0.7, name: 'Authentication Attack' },
  NETWORK_SCAN:         { networkRisk: 0.9, accessRisk: 0.2, name: 'Reconnaissance' },
  API_ABUSE:            { networkRisk: 0.6, accessRisk: 0.5, name: 'API Layer Attack' },
  PRIVILEGE_ESCALATION: { networkRisk: 0.3, accessRisk: 0.95, name: 'Privilege Escalation' },
  MALWARE_DETECTION:    { networkRisk: 0.7, accessRisk: 0.6, name: 'Malware Execution' },
  DATA_EXFILTRATION:    { networkRisk: 0.85, accessRisk: 0.7, name: 'Data Theft' },
  CREDENTIAL_STUFFING:  { networkRisk: 0.75, accessRisk: 0.8, name: 'Credential Attack' },
  ANOMALOUS_BEHAVIOR:   { networkRisk: 0.4, accessRisk: 0.6, name: 'Insider Threat' },
  IAM_POLICY_CHANGE:    { networkRisk: 0.2, accessRisk: 0.9, name: 'Access Control Attack' },
  ZERO_DAY_ATTEMPT:     { networkRisk: 0.95, accessRisk: 0.9, name: 'Advanced Exploit' },
};

const DEFENSE_ACTIONS = {
  CRITICAL: [
    'Immediately block source IP at perimeter firewall',
    'Isolate affected EC2 instances from VPC',
    'Revoke all active IAM sessions for affected user',
    'Enable AWS Shield Advanced DDoS protection',
    'Trigger IR playbook: P1-CRITICAL',
    'Page on-call security engineer immediately',
  ],
  HIGH: [
    'Block source IP in Security Group rules',
    'Enable enhanced CloudTrail monitoring',
    'Force MFA re-authentication for affected accounts',
    'Increase WAF sensitivity for affected endpoints',
    'Alert SOC Tier 2 analyst',
    'Capture network flow logs for forensics',
  ],
  MEDIUM: [
    'Add IP to watchlist for 24h monitoring',
    'Increase authentication log verbosity',
    'Review and tighten related IAM policies',
    'Send alert digest to security team',
  ],
  LOW: [
    'Log and monitor for pattern escalation',
    'Add to threat intelligence database',
    'Review in next security standup',
  ],
};

const MITRE_TACTICS = {
  BRUTE_FORCE_LOGIN:    'Initial Access → Credential Access',
  NETWORK_SCAN:         'Reconnaissance → Discovery',
  API_ABUSE:            'Initial Access → Impact',
  PRIVILEGE_ESCALATION: 'Privilege Escalation → Defense Evasion',
  MALWARE_DETECTION:    'Execution → Persistence',
  DATA_EXFILTRATION:    'Exfiltration → Collection',
  CREDENTIAL_STUFFING:  'Initial Access → Credential Access',
  ANOMALOUS_BEHAVIOR:   'Lateral Movement → Collection',
  IAM_POLICY_CHANGE:    'Persistence → Privilege Escalation',
  ZERO_DAY_ATTEMPT:     'Initial Access → Execution',
};

function analyzeEvent(event) {
  const category = THREAT_CATEGORIES[event.type] || { networkRisk: 0.5, accessRisk: 0.5, name: 'Unknown' };

  // Behavior anomaly from confidence and severity
  const sevMap = { LOW: 0.25, MEDIUM: 0.5, HIGH: 0.75, CRITICAL: 1.0 };
  const behaviorAnomaly = (sevMap[event.severity] || 0.5) * event.confidenceScore;

  // Slight jitter for realism
  const jitter = () => (Math.random() - 0.5) * 0.1;
  const networkRisk = Math.min(Math.max(category.networkRisk + jitter(), 0), 1);
  const accessRisk  = Math.min(Math.max(category.accessRisk + jitter(), 0), 1);

  // Risk formula: (Behavior × 0.4) + (Network × 0.3) + (Access × 0.3)
  const riskScore = parseFloat(
    ((behaviorAnomaly * 0.4) + (networkRisk * 0.3) + (accessRisk * 0.3)).toFixed(3)
  );

  const threatLevel = riskScore > 0.75 ? 'CRITICAL' : riskScore > 0.55 ? 'HIGH' : riskScore > 0.35 ? 'MEDIUM' : 'LOW';
  const defenseActions = DEFENSE_ACTIONS[threatLevel] || DEFENSE_ACTIONS.LOW;

  // Attack probability prediction (next 24h)
  const attackProbability = parseFloat(Math.min(riskScore * 1.2 + Math.random() * 0.1, 1).toFixed(2));

  // Time prediction
  const hoursToNextAttack = parseFloat((1 / attackProbability * (2 + Math.random() * 4)).toFixed(1));

  return {
    analysis: {
      behaviorAnomaly: parseFloat(behaviorAnomaly.toFixed(3)),
      networkRisk:     parseFloat(networkRisk.toFixed(3)),
      accessPatternRisk: parseFloat(accessRisk.toFixed(3)),
      compositeRiskScore: riskScore,
    },
    prediction: {
      threatLevel,
      threatCategory: category.name,
      mitreTactic: MITRE_TACTICS[event.type] || 'Unknown',
      attackProbability,
      estimatedTimeToNextAttack: `${hoursToNextAttack}h`,
      confidence: event.confidenceScore,
    },
    recommendedActions: defenseActions.slice(0, 3),
    allActions: defenseActions,
    modelVersion: 'SecureCloud-ThreatModel-v2.1',
    analyzedAt: new Date().toISOString(),
  };
}

// Aggregate risk across multiple events
function aggregateRisk(events) {
  if (!events.length) return { overallRisk: 0, level: 'SAFE' };
  const avgRisk = events.reduce((s, e) => s + (e.riskScore || 0), 0) / events.length;
  const maxSev = events.some(e => e.severity === 'CRITICAL') ? 'CRITICAL'
               : events.some(e => e.severity === 'HIGH')     ? 'HIGH'
               : events.some(e => e.severity === 'MEDIUM')   ? 'MEDIUM' : 'LOW';
  return {
    overallRisk: parseFloat(avgRisk.toFixed(3)),
    level: avgRisk > 0.7 ? 'CRITICAL' : avgRisk > 0.5 ? 'HIGH' : avgRisk > 0.3 ? 'MEDIUM' : 'LOW',
    maxSeverity: maxSev,
    eventCount: events.length,
    criticalCount: events.filter(e => e.severity === 'CRITICAL').length,
    highCount:     events.filter(e => e.severity === 'HIGH').length,
  };
}

module.exports = { analyzeEvent, aggregateRisk, THREAT_CATEGORIES };
