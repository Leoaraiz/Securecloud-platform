/**
 * IAM Policy Security Analyzer (simulated)
 */

const SIMULATED_POLICIES = [
  {
    id: 'pol-001',
    name: 'DeveloperFullAccess',
    entity: 'dev-team-role',
    entityType: 'Role',
    statements: [
      { effect: 'Allow', actions: ['s3:*', 'ec2:*', 'rds:*'], resources: ['*'] },
      { effect: 'Allow', actions: ['iam:PassRole'], resources: ['*'] },
    ],
    lastUsed: '2024-01-15',
    unusedDays: 45,
  },
  {
    id: 'pol-002',
    name: 'CIBuildRole',
    entity: 'github-actions-role',
    entityType: 'Role',
    statements: [
      { effect: 'Allow', actions: ['ecr:*', 's3:PutObject', 's3:GetObject'], resources: ['*'] },
      { effect: 'Allow', actions: ['iam:CreateRole', 'iam:AttachRolePolicy'], resources: ['*'] },
    ],
    lastUsed: '2024-01-20',
    unusedDays: 0,
  },
  {
    id: 'pol-003',
    name: 'ReadOnlyAnalyst',
    entity: 'analyst-user-group',
    entityType: 'Group',
    statements: [
      { effect: 'Allow', actions: ['cloudwatch:Get*', 'cloudwatch:List*', 'cloudtrail:Lookup*'], resources: ['*'] },
    ],
    lastUsed: '2024-01-22',
    unusedDays: 0,
  },
  {
    id: 'pol-004',
    name: 'LambdaExecutionRole',
    entity: 'lambda-processor-role',
    entityType: 'Role',
    statements: [
      { effect: 'Allow', actions: ['logs:*', 'dynamodb:*', 's3:*', 'sqs:*', 'sns:*', 'ec2:*', 'iam:*'], resources: ['*'] },
    ],
    lastUsed: '2024-01-10',
    unusedDays: 12,
  },
  {
    id: 'pol-005',
    name: 'DataScienceNotebook',
    entity: 'data-science-user',
    entityType: 'User',
    statements: [
      { effect: 'Allow', actions: ['s3:GetObject', 's3:PutObject', 'athena:*', 'glue:*'], resources: ['*'] },
    ],
    lastUsed: '2024-01-21',
    unusedDays: 1,
  },
  {
    id: 'pol-006',
    name: 'OldAdminAccess',
    entity: 'ex-contractor-user',
    entityType: 'User',
    statements: [
      { effect: 'Allow', actions: ['*'], resources: ['*'] },
    ],
    lastUsed: '2023-11-30',
    unusedDays: 53,
  },
];

const RISKY_ACTIONS = ['iam:*', '*', 'iam:PassRole', 'iam:CreateRole', 'iam:AttachRolePolicy', 'sts:AssumeRole'];
const WRITE_ACTIONS_PATTERN = /:(Put|Create|Delete|Update|Modify|Attach|Detach|Write|.*\*)/;

function analyzePolicy(policy) {
  const violations = [];
  let riskScore = 0;

  policy.statements.forEach(stmt => {
    if (stmt.effect !== 'Allow') return;

    stmt.actions.forEach(action => {
      // Wildcard / full admin
      if (action === '*' || action === 'iam:*') {
        violations.push({ severity: 'CRITICAL', type: 'FULL_ADMIN', description: `Action "${action}" grants full administrative access`, action });
        riskScore += 0.4;
      }
      // Dangerous IAM actions
      else if (RISKY_ACTIONS.includes(action)) {
        violations.push({ severity: 'HIGH', type: 'DANGEROUS_IAM', description: `Action "${action}" can be used for privilege escalation`, action });
        riskScore += 0.25;
      }
      // Broad write
      else if (WRITE_ACTIONS_PATTERN.test(action)) {
        violations.push({ severity: 'MEDIUM', type: 'BROAD_WRITE', description: `Write action "${action}" on "*" resource`, action });
        riskScore += 0.10;
      }
    });

    // Wildcard resource
    if (stmt.resources.includes('*') && stmt.actions.length > 2) {
      violations.push({ severity: 'HIGH', type: 'WILDCARD_RESOURCE', description: 'Policy applies to all resources (*) — should be scoped', action: 'resource:*' });
      riskScore += 0.15;
    }
  });

  // Unused policy
  if (policy.unusedDays > 30) {
    violations.push({ severity: 'MEDIUM', type: 'STALE_POLICY', description: `Policy unused for ${policy.unusedDays} days — review for removal`, action: 'N/A' });
    riskScore += 0.10;
  }

  const normalizedRisk = Math.min(riskScore, 1);
  const riskLevel = normalizedRisk > 0.6 ? 'CRITICAL' : normalizedRisk > 0.4 ? 'HIGH' : normalizedRisk > 0.2 ? 'MEDIUM' : 'LOW';

  return {
    ...policy,
    violations: violations.slice(0, 6), // cap
    riskScore: parseFloat(normalizedRisk.toFixed(3)),
    riskLevel,
    violationCount: violations.length,
    recommendation: riskLevel === 'CRITICAL'
      ? 'Immediately revoke or replace with scoped permissions'
      : riskLevel === 'HIGH'
      ? 'Review and apply principle of least privilege'
      : riskLevel === 'MEDIUM'
      ? 'Schedule policy audit within 2 weeks'
      : 'Policy looks reasonable — continue monitoring',
    analyzedAt: new Date().toISOString(),
  };
}

function analyzeAllPolicies() {
  const results = SIMULATED_POLICIES.map(analyzePolicy);
  const summary = {
    total:    results.length,
    critical: results.filter(r => r.riskLevel === 'CRITICAL').length,
    high:     results.filter(r => r.riskLevel === 'HIGH').length,
    medium:   results.filter(r => r.riskLevel === 'MEDIUM').length,
    low:      results.filter(r => r.riskLevel === 'LOW').length,
    avgRisk:  parseFloat((results.reduce((s, r) => s + r.riskScore, 0) / results.length).toFixed(3)),
    topViolations: results.flatMap(r => r.violations).filter(v => v.severity === 'CRITICAL').slice(0, 5),
  };
  return { policies: results, summary };
}

module.exports = { analyzeAllPolicies, analyzePolicy };
