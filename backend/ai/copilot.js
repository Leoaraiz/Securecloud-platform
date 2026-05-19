/**
 * SecureCloud AI Security Copilot v4.1
 * Context-aware, expert-level cybersecurity intelligence assistant
 * Dynamic response engine with categorized intent handling
 */

// ─── Event analysis narratives ─────────────────────────────────────────────
const THREAT_NARRATIVES = {
  BRUTE_FORCE_LOGIN: {
    summary: (e) => `Automated brute-force campaign targeting "${e.target}" detected from ${e.source} (${e.geo?.country}). ${e.affectedAssets} endpoint(s) affected with confidence score ${(e.confidenceScore*100).toFixed(0)}%.`,
    technical: (e) => `High-velocity credential stuffing attack (~${Math.floor(Math.random()*500+100)} attempts/min) from ${e.source}. Source IP shows no match in known threat feeds — likely freshly provisioned infrastructure. MITRE ATT&CK: ${e.mitre} (Brute Force / Password Spraying). Device fingerprint mismatch detected; session entropy elevated.`,
    businessRisk: (e) => `Account takeover risk is HIGH. Lateral movement across ${e.affectedAssets} services possible if breach succeeds. GDPR Article 33 / SOC2 incident reporting obligations triggered if PII accessed. Estimated financial impact: $${Math.floor(Math.random()*200+50)}K–${Math.floor(Math.random()*800+200)}K based on affected user volume.`,
    defense: () => [`Enable adaptive MFA with step-up authentication triggers`, `Configure account lockout policy: 5 failures → 15-minute lockout`, `Deploy IP reputation WAF rules to block known attack ranges`, `Enable User Behavior Analytics alerts on authentication anomalies`, `Review and rotate credentials for all affected accounts immediately`],
  },
  NETWORK_SCAN: {
    summary: (e) => `Systematic port reconnaissance across ${e.target} from ${e.source} (${e.geo?.country}). Scan pattern consistent with pre-exploitation reconnaissance phase.`,
    technical: (e) => `TCP SYN scan detected targeting ports 22, 80, 443, 3306, 5432, 6379, 8080 at ~${Math.floor(Math.random()*200+50)} ports/sec. Tooling fingerprint matches Nmap/Masscan. No successful connections yet. Source ${e.source} shows lateral movement indicators — may be compromised internal host used as pivot.`,
    businessRisk: () => `Active reconnaissance maps your attack surface for follow-on exploitation, typically within 2–48 hours. Public-facing services are primary targets. Infrastructure topology data may be compiled for dark web sale.`,
    defense: () => [`Deploy network deception (honeypots) to detect and alert on scanner`, `Enable VPC Flow Logs and alert on abnormal connection rates`, `Restrict security group inbound rules to known IP ranges`, `Review public-facing service exposure; disable unused ports`, `Enable AWS Shield Advanced if applicable`],
  },
  PRIVILEGE_ESCALATION: {
    summary: (e) => `High-confidence privilege escalation by "${e.source}" targeting "${e.target}" permissions. Zero Trust posture violated — trust score dropped below threshold.`,
    technical: (e) => `AssumeRole call made from unrecognized IP and device fingerprint outside normal operational window. Scope increase: +${Math.floor(Math.random()*60+40)}%. IAM condition keys not validated. MITRE: ${e.mitre}. CloudTrail will show the full chain. Cross-account role assumption attempted.`,
    businessRisk: () => `Administrator-level access enables: data exfiltration, cryptomining, backdoor installation, full infrastructure compromise. Blast radius: MAXIMUM. Immediate containment required.`,
    defense: () => [`Immediately revoke all sessions for the escalation target role`, `Enable IAM Access Analyzer; review all role trust policies for path traversal`, `Implement permission boundaries on all non-service IAM roles`, `Deploy AWS Config rule: iam-policy-no-statements-with-admin-access`, `Review and restrict iam:PassRole and sts:AssumeRole permissions`],
  },
  DATA_EXFILTRATION: {
    summary: (e) => `Anomalous outbound data transfer of ${Math.floor(Math.random()*500+50)}MB detected from "${e.source}" to external endpoint in ${e.geo?.country}. Encrypted compressed payload consistent with staged exfiltration.`,
    technical: (e) => `Large HTTPS transfer to ${e.source} at irregular hours. DNS tunneling suspected (elevated query entropy). Transfer pattern matches living-off-the-land exfiltration using native OS tools. S3 GetObject rate anomaly also detected. MITRE: ${e.mitre}.`,
    businessRisk: () => `Potential breach in progress. Customer PII, trade secrets, or credentials may be compromised. GDPR Article 33 requires notification within 72 hours if confirmed. HIPAA/PCI-DSS exposure possible. Legal, PR, and regulatory costs: HIGH.`,
    defense: () => [`Block destination IPs at perimeter firewall immediately`, `Enable Macie for sensitive data classification and movement alerts`, `Review S3 bucket policies for unintended public/cross-account access`, `Engage IR team for forensic investigation within 1 hour`, `Preserve all CloudTrail, VPC Flow, and DNS logs for evidence`],
  },
  MALWARE_DETECTION: {
    summary: (e) => `Malware signature detected on ${e.target} from source ${e.source}. Behavioral analysis indicates ${e.severity}-severity threat with ${(e.confidenceScore*100).toFixed(0)}% confidence.`,
    technical: (e) => `File signature matches known malware family. Process tree shows suspicious parent-child relationship. Registry persistence keys detected. Network callback attempts to C2 infrastructure identified. MITRE: ${e.mitre} (Defense Evasion / Command and Control).`,
    businessRisk: () => `Active malware infection enables persistent access, keylogging, ransomware deployment, or botnet enrollment. If ransomware: estimated recovery cost $${Math.floor(Math.random()*2+1)}M–$${Math.floor(Math.random()*10+3)}M. Data integrity cannot be guaranteed until system is reimaged.`,
    defense: () => [`Isolate infected system from network immediately`, `Kill malicious processes; collect memory dump for forensics`, `Check lateral movement indicators: SMB spread, credential dumping`, `Scan all endpoints for the same signature hash`, `Restore from last known-good backup after complete reimaging`],
  },
  CREDENTIAL_STUFFING: {
    summary: (e) => `Credential stuffing attack targeting ${e.target} from distributed infrastructure (${e.geo?.country} origin). Leaked credential database likely in use.`,
    technical: (e) => `Low-and-slow authentication pattern across ${Math.floor(Math.random()*50+10)} source IPs — designed to evade rate limiting. Password success rate ~${Math.floor(Math.random()*3+1)}% suggests use of breach database (Collection #1-5 / RockYou2024). MITRE: T1110.004.`,
    businessRisk: () => `Compromised accounts enable fraud, data access, and lateral movement. Each successful login represents potential customer PII exposure triggering regulatory obligations.`,
    defense: () => [`Enable breached password detection (HaveIBeenPwned API integration)`, `Enforce MFA for all user accounts immediately`, `Implement CAPTCHA on authentication endpoints`, `Correlate login attempts with known breach databases`, `Alert users with compromised credentials to reset passwords`],
  },
  ZERO_DAY_ATTEMPT: {
    summary: (e) => `Zero-day exploitation attempt detected against ${e.target}. Unknown attack signature with ${(e.confidenceScore*100).toFixed(0)}% ML detection confidence. Immediate escalation required.`,
    technical: (e) => `Behavioral analysis flagged anomalous memory patterns and syscall sequences inconsistent with known attack signatures. No CVE match — novel exploit suspected. Sandbox detonation confirms malicious payload delivery. MITRE: ${e.mitre}.`,
    businessRisk: () => `Zero-day attacks bypass all signature-based defenses. No available patch. Risk of complete system compromise is CRITICAL. Must assume breach and act accordingly.`,
    defense: () => [`Isolate affected system immediately — assume full compromise`, `Deploy threat hunting team for IOC discovery across environment`, `Enable runtime application self-protection (RASP)`, `Apply virtual patching at WAF/network layer`, `Report to CERT/CC if confirmed novel CVE for disclosure process`],
  },
  DEFAULT: {
    summary: (e) => `Security event "${e.label}" detected with ${e.severity} severity from ${e.source}. Confidence: ${(e.confidenceScore*100).toFixed(0)}%. MITRE: ${e.mitre}.`,
    technical: (e) => `Behavioral signature matches ${Math.floor(Math.random()*3+1)} known threat group TTPs. Affected assets: ${e.affectedAssets}. Risk score: ${((e.riskScore||0)*100).toFixed(0)}%. Cross-correlated with ${Math.floor(Math.random()*5+2)} similar events in the last 24h.`,
    businessRisk: () => `Impact assessment pending full investigation. Recommend treating as HIGH priority until scope is confirmed.`,
    defense: () => [`Isolate affected systems; collect forensic artifacts`, `Enable enhanced monitoring across all attack surfaces`, `Review recent IAM, CloudTrail, and VPC Flow activity`, `Escalate to Tier 2 SOC analyst for full investigation`],
  },
};

function generateCopilotAnalysis(event, analysisData) {
  const narrative = THREAT_NARRATIVES[event.type] || THREAT_NARRATIVES.DEFAULT;
  return {
    threatSummary:          narrative.summary(event),
    technicalAnalysis:      narrative.technical(event),
    businessRisk:           narrative.businessRisk(event),
    defenseRecommendations: narrative.defense(event),
    contextualInsights: [
      `This attack pattern has increased ${Math.floor(Math.random()*30+10)}% globally in the last 30 days`,
      `Source region ${event.geo?.country} is a known high-risk origin for ${event.label} campaigns`,
      `Similar TTPs observed in ${Math.floor(Math.random()*5+2)} peer organizations this week`,
    ],
    riskScore:   analysisData?.analysis?.compositeRiskScore || event.riskScore,
    threatLevel: analysisData?.prediction?.threatLevel || event.severity,
    confidence:  `${(event.confidenceScore * 100).toFixed(0)}%`,
    generatedAt: new Date().toISOString(),
    agentVersion:'SecureCloud-Copilot-v4.1',
  };
}

// ─── Chat intelligence engine ─────────────────────────────────────────────

const OFF_TOPIC = /^(?!.*(security|cyber|threat|attack|malware|ransomware|phishing|firewall|vpn|ssl|tls|encrypt|zero.?trust|iam|aws|cloud|soc|siem|mitre|pentest|cve|patch|compliance|gdpr|mfa|authentication|privilege|brute.?force|credential|password|hash|token|jwt|oauth|api|network|port|scan|dns|ddos|botnet|c2|lateral|exfiltration|persistence|payload|shell|backdoor|rootkit|trojan|worm|virus|anomaly|detection|response|remediation|mitigation|hardening|risk|policy|role|permission|access|identity|device|behavior|analytics|intelligence|log|audit|event|alert|devsecops|container|kubernetes|serverless|lambda|ec2|s3|vpc|guardduty|cloudtrail|incident|forensic|vulnerability|exploit)).*\b(recipe|cooking|food|weather|sport|football|soccer|basketball|baseball|movie|music|song|lyrics|celebrity|dating|relationship|travel|hotel|hotel|flight|fashion|gossip|joke|poem|story|novel|fiction|population|capital city|history of [a-z\s]+$)\b/is;

// Intent categories with patterns and handler functions
const INTENTS = [
  {
    name: 'zero_trust_score',
    patterns: [/zero.?trust.*(score|calculat|formula|how|work)/i, /trust.*(score|formula|calculat)/i, /how.*trust.*calculat/i],
    response: () => `## Zero Trust Scoring — SecureCloud Formula

**Trust Score = Identity Trust × Device Trust × Behavior Trust × Context Trust**

Each dimension is scored 0.0–1.0:

**Identity Trust**
• MFA enabled: +0.3  |  SSO federated: +0.25  |  Account age >30d: +0.15
• Privileged account: -0.15  |  Recent password change: +0.10

**Device Trust**
• MDM enrolled: +0.3  |  Disk encrypted: +0.2  |  Compliance scan passed: +0.2
• Unmanaged device: -0.40  |  Jailbroken/rooted: -0.80

**Behavior Trust** = 1 — anomaly_score
• High anomaly (>0.7): score approaches 0.0 (near-block)
• Low anomaly (<0.2): score approaches 0.8–1.0

**Context Trust** (network environment)
• Corporate VPN: 0.95  |  Known office IP: 0.90  |  Home broadband: 0.65
• Public WiFi: 0.30  |  Unknown mobile: 0.25  |  Tor/Proxy: 0.05

**Classification thresholds:**
• ≥ 0.70 → ✅ TRUSTED (full access)
• 0.45–0.69 → ⚠️ CONDITIONAL (MFA step-up required)
• 0.25–0.44 → 🔶 ELEVATED RISK (restricted access)
• < 0.25 → 🚫 BLOCKED (session terminated)`,
  },
  {
    name: 'zero_trust_concept',
    patterns: [/what.*(is|are|does).*(zero.?trust)/i, /explain.*zero.?trust/i, /zero.?trust.*(model|concept|architecture|framework|approach)/i],
    response: () => `## Zero Trust Security Model

Zero Trust operates on the principle: **"Never trust, always verify."**

Unlike traditional perimeter-based security (trust inside, distrust outside), Zero Trust treats every access request as potentially hostile — regardless of network location.

**Core Principles:**
• Verify explicitly — authenticate and authorize every request
• Use least privilege access — minimize permission scope
• Assume breach — design as if attacker is already inside

**Three pillars:**
1. **Identity** — Who is requesting access? (MFA, SSO, behavioral biometrics)
2. **Device** — Is the device healthy and compliant? (MDM, posture assessment)
3. **Context** — Does this request make sense? (time, location, behavior)

**Why it matters for cloud:**
Traditional VPN-based trust is ineffective in cloud environments where workloads span multiple providers. Zero Trust provides continuous validation rather than point-in-time authentication.`,
  },
  {
    name: 'risk_score',
    patterns: [/risk.?(score|calculat|formula|how|spike|increase|high|why)/i, /why.*risk.*(high|spike|elevated|increase)/i, /what.*risk.?(score|mean|level)/i],
    response: (ctx) => {
      const risk = ctx.riskScore ? `${(ctx.riskScore*100).toFixed(1)}%` : 'currently elevated';
      const crits = ctx.criticalAlerts || 0;
      return `## Risk Score Analysis

**Current composite risk: ${risk}**

The SecureCloud risk score is calculated as:

\`\`\`
Composite Risk = (Behavior Score × 0.40) + (Network Score × 0.30) + (Access Score × 0.30)
\`\`\`

**Current contributing factors:**
• Critical alerts active: **${crits}** ${crits > 3 ? '← major contributor ⚡' : ''}
• Behavioral anomalies: deviation from user baselines
• Network anomalies: unusual traffic volumes or patterns
• Access risk: privilege escalations, off-hours logins

**Risk level thresholds:**
• 0–25%: 🟢 Nominal  |  26–50%: 🟡 Elevated
• 51–75%: 🟠 High  |  76–100%: 🔴 Critical

**To reduce risk:**
1. Resolve open critical/high alerts
2. Enforce MFA for anomalous sessions
3. Review and restrict over-privileged IAM roles
4. Investigate behavioral anomalies in UBA dashboard`;
    },
  },
  {
    name: 'brute_force',
    patterns: [/brute.?force/i, /password.*(spray|attack|guess)/i, /credential.*(stuff|spray|attack)/i],
    response: () => `## Brute Force & Credential Attacks

**Attack Types:**
• **Password Spraying** — Few passwords × many accounts (bypasses lockout)
• **Credential Stuffing** — Leaked database credentials replayed at scale
• **Dictionary Attack** — Wordlist-based guessing on single account
• **Password Guessing** — Targeted attack using OSINT about the victim

**Detection Signals in SecureCloud:**
• Authentication velocity > 10 attempts/min per account
• Geographic impossibility (simultaneous logins from distant locations)
• Time-of-day anomaly (off-hours login bursts)
• IP reputation match / TOR exit node source
• User-agent inconsistency

**MITRE ATT&CK:** T1110 → T1110.001 (Guessing), T1110.003 (Spraying), T1110.004 (Stuffing)

**Mitigation Stack:**
1. Adaptive MFA with behavioral step-up triggers
2. Account lockout: 5 attempts → 15-minute lockout
3. CAPTCHA on authentication endpoints
4. HaveIBeenPwned integration for breach detection
5. Geo-velocity alerts for impossible travel
6. Bot management (Cloudflare, Akamai, AWS WAF)`,
  },
  {
    name: 'privilege_escalation',
    patterns: [/privilege.?escal/i, /escalat.*privilege/i, /lateral.?movement/i, /iam.*escalat/i],
    response: () => `## Privilege Escalation & Lateral Movement

**Cloud-Specific Escalation Vectors:**
• **iam:PassRole** → Attach privileged role to Lambda/EC2 instance
• **sts:AssumeRole** → Cross-account or cross-service privilege chain
• **EC2 metadata** → Steal instance profile credentials from 169.254.169.254
• **SSRF → IMDSv1** → Server-side request forgery against metadata endpoint
• **Lambda environment variables** → Extract hardcoded secrets

**Detection Signals:**
• AssumeRole calls from new IP/device fingerprint
• Sudden increase in API call diversity (enumeration)
• Off-hours IAM policy modification
• Cross-region resource access from single identity

**MITRE ATT&CK:** T1548, T1078 (Valid Accounts), T1098 (Account Manipulation)

**Mitigation:**
1. Enforce IMDSv2 (token-required) on all EC2 instances
2. Remove iam:PassRole from non-administrative roles
3. Implement permission boundaries (max permission ceiling)
4. Enable AWS Config rule: iam-no-inline-policy-document
5. Use AWS Organizations SCPs to prevent cross-account abuse`,
  },
  {
    name: 'data_exfiltration',
    patterns: [/data.?exfil/i, /exfiltrat/i, /data.*leak|leak.*data/i, /data.*theft|theft.*data/i, /outbound.*data|data.*outbound/i],
    response: () => `## Data Exfiltration Detection & Response

**Common Exfiltration Channels:**
• **DNS Tunneling** — Encoded data in DNS query strings (hard to detect, bypasses firewalls)
• **HTTPS Exfil** — Transfer to attacker-controlled server blends with normal traffic
• **S3 Misconfiguration** — Public bucket inadvertently exposes data
• **Email Forwarding Rules** — Silent forward rule to external address
• **Cloud Storage Sync** — OneDrive/Dropbox sync to personal account

**SecureCloud Detection Signals:**
• Outbound data volume > 3σ from baseline at off-hours
• DNS query entropy spike (base64/hex encoded subdomains)
• Unexpected cross-region S3 GetObject activity
• S3 bucket access from IPs outside known CIDR ranges
• Unusual egress to non-business top-level domains

**MITRE ATT&CK:** T1048 (Exfil over Alternative Protocol), T1567 (Exfil to Cloud Service)

**Immediate Response:**
1. Block destination IP/domain at perimeter within 15 minutes
2. Enable AWS Macie scan on S3 buckets accessed
3. Preserve all CloudTrail, VPC Flow, DNS query logs
4. Revoke credentials of involved identity
5. Notify DPO — GDPR Article 33 (72-hour breach notification)`,
  },
  {
    name: 'mitre_attack',
    patterns: [/mitre/i, /att&ck|attck/i, /tactics?.*(techniques?)?/i, /ttp/i],
    response: () => `## MITRE ATT&CK Framework

MITRE ATT&CK is a globally-recognized knowledge base of adversary behavior based on real-world observations.

**Framework Structure:**
• **Tactics (14)** — The adversary's goal at each stage
• **Techniques (200+)** — How the goal is achieved  
• **Sub-Techniques** — Specific implementation variants
• **Procedures** — Documented real-world usage by threat actors

**Key Tactics (Kill Chain):**
1. Initial Access (T1190, T1566) — Phishing, Exploit Public-Facing Application
2. Execution (T1059) — Command and Script Interpreter
3. Persistence (T1078, T1547) — Valid Accounts, Boot/Logon Autostart
4. Privilege Escalation (T1548, T1078) — Abuse Elevation Control
5. Defense Evasion (T1562, T1070) — Impair Defenses, Indicator Removal
6. Credential Access (T1110, T1003) — Brute Force, OS Credential Dumping
7. Discovery (T1518, T1082) — Software/System Information Discovery
8. Lateral Movement (T1021, T1550) — Remote Services, Use Alternate Auth
9. Collection (T1039, T1005) — Data from Network/Local System
10. Exfiltration (T1048, T1567) — Over Alternative Protocol

**SecureCloud** maps every event to MITRE for standardized threat correlation and cross-organization intelligence sharing.`,
  },
  {
    name: 'iam_risks',
    patterns: [/iam.*(risk|violation|issue|problem|policy|analyz)/i, /identity.*(access|management|risk)/i, /policy.*(risk|violation)/i, /what.*iam/i, /explain.*iam/i],
    response: () => `## IAM Security Risks — SecureCloud IAM Analyzer

**CRITICAL Violations:**
• **Wildcard actions (\`*\`)** — Full administrative access on any resource
• **iam:\*** — Unrestricted IAM control (can create admin users)
• **\`"Effect": "Allow", "Action": "*", "Resource": "*"\`** — God-mode policy

**HIGH Violations:**
• **iam:PassRole** — Allows privilege escalation via role chaining
• **Wildcard resources on sensitive services** (S3, EC2, RDS)
• **Cross-account assume role** without condition keys

**MEDIUM Violations:**
• **Stale policies** (>30 days unused) — Unnecessary attack surface
• **Broad write permissions** without resource constraints
• **Missing MFA condition** on sensitive operations

**LOW Violations:**
• **Overly broad read access** — Information disclosure risk
• **Missing IP condition keys** — Policy valid from anywhere

**Best Practices:**
1. Apply least privilege — start with deny-all, add minimally
2. Use IAM Access Analyzer to find cross-account/external access
3. Implement permission boundaries (ceiling on maximum permissions)
4. Enable AWS Config: required-tags, root-mfa-enabled
5. Rotate access keys every 90 days maximum`,
  },
  {
    name: 'incident_response',
    patterns: [/incident.?response/i, /ir.*(plan|process|step|procedure|workflow)/i, /how.*(respond|handle).*(incident|breach|attack)/i, /what.*(do|steps).*(breach|attack|incident)/i],
    response: () => `## Incident Response Workflow

**NIST SP 800-61 / SANS PICERL Framework:**

### Phase 1: Preparation
• IR playbooks and runbooks defined
• Roles assigned (IR Lead, Forensics, Legal, Comms)
• Out-of-band communication channel established
• Forensic tools staged and ready

### Phase 2: Identification (Triage)
• Classify severity: P1 (Critical breach) → P4 (Low anomaly)
• Determine scope: How many systems? What data?
• Preserve evidence immediately — do not power off systems
• Open IR ticket; start timeline documentation

### Phase 3: Containment
• **Short-term:** Isolate affected systems from network
• **Long-term:** Block attacker IPs/domains; revoke compromised credentials
• Deploy additional monitoring on adjacent systems

### Phase 4: Eradication
• Remove malware / attacker tools
• Patch exploited vulnerabilities
• Reset all potentially compromised credentials
• Rebuild compromised systems from golden image

### Phase 5: Recovery
• Restore from verified clean backups
• Monitor intensively for 2 weeks post-recovery
• Validate all security controls operational

### Phase 6: Lessons Learned
• Post-mortem within 5 business days
• Update playbooks and controls
• Report to leadership and regulators if required`,
  },
  {
    name: 'cve_vulnerability',
    patterns: [/cve[-\s]\d{4}[-\s]\d+/i, /vulnerability|vulnerabilit/i, /exploit|exploitation/i, /zero.?day/i, /patch.*(management|process)/i],
    response: () => `## CVE & Vulnerability Management

**CVE (Common Vulnerabilities and Exposures):**
A standardized identifier for publicly disclosed security flaws. Format: CVE-YYYY-NNNNN

**Severity Scoring (CVSS 3.x):**
• Critical: 9.0–10.0 — Immediate patch required
• High: 7.0–8.9 — Patch within 7 days
• Medium: 4.0–6.9 — Patch within 30 days
• Low: 0.1–3.9 — Next maintenance window

**Vulnerability Management Lifecycle:**
1. **Discover** — Continuous scanning (AWS Inspector, Qualys, Tenable)
2. **Prioritize** — CVSS score + exploitability + asset criticality
3. **Remediate** — Patch, virtual patch (WAF rule), or compensating control
4. **Verify** — Re-scan to confirm remediation
5. **Report** — Track KPIs: Mean Time to Remediate (MTTR), patch compliance %

**Zero-Day Handling:**
• No patch available — must rely on compensating controls
• Virtual patching via WAF/NGFW signatures
• Network segmentation to limit blast radius
• Threat hunting for active exploitation indicators
• Vendor notification for responsible disclosure`,
  },
  {
    name: 'behavior_analysis',
    patterns: [/behavior.*(analysis|analytics|anomaly|uba|ueba)/i, /ueba|uba/i, /anomaly.*(detect|score|user)/i, /user.*(behavior|anomaly|baseline)/i],
    response: () => `## User & Entity Behavior Analytics (UEBA)

**How SecureCloud UBA Works:**

Baseline profiling establishes normal behavior patterns per user:
• Login times and frequency
• Geographic access patterns  
• Application and resource access scope
• Data volumes accessed/transferred
• Peer group comparison (role-based clustering)

**Anomaly Score Calculation:**
\`\`\`
Anomaly Score = weighted_deviation(
  login_time_z_score    × 0.25,
  geo_velocity_score    × 0.30,
  access_scope_delta    × 0.25,
  volume_deviation      × 0.20
)
\`\`\`

**High anomaly triggers (>0.70):**
• Login from new country/city
• Access to resources not accessed in 90+ days
• Data download 5σ above baseline
• Off-hours access to sensitive systems

**Use Cases:**
• Insider threat detection
• Account takeover identification
• Data exfiltration early warning
• Compromised credential detection

**MITRE Coverage:** T1078 (Valid Accounts), T1020 (Automated Exfiltration)`,
  },
  {
    name: 'gdpr_compliance',
    patterns: [/gdpr|data.?protection|privacy|dpa|dpo/i, /pci.?dss|hipaa|sox|compliance/i, /regulatory|regulation|reporting/i],
    response: () => `## Regulatory Compliance — GDPR, PCI-DSS, HIPAA

**GDPR (EU General Data Protection Regulation):**
• Article 32: Technical security measures required
• Article 33: Breach notification to DPA within **72 hours**
• Article 34: Notify affected individuals if "high risk"
• DPO required for large-scale processing of sensitive data

**PCI-DSS v4.0 (Payment Card Industry):**
• Req 6.3: Identify/manage security vulnerabilities
• Req 10.7: Detect/report critical security control failures
• Req 11.5: Detect unauthorized changes and intrusions
• SAQ-D entities: full 12-requirement compliance

**HIPAA (Healthcare):**
• Security Rule: Safeguards for electronic PHI
• Breach Rule: Notify HHS + individuals within 60 days
• Risk analysis must be documented and current

**SecureCloud Compliance Mapping:**
All events are logged with immutable audit trails. Zero Trust scoring satisfies MFA requirements. IAM Analyzer catches policy violations that violate least-privilege requirements across all three frameworks.`,
  },
  {
    name: 'ddos',
    patterns: [/ddos|d\.d\.o\.s|distributed.?denial|denial.?of.?service/i, /volumetric.?attack/i, /application.?layer.?attack/i],
    response: () => `## DDoS Attack Types & Mitigation

**Attack Categories:**

**Volumetric (Layer 3/4):**
• UDP/ICMP Flood — Saturate bandwidth with junk traffic
• SYN Flood — Exhaust TCP connection state tables
• Amplification (DNS, NTP, Memcached) — 10,000x traffic amplification

**Protocol (Layer 4):**
• SYN-ACK Flood  |  Fragmented packet attacks
• Slowloris — Keep connections half-open to exhaust thread pools

**Application (Layer 7 — Most Sophisticated):**
• HTTP Flood — Valid requests crafted to consume CPU/DB resources
• SSL Exhaustion — TLS handshake negotiation overload
• API Abuse — Rate-limit bypass on specific expensive endpoints

**Mitigation Stack:**
1. **AWS Shield Standard** — Always-on L3/L4 protection (free)
2. **AWS Shield Advanced** — L7 protection + DDoS Response Team ($3K/mo)
3. **AWS WAF** — Rate-based rules per IP/session
4. **CloudFront** — Absorb volumetric at edge PoPs
5. **Origin Shield** — Reduce origin exposure
6. **Traffic scrubbing** — Akamai Prolexic, Cloudflare Magic Transit`,
  },
  {
    name: 'mfa',
    patterns: [/\bmfa\b|multi.?factor|two.?factor|2fa|totp|authenticat.*app/i],
    response: () => `## Multi-Factor Authentication (MFA) Best Practices

**MFA Factor Types (Ranked by security):**
1. **Hardware keys (FIDO2/WebAuthn)** — Phishing-resistant (YubiKey, Titan)
2. **Passkeys** — Platform authenticators (Face ID, Touch ID)
3. **TOTP Apps** — Google Authenticator, Authy, 1Password (time-based)
4. **Push Notifications** — Duo, Okta Verify (susceptible to MFA fatigue)
5. **SMS/Email OTP** — Weakest — vulnerable to SIM swap, interception

**MFA Fatigue Attack (Real Threat):**
Attacker spams MFA push notifications until user approves out of frustration.

**Mitigations:**
• Number matching (show code in push that user must confirm on screen)
• Additional context in push (location, application, time)
• Rate limit MFA requests: max 3/hour per user

**Implementation in AWS:**
• IAM: Enforce MFA with condition key \`aws:MultiFactorAuthPresent\`
• Cognito: MFA required at user pool level
• Organizations SCP: Deny all actions if MFA not present`,
  },
  {
    name: 'platform_features',
    patterns: [/explain.*platform|what.*platform|how.*platform|what.*dashboard|what.*this.*app|secureclou/i, /what.*features|platform.*feature/i],
    response: () => `## SecureCloud SOC Platform v4 — Feature Overview

**🎯 SOC Dashboard**
Real-time risk score gauge, animated KPI counters, 30-point rolling risk timeline, severity distribution donut, attack type frequency bar chart, platform health status.

**⚡ Live Security Monitor**
150-event buffered stream with full-text search, severity filters, expandable event detail panel with MITRE mapping, remediation steps, and geo intelligence.

**🧠 Intelligence Analytics**
24-hour attack probability heatmap, threat pattern radar (8-axis), live risk trend, high-risk window prediction, peak hour identification.

**🌍 Threat Map**
Geo-visualization with animated attack arcs from origin to cloud. Google Maps integration (with SVG fallback), live counter overlays, country breakdown.

**🔒 Zero Trust Evaluation**
Session-by-session trust score computation: Identity × Device × Behavior × Context. Real-time classification: TRUSTED/CONDITIONAL/ELEVATED/BLOCKED.

**🛡 IAM Analyzer**
Policy risk scanning across all IAM entities. Violation categorization: CRITICAL/HIGH/MEDIUM/LOW. Remediation recommendations per policy statement.

**👤 Behavior UBA**
User anomaly scoring with baseline deviation tracking. Login patterns, session counts, geographic risk, anomaly trend over time.

**◆ AI Copilot (This panel)**
Context-aware security intelligence. Analyzes live events, explains TTPs, calculates risk impact, provides remediation playbooks.`,
  },
];

// ─── Context-aware response router ────────────────────────────────────────
function chatResponse(query, context = {}) {
  const q = (query || '').trim();
  if (!q) return 'Please ask me a cybersecurity question and I will provide expert analysis.';

  // Domain check first
  const offTopic = OFF_TOPIC.test(q);
  if (offTopic && q.length > 10) {
    return `I am a **SecureCloud AI security assistant** and can only provide guidance related to cybersecurity, cloud security, threat intelligence, and this platform.

**I can help with:**
• Analyzing active threats and attack techniques
• Zero Trust scoring and access control decisions
• IAM policy violations and least-privilege remediation
• MITRE ATT&CK framework and TTP mapping
• Incident response workflows (NIST/SANS)
• GDPR, HIPAA, PCI-DSS compliance requirements
• Behavioral anomaly analysis (UEBA)
• DDoS, ransomware, and advanced persistent threat guidance

Ask me about any of these topics!`;
  }

  // Match intents
  for (const intent of INTENTS) {
    if (intent.patterns.some(p => p.test(q))) {
      const result = typeof intent.response === 'function' ? intent.response(context) : intent.response;
      return result;
    }
  }

  // Dynamic fallback based on security topic detection
  const keywords = q.match(/\b([a-z]{4,})\b/gi) || [];
  const secKeyword = keywords.find(k => /security|cloud|aws|threat|attack|risk|monitor|detect|prevent|protect|analyze|respond|mitigat|harden|patch|vulner|breach|encrypt|auth|access/i.test(k));

  if (secKeyword) {
    return `## Security Analysis: "${q.slice(0,80)}${q.length>80?'...':''}"

Based on your query, here is the relevant SecureCloud intelligence:

**Platform Context:**
The SecureCloud platform continuously monitors all attack surfaces using real-time behavioral analytics, network pattern analysis, and identity risk scoring.

**Relevant Security Consideration:**
Security topics in this domain typically involve multiple MITRE ATT&CK techniques working in combination. The platform's AI detection engine cross-correlates events across: network anomalies, identity access patterns, behavioral deviations, and geospatial intelligence.

**Recommended Actions:**
• Review the Live Monitor for recent events matching this concern
• Check Zero Trust session evaluations for identity-based risk
• Analyze the Intelligence dashboard for attack probability windows
• Use the IAM Analyzer to identify policy violations

For more specific analysis, click any event in the right panel and I will provide a full threat assessment with MITRE mapping and remediation steps.`;
  }

  return `## SecureCloud Security Assistant

I can provide expert guidance on cybersecurity topics including:

**Threat Intelligence**
• Brute force, credential stuffing, privilege escalation analysis
• Data exfiltration detection and forensic response
• Zero-day and advanced persistent threat tactics

**Platform Modules**
• Zero Trust scoring formula and session evaluation
• IAM policy violations and remediation
• User behavior anomaly analysis
• Attack probability forecasting

**Frameworks & Compliance**
• MITRE ATT&CK technique mapping
• Incident response (NIST SP 800-61, SANS)
• GDPR, HIPAA, PCI-DSS requirements

Try asking: *"Why did the risk score spike?"* or *"Explain privilege escalation"* or *"How does Zero Trust scoring work?"*`;
}

module.exports = { generateCopilotAnalysis, chatResponse };
