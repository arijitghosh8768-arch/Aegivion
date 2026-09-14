import type { Alert, ThreatChainEdge, ThreatChainNode } from "@/lib/types";

export const ALERTS: Alert[] = [
  {
    id: "al-501",
    title: "IAM access keys exposed in public GitHub repository",
    description:
      "Aegivion detected live AWS access keys committed to acme/platform-config on GitHub. The keys belong to 'ci-deploy-role' which holds AdministratorAccess.",
    severity: "critical",
    status: "investigating",
    tactic: "Initial Access",
    technique: "Valid Accounts",
    techniqueId: "T1078.004",
    source: "github.com/acme/platform-config",
    target: "ci-deploy-role (AWS prod-9823)",
    account: "prod-9823",
    confidence: 97,
    timestamp: "2026-08-04T05:41:00Z",
    evidence: [
      "Secret scanner (GitHub) matched pattern AKIA[0-9A-Z]{16}",
      "Key last used 11 minutes ago from IP 185.220.101.4 (TOR exit)",
      "CloudTrail: AssumeRoleWithWebIdentity via GitHub OIDC, then ec2:DescribeInstances burst",
    ],
    affectedAssets: ["ci-deploy-role", "web-prod-1"],
  },
  {
    id: "al-502",
    title: "Anomalous S3 bulk download — 42 GB from 'prod-customer-data'",
    description:
      "A single credential downloaded 42 GB across 18,400 objects in 22 minutes, consistent with data staging for exfiltration.",
    severity: "critical",
    status: "active",
    tactic: "Exfiltration",
    technique: "Transfer Data to Cloud Account",
    techniqueId: "T1567.002",
    source: "AKIA5F6G…9Q2C (svc-order-api)",
    target: "s3://prod-customer-data",
    account: "prod-9823",
    confidence: 94,
    timestamp: "2026-08-04T05:58:00Z",
    evidence: [
      "GuardDuty: S3ObjectReadAnomaly on prod-customer-data",
      "Baseline download volume: 2.1 GB/day — today: 42 GB",
      "Concurrent S3 CopyObject to bucket 'backup-7f3a' in ap-southeast-1",
    ],
    affectedAssets: ["prod-customer-data"],
  },
  {
    id: "al-503",
    title: "New IAM user 'support-dmz' created with AdministratorAccess",
    description:
      "A new IAM user was created outside the change window and immediately granted AdministratorAccess, a classic persistence primitive.",
    severity: "high",
    status: "active",
    tactic: "Persistence",
    technique: "Create Account",
    techniqueId: "T1136.003",
    source: "iam.amazonaws.com CreateUser (source: AKIA5F6G…9Q2C)",
    target: "support-dmz",
    account: "prod-9823",
    confidence: 91,
    timestamp: "2026-08-04T05:47:00Z",
    evidence: [
      "CloudTrail eventId 8f2c…44a1 at 05:47:12 UTC",
      "User created 6 minutes after first key use from TOR IP",
      "No Change Management ticket correlates with this action",
    ],
    affectedAssets: ["support-dmz"],
  },
  {
    id: "al-504",
    title: "RDP brute-force against 'vm-payroll-prod' — 1,240 attempts",
    description:
      "Microsoft Defender for Cloud reported 1,240 failed RDP authentication attempts against the payroll VM from 4 external IPs.",
    severity: "high",
    status: "investigating",
    tactic: "Lateral Movement",
    technique: "Remote Services",
    techniqueId: "T1021.001",
    source: "4 external IPs (ASN AS16509, AS8075)",
    target: "vm-payroll-prod:3389",
    account: "prod-72b9",
    confidence: 88,
    timestamp: "2026-08-03T22:14:00Z",
    evidence: [
      "Defender for Cloud alert: RDP_BruteForce_PayrollVM",
      "Failed logins use 'Administrator' and 'svc_backup' usernames",
      "First attempt at 21:38, last at 22:13 UTC",
    ],
    affectedAssets: ["vm-payroll-prod"],
  },
  {
    id: "al-505",
    title: "CloudTrail logging disabled in legacy account us-west-2",
    description:
      "StopLogging was invoked on the only trail covering us-west-2, a known defense-evasion step before credential theft.",
    severity: "high",
    status: "active",
    tactic: "Defense Evasion",
    technique: "Impair Defenses — Disable Cloud Logs",
    techniqueId: "T1562.008",
    source: "console.aws.amazon.com (role: root, no MFA)",
    target: "trail: acme-legacy-global (legacy-7755)",
    account: "legacy-7755",
    confidence: 86,
    timestamp: "2026-08-03T20:31:00Z",
    evidence: [
      "CloudTrail StopLogging API call from root session without MFA",
      "Trail paused for 18 minutes before automatic re-enable by Aegivion watchdog",
      "Correlates with 'support-dmz' creation in sibling account",
    ],
    affectedAssets: ["jenkins-legacy"],
  },
  {
    id: "al-506",
    title: "EC2 instance 'web-prod-1' invoked cross-account AssumeRole to legacy",
    description:
      "A production web instance assumed a role in the legacy account, violating the trust boundary and enabling privilege escalation paths.",
    severity: "medium",
    status: "contained",
    tactic: "Privilege Escalation",
    technique: "Valid Accounts",
    techniqueId: "T1078",
    source: "i-0f2c9a31b8d4e7a12 (web-prod-1)",
    target: "role: legacy-admin-readonly (legacy-7755)",
    account: "prod-9823",
    confidence: 82,
    timestamp: "2026-08-03T14:02:00Z",
    evidence: [
      "CloudTrail: sts:AssumeRole from i-0f2c9a31b8d4e7a12 to arn:aws:iam::7755:role/legacy-admin-readonly",
      "Role policy allows s3:GetObject on billing buckets",
      "No deployment correlating with this access",
    ],
    affectedAssets: ["web-prod-1"],
  },
  {
    id: "al-507",
    title: "Crypto-mining workload detected on GKE 'gke-model-serving'",
    description:
      "Resource anomaly on the model-serving cluster matches known miner behavior — high CPU, outbound connections to mining pools on ports 3333/4444.",
    severity: "medium",
    status: "contained",
    tactic: "Impact",
    technique: "Resource Hijacking",
    techniqueId: "T1496",
    source: "gke-model-serving (namespace: default, pod: geth-x7k2)",
    target: "Cluster node pool ml-pool-1",
    account: "data-analytics",
    confidence: 84,
    timestamp: "2026-08-02T11:19:00Z",
    evidence: [
      "Security Command Center: CryptoMining alert on GKE",
      "Pod image: registry.hub.docker.com/ethereum/client-go@sha256:4f1c…",
      "Connections to 51.15.77.4:4444 (known mining pool)",
    ],
    affectedAssets: ["gke-model-serving"],
  },
  {
    id: "al-508",
    title: "Entra ID sign-in risk: impossible travel from two continents",
    description:
      "The global-admin account signed in from Frankfurt and São Paulo within 14 minutes. Identity Protection flags this as high-risk sign-in.",
    severity: "high",
    status: "investigating",
    tactic: "Initial Access",
    technique: "Valid Accounts",
    techniqueId: "T1078",
    source: "IP 185.93.4.11 (DE) → 177.54.22.9 (BR)",
    target: "entra-global-admins",
    account: "prod-72b9",
    confidence: 79,
    timestamp: "2026-08-02T08:55:00Z",
    evidence: [
      "Entra Identity Protection risk: High (impossibleTravel)",
      "Session granted Azure AD Conditional Access with no MFA (legacy policy)",
      "Session token activity: Key Vault GetSecret x 38",
    ],
    affectedAssets: ["entra-global-admins", "vault-kv-prod"],
  },
];

/* ----------------------- Threat correlation chains ----------------------- */

export const CHAIN_1_NODES: ThreatChainNode[] = [
  { id: "c1n1", label: "Exposed IAM keys on GitHub", tactic: "Initial Access", techniqueId: "T1078.004", severity: "critical", alertId: "al-501" },
  { id: "c1n2", label: "Keys used via TOR → DescribeInstances", tactic: "Execution", techniqueId: "T1059", severity: "high", alertId: "al-501" },
  { id: "c1n3", label: "Backdoor IAM user 'support-dmz' created", tactic: "Persistence", techniqueId: "T1136.003", severity: "high", alertId: "al-503" },
  { id: "c1n4", label: "CloudTrail logging paused (legacy)", tactic: "Defense Evasion", techniqueId: "T1562.008", severity: "high", alertId: "al-505" },
  { id: "c1n5", label: "Bulk S3 download 42 GB staged", tactic: "Exfiltration", techniqueId: "T1567.002", severity: "critical", alertId: "al-502" },
];

export const CHAIN_1_EDGES: ThreatChainEdge[] = [
  { id: "c1e1", source: "c1n1", target: "c1n2", evidence: "Key first use 11m after commit push" },
  { id: "c1e2", source: "c1n2", target: "c1n3", evidence: "CreateUser called with same key AKIA5F6G…9Q2C" },
  { id: "c1e3", source: "c1n3", target: "c1n4", evidence: "support-dmz role used to StopLogging" },
  { id: "c1e4", source: "c1n4", target: "c1n5", evidence: "42 GB read anomaly 22 min after logging paused" },
];

export const CHAIN_2_NODES: ThreatChainNode[] = [
  { id: "c2n1", label: "Public GKE API exposed", tactic: "Initial Access", techniqueId: "T1190", severity: "medium", alertId: "al-507" },
  { id: "c2n2", label: "kubectl exec into pod", tactic: "Execution", techniqueId: "T1609", severity: "medium", alertId: "al-507" },
  { id: "c2n3", label: "Privileged pod with hostPath mount", tactic: "Privilege Escalation", techniqueId: "T1611", severity: "high", alertId: "al-507" },
  { id: "c2n4", label: "Miner container deployed", tactic: "Impact", techniqueId: "T1496", severity: "medium", alertId: "al-507" },
];

export const CHAIN_2_EDGES: ThreatChainEdge[] = [
  { id: "c2e1", source: "c2n1", target: "c2n2", evidence: "Audit log: create /api/v1/namespaces/default/pods/exec" },
  { id: "c2e2", source: "c2n2", target: "c2n3", evidence: "Pod spec modified with hostPath /var/lib/docker" },
  { id: "c2e3", source: "c2n3", target: "c2n4", evidence: "Image pull of ethereum/client-go from hub.docker.com" },
];

export const ATTACK_TIMELINE = [
  { time: "00:00", events: 2 },
  { time: "02:00", events: 1 },
  { time: "04:00", events: 3 },
  { time: "06:00", events: 6 },
  { time: "08:00", events: 4 },
  { time: "10:00", events: 5 },
  { time: "12:00", events: 3 },
  { time: "14:00", events: 7 },
  { time: "16:00", events: 4 },
  { time: "18:00", events: 2 },
  { time: "20:00", events: 5 },
  { time: "22:00", events: 9 },
];

export const MITRE_COVERAGE = [
  { tactic: "Initial Access", techniques: 3, color: "#6d5df6" },
  { tactic: "Execution", techniques: 2, color: "#4f7cf7" },
  { tactic: "Persistence", techniques: 2, color: "#c35df5" },
  { tactic: "Privilege Escalation", techniques: 2, color: "#f59e0b" },
  { tactic: "Defense Evasion", techniques: 1, color: "#ef4444" },
  { tactic: "Lateral Movement", techniques: 1, color: "#16a34a" },
  { tactic: "Exfiltration", techniques: 1, color: "#0ea5e9" },
  { tactic: "Impact", techniques: 1, color: "#8b5cf6" },
];
