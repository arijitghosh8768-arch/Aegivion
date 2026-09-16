import type { ProviderId } from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Topology node model                                                 */
/* ------------------------------------------------------------------ */

export type TopologyNodeId = ProviderId | "network" | "database" | "users" | "firewall" | "endpoints";

export type NodeStatus = "healthy" | "warning" | "critical" | "disconnected";

export interface TopologyResource {
  type: string;
  angle: number; // degrees around the node body
  risk: number; // 0-100
}

export interface TopologyPacket {
  dur: number; // seconds for one trip
  offset: number; // 0-1 phase
  size: number; // radius
}

export interface TopologySection {
  title: string;
  values: string[];
}

export interface TopologyRisk {
  text: string;
  level: "ok" | "warn" | "crit";
}

export interface TopologyProvider {
  id: TopologyNodeId;
  kind: "provider" | "network" | "database" | "users";
  name: string; // display label under the node
  short: string;
  tagline: string;
  angle: number; // base orbital angle (0 = top, clockwise)
  radius: number; // orbit radius from the core
  color: string;
  soft: string;
  assetLabel: string; // "assets" | "identities"
  resourceCount: number;
  critical: number;
  orbitRadius: number;
  orbitSpeed: number;
  orbitSpeed2: number;
  resources: TopologyResource[];
  packets: TopologyPacket[];
  status: NodeStatus;
  securityScore: number;
  complianceScore: number;
  lastScan: string;
  connectedSince: string;
  region: string;
  findings: { critical: number; high: number; medium: number; low: number };
  summary: string;
  sections: TopologySection[];
  risks: TopologyRisk[];
  recommendations: string[];
  focus: TopologyNodeId[]; // nodes highlighted when this node is selected
}

export const TOPOLOGY_W = 1200;
export const TOPOLOGY_H = 780;
export const TOPOLOGY_CENTER = { x: 600, y: 390 };

/* 0° = top, clockwise (matches the orbital ring) */
const NODE_RADIUS = 318;

/* ------------------------------------------------------------------ */
/* Cloud providers                                                     */
/* ------------------------------------------------------------------ */

export const TOPOLOGY_PROVIDERS: (TopologyProvider & { id: ProviderId })[] = [
  {
    id: "aws",
    kind: "provider",
    name: "AWS Cloud",
    short: "AWS",
    tagline: "Amazon Web Services · 3 accounts",
    angle: 60,
    radius: NODE_RADIUS,
    color: "#FF9900",
    soft: "rgba(255,153,0,0.14)",
    assetLabel: "assets",
    resourceCount: 12,
    critical: 3,
    orbitRadius: 128,
    orbitSpeed: 46,
    orbitSpeed2: 70,
    resources: [
      { type: "EC2", angle: 0, risk: 82 },
      { type: "S3", angle: 60, risk: 96 },
      { type: "IAM", angle: 120, risk: 74 },
      { type: "Lambda", angle: 180, risk: 41 },
      { type: "RDS", angle: 240, risk: 63 },
      { type: "VPC", angle: 300, risk: 12 },
      { type: "EKS", angle: 20, risk: 57 },
      { type: "SG", angle: 160, risk: 88 },
    ],
    packets: [
      { dur: 5.2, offset: 0, size: 3.4 },
      { dur: 7.6, offset: 0.24, size: 2.6 },
      { dur: 6.4, offset: 0.53, size: 3.0 },
    ],
    status: "warning",
    securityScore: 84,
    complianceScore: 91,
    lastScan: "2m ago",
    connectedSince: "Jan 2025",
    region: "ap-south-1 · +3",
    findings: { critical: 3, high: 11, medium: 24, low: 9 },
    summary: "Production workloads across 3 accounts. S3 exposure and over-privileged roles drive the risk posture.",
    sections: [
      {
        title: "Connected Services",
        values: ["EC2 · 2,841", "S3 · 412", "Lambda · 96", "CloudTrail · 14", "IAM · 38", "RDS · 23", "GuardDuty · On", "Inspector · On", "Security Hub · On"],
      },
    ],
    risks: [
      { text: "S3 bucket policy publicly readable", level: "crit" },
      { text: "IAM role over-privileged (deploy-bot)", level: "warn" },
      { text: "SG allows SSH from 0.0.0.0/0", level: "warn" },
    ],
    recommendations: [
      "Enable Block Public Access on all S3 buckets",
      "Attach least-privilege IAM policy to deploy-bot",
      "Scope SSH security group to bastion CIDR only",
    ],
    focus: ["aws", "network", "database", "users"],
  },
  {
    id: "azure",
    kind: "provider",
    name: "Microsoft Azure",
    short: "Azure",
    tagline: "Microsoft Azure · 2 tenants",
    angle: 180,
    radius: NODE_RADIUS,
    color: "#0078D4",
    soft: "rgba(0,120,212,0.14)",
    assetLabel: "assets",
    resourceCount: 10,
    critical: 1,
    orbitRadius: 118,
    orbitSpeed: 56,
    orbitSpeed2: 88,
    resources: [
      { type: "VM", angle: 30, risk: 79 },
      { type: "Storage", angle: 90, risk: 69 },
      { type: "SQL", angle: 150, risk: 44 },
      { type: "AKS", angle: 210, risk: 52 },
      { type: "Entra", angle: 270, risk: 84 },
      { type: "Kvault", angle: 330, risk: 61 },
    ],
    packets: [
      { dur: 6.8, offset: 0.08, size: 2.8 },
      { dur: 8.2, offset: 0.34, size: 2.2 },
    ],
    status: "healthy",
    securityScore: 87,
    complianceScore: 93,
    lastScan: "4m ago",
    connectedSince: "Feb 2025",
    region: "eastus · +1",
    findings: { critical: 1, high: 8, medium: 17, low: 5 },
    summary: "Enterprise subscriptions with Defender enabled. Remaining exposure is concentrated in storage and Entra ID.",
    sections: [
      {
        title: "Connected Services",
        values: ["VM · 8", "Storage · 6", "Azure AD · 12", "Defender · On", "Activity Logs · On", "Resource Groups · 9"],
      },
    ],
    risks: [
      { text: "Storage account allows anonymous access", level: "warn" },
      { text: "Service principal has broad role assignment", level: "warn" },
    ],
    recommendations: [
      "Disable anonymous blob access on storage account",
      "Scope SPN role assignment to a single resource group",
      "Enforce Conditional Access MFA for all admins",
    ],
    focus: ["azure", "network", "database", "users"],
  },
  {
    id: "gcp",
    kind: "provider",
    name: "Google Cloud",
    short: "GCP",
    tagline: "Google Cloud · 2 projects",
    angle: 120,
    radius: NODE_RADIUS,
    color: "#4285F4",
    soft: "rgba(66,133,244,0.14)",
    assetLabel: "assets",
    resourceCount: 10,
    critical: 1,
    orbitRadius: 108,
    orbitSpeed: 62,
    orbitSpeed2: 96,
    resources: [
      { type: "GCE", angle: 45, risk: 58 },
      { type: "GCS", angle: 135, risk: 46 },
      { type: "SQL", angle: 225, risk: 38 },
      { type: "GKE", angle: 315, risk: 64 },
      { type: "SA", angle: 10, risk: 77 },
    ],
    packets: [
      { dur: 7.2, offset: 0.14, size: 2.4 },
      { dur: 5.8, offset: 0.41, size: 3.2 },
    ],
    status: "warning",
    securityScore: 79,
    complianceScore: 88,
    lastScan: "6m ago",
    connectedSince: "Mar 2025",
    region: "us-central1",
    findings: { critical: 1, high: 9, medium: 15, low: 6 },
    summary: "Data analytics estate. A leaked service-account key and a world-readable bucket need immediate attention.",
    sections: [
      {
        title: "Connected Services",
        values: ["Compute Engine · 11", "Cloud Storage · 7", "IAM · 24", "Cloud Logging · On", "Cloud SQL · 4", "Security Command Center · Live"],
      },
    ],
    risks: [
      { text: "Cloud Storage bucket world-readable", level: "warn" },
      { text: "Service account key exposed in repo", level: "crit" },
    ],
    recommendations: [
      "Rotate exposed SA key and scan repos for secrets",
      "Enforce uniform bucket-level access",
      "Enable VPC flow logs with 90-day retention",
    ],
    focus: ["gcp", "network", "database", "users"],
  },
];

/* ------------------------------------------------------------------ */
/* Environment domains                                                 */
/* ------------------------------------------------------------------ */

const DOMAIN_NODES: (TopologyProvider & { id: "network" | "database" | "users" })[] = [
  {
    id: "network",
    kind: "network",
    name: "Network",
    short: "NET",
    tagline: "VPC · subnets · security groups",
    angle: 0,
    radius: NODE_RADIUS,
    color: "#4f7cf7",
    soft: "rgba(79,124,247,0.14)",
    assetLabel: "assets",
    resourceCount: 6,
    critical: 2,
    orbitRadius: 112,
    orbitSpeed: 52,
    orbitSpeed2: 82,
    resources: [
      { type: "VPC", angle: 0, risk: 12 },
      { type: "Subnets", angle: 60, risk: 38 },
      { type: "SG", angle: 120, risk: 88 },
      { type: "Route", angle: 180, risk: 22 },
      { type: "IGW", angle: 240, risk: 54 },
      { type: "NAT", angle: 300, risk: 18 },
    ],
    packets: [
      { dur: 5.6, offset: 0.05, size: 2.6 },
      { dur: 7.4, offset: 0.38, size: 2.2 },
    ],
    status: "critical",
    securityScore: 66,
    complianceScore: 72,
    lastScan: "1m ago",
    connectedSince: "Jan 2025",
    region: "Global",
    findings: { critical: 2, high: 5, medium: 9, low: 3 },
    summary: "Cross-cloud network backbone. Open SSH exposure and unrestricted egress are the top network risks.",
    sections: [
      {
        title: "VPCs",
        values: ["VPC · 3", "Subnets · 9", "Security Groups · 14", "Route Tables · 6", "Internet Gateway · 2", "NAT Gateway · 1", "Open Ports · 4"],
      },
      { title: "Network Diagram", values: ["Flow logs", "Topology map", "Route analysis"] },
    ],
    risks: [
      { text: "Open SSH port on production security group", level: "crit" },
      { text: "Unrestricted egress from public subnet", level: "warn" },
    ],
    recommendations: [
      "Remove 0.0.0.0/0 SSH rule from prod-sg",
      "Add egress allowlist for public subnets",
      "Enable flow-log analytics pipeline",
    ],
    focus: ["network", "aws", "azure", "gcp", "database", "users"],
  },
  {
    id: "database",
    kind: "database",
    name: "Database",
    short: "DB",
    tagline: "Monitored database engines",
    angle: 240,
    radius: NODE_RADIUS,
    color: "#8b5cf6",
    soft: "rgba(139,92,246,0.14)",
    assetLabel: "assets",
    resourceCount: 4,
    critical: 0,
    orbitRadius: 116,
    orbitSpeed: 58,
    orbitSpeed2: 90,
    resources: [
      { type: "RDS", angle: 0, risk: 44 },
      { type: "Aurora", angle: 72, risk: 28 },
      { type: "Postgres", angle: 144, risk: 36 },
      { type: "MySQL", angle: 216, risk: 31 },
      { type: "Mongo", angle: 288, risk: 52 },
    ],
    packets: [
      { dur: 6.2, offset: 0.12, size: 2.6 },
      { dur: 8.6, offset: 0.46, size: 2.2 },
    ],
    status: "healthy",
    securityScore: 88,
    complianceScore: 95,
    lastScan: "3m ago",
    connectedSince: "Jan 2025",
    region: "All regions",
    findings: { critical: 0, high: 2, medium: 6, low: 2 },
    summary: "Managed database estate with daily backups. One instance still lacks encryption at rest.",
    sections: [
      {
        title: "Engines",
        values: ["RDS · 3", "Aurora · 1", "SQL · 2", "PostgreSQL · 1", "MySQL · 1", "MongoDB · 1"],
      },
      {
        title: "Hardening",
        values: ["Encryption · 6/7", "Public Access · 0", "Backups · Daily", "Performance · Healthy"],
      },
    ],
    risks: [
      { text: "1 instance without encryption at rest", level: "warn" },
      { text: "Database snapshots retained 30 days", level: "ok" },
    ],
    recommendations: [
      "Enable encryption at rest on rds-prod-01",
      "Enable automated minor version upgrades",
      "Rotate DB master credentials quarterly",
    ],
    focus: ["database", "aws", "azure", "gcp", "network"],
  },
  {
    id: "users",
    kind: "users",
    name: "Users",
    short: "USR",
    tagline: "Identities & IAM",
    angle: 300,
    radius: NODE_RADIUS,
    color: "#c35df5",
    soft: "rgba(195,93,245,0.14)",
    assetLabel: "identities",
    resourceCount: 9,
    critical: 1,
    orbitRadius: 118,
    orbitSpeed: 54,
    orbitSpeed2: 86,
    resources: [
      { type: "IAM Users", angle: 0, risk: 48 },
      { type: "IAM Roles", angle: 60, risk: 66 },
      { type: "Groups", angle: 120, risk: 30 },
      { type: "MFA", angle: 180, risk: 58 },
      { type: "Keys", angle: 240, risk: 72 },
      { type: "Admins", angle: 300, risk: 81 },
    ],
    packets: [
      { dur: 6.6, offset: 0.18, size: 2.4 },
      { dur: 8.8, offset: 0.52, size: 2.0 },
    ],
    status: "warning",
    securityScore: 71,
    complianceScore: 76,
    lastScan: "5m ago",
    connectedSince: "Jan 2025",
    region: "Global",
    findings: { critical: 1, high: 4, medium: 8, low: 4 },
    summary: "Human and machine identities. Two users still lack MFA and several access keys are overdue for rotation.",
    sections: [
      {
        title: "Identities",
        values: ["IAM Users · 9", "IAM Roles · 14", "Groups · 5", "Permissions · 38", "Administrator Accounts · 2"],
      },
      {
        title: "Hygiene",
        values: ["MFA Status · 7/9", "Inactive Users · 2", "Access Keys · 4"],
      },
    ],
    risks: [
      { text: "2 users without MFA enabled", level: "warn" },
      { text: "Root login attempt detected (12m ago)", level: "warn" },
    ],
    recommendations: [
      "Enforce MFA for all 9 identities",
      "Rotate access keys older than 90 days",
      "Remove long-term credentials from root user",
    ],
    focus: ["users", "aws", "azure", "gcp", "network"],
  },
];

export const TOPOLOGY_NODES: TopologyProvider[] = [
  ...TOPOLOGY_PROVIDERS,
  ...DOMAIN_NODES,
];

/* ------------------------------------------------------------------ */
/* Orbital arc sector labels (rotate with the ring)                    */
/* ------------------------------------------------------------------ */

export interface TopologyArc {
  text: string;
  from: number; // degrees (0 = top, clockwise)
  to: number;
  r: number;
}

export const TOPOLOGY_ARCS: TopologyArc[] = [
  { text: "A P P L I C A T I O N S", from: 8, to: 46, r: 358 },
  { text: "I D E N T I T I E S", from: 74, to: 106, r: 358 },
  { text: "D A T A", from: 132, to: 168, r: 358 },
  { text: "W O R K L O A D S", from: 192, to: 228, r: 358 },
  { text: "C O M P U T E", from: 252, to: 288, r: 358 },
  { text: "N E T W O R K", from: 312, to: 352, r: 358 },
];

/* ------------------------------------------------------------------ */
/* Backwards-compatible exports                                        */
/* ------------------------------------------------------------------ */

export interface TopologyLink {
  id: string;
  from: ProviderId;
  to: "core";
  packets: { dur: number; begin: number; size: number }[];
}

export const TOPOLOGY_LINKS: TopologyLink[] = [
  {
    id: "l-aws",
    from: "aws",
    to: "core",
    packets: [
      { dur: 5.2, begin: 0, size: 3.4 },
      { dur: 7.6, begin: 1.8, size: 2.6 },
      { dur: 6.4, begin: 3.4, size: 3.0 },
    ],
  },
  {
    id: "l-azure",
    from: "azure",
    to: "core",
    packets: [
      { dur: 6.8, begin: 0.6, size: 2.8 },
      { dur: 8.2, begin: 2.6, size: 2.2 },
    ],
  },
  {
    id: "l-gcp",
    from: "gcp",
    to: "core",
    packets: [
      { dur: 7.2, begin: 1.1, size: 2.4 },
      { dur: 5.8, begin: 3.0, size: 3.2 },
    ],
  },
];

export interface AttackPath {
  id: string;
  from: TopologyNodeId;
  to: TopologyNodeId;
  label: string;
  severity: "critical" | "high" | "medium";
}

export const ATTACK_PATHS: AttackPath[] = [
  {
    id: "ap-1",
    from: "aws",
    to: "database",
    label: "Public S3 → unencrypted RDS",
    severity: "critical",
  },
  {
    id: "ap-2",
    from: "azure",
    to: "users",
    label: "Key Vault secret → stale admin keys",
    severity: "high",
  },
  {
    id: "ap-3",
    from: "gcp",
    to: "network",
    label: "Exposed VM → open security group",
    severity: "medium",
  },
];

export const RESOURCE_TYPE_FILTERS = [
  "EC2",
  "S3",
  "IAM",
  "Lambda",
  "RDS",
  "VM",
  "GCE",
  "GKE",
  "Storage",
  "SQL",
  "VPC",
  "SG",
  "Subnets",
  "MFA",
];
