export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ProviderId = "aws" | "azure" | "gcp";
export type FindingStatus = "open" | "acknowledged" | "remediating" | "remediated";
export type AlertStatus = "active" | "investigating" | "contained" | "resolved";
export type RiskLevel = "low" | "moderate" | "elevated" | "high" | "critical";

export interface CloudAccount {
  id: string;
  provider: ProviderId;
  name: string;
  accountId: string;
  status: "connected" | "degraded" | "error";
  regions: number;
  lastScan: string;
  resources: number;
  findings: number;
  critical: number;
  healthScore: number;
  coverage: string[];
  plan: "Free" | "Pro" | "Enterprise";
}

export interface Asset {
  id: string;
  name: string;
  type: string;
  provider: ProviderId;
  region: string;
  account: string;
  riskScore: number;
  critical: boolean;
  publicExposed: boolean;
  tags: string[];
  lastSeen: string;
  owner: string;
  services: string[];
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  service: string;
  category: "iam" | "s3" | "ec2" | "security-group" | "cloudtrail" | "cloudwatch" | "k8s" | "database";
  provider: ProviderId;
  severity: Severity;
  confidence: number;
  status: FindingStatus;
  evidence: string;
  affectedAsset: string;
  detectedAt: string;
  cve?: string;
  framework?: string;
  mitre?: string[];
  terraform?: string;
  cli?: string;
  rollback?: string;
  autoFixable: boolean;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  tactic: string;
  technique: string;
  techniqueId: string;
  source: string;
  target: string;
  account: string;
  confidence: number;
  timestamp: string;
  evidence: string[];
  affectedAssets: string[];
}

export interface ThreatChainNode {
  id: string;
  label: string;
  tactic: string;
  techniqueId: string;
  severity: Severity;
  alertId: string;
}

export interface ThreatChainEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  evidence?: string;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  short: string;
  passed: number;
  total: number;
  score: number;
  trend: number;
  status: "pass" | "attention" | "fail";
}

export interface NotificationItem {
  id: string;
  title: string;
  body: string;
  severity: Severity;
  time: string;
  read: boolean;
  category: "alert" | "finding" | "system" | "remediation";
}

export interface IncidentMemory {
  id: string;
  title: string;
  date: string;
  outcome: string;
  summary: string;
  patterns: string[];
  repeated: boolean;
  severity: Severity;
  durationHrs: number;
  affected: number;
}

export interface RemediationPlan {
  findingId: string;
  title: string;
  provider: ProviderId;
  service: string;
  severity: Severity;
  status: "pending" | "approved" | "rejected" | "applied" | "failed";
  impact: "low" | "medium" | "high";
  etaMin: number;
  riskOfChange: "low" | "medium" | "high";
  terraform: string;
  cli: string;
  rollback: string;
  requestedBy: string;
  createdAt: string;
}

export interface Workspace {
  id: string;
  name: string;
  plan: string;
  region: string;
}
