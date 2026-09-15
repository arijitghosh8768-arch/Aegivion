import type { Alert, ThreatChainEdge, ThreatChainNode } from "@/lib/types";

/* ----------------------- Threat correlation chains ----------------------- */
export const ALERTS: Alert[] = [];


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
