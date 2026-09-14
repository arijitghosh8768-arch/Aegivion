import type { NotificationItem } from "@/lib/types";

export const INITIAL_NOTIFICATIONS: NotificationItem[] = [
  {
    id: "n-1",
    title: "Critical: IAM keys exposed on GitHub",
    body: "Live AWS keys for ci-deploy-role were found in acme/platform-config.",
    severity: "critical",
    time: "18 min ago",
    read: false,
    category: "alert",
  },
  {
    id: "n-2",
    title: "Anomalous S3 download detected",
    body: "42 GB staged from prod-customer-data. Exfiltration chain CH-2026-08-04-01.",
    severity: "critical",
    time: "24 min ago",
    read: false,
    category: "alert",
  },
  {
    id: "n-3",
    title: "Remediation applied: sg-web-lb",
    body: "SSH 0.0.0.0/0 rule revoked on web-prod-1. Rollback available for 24h.",
    severity: "medium",
    time: "1 h ago",
    read: false,
    category: "remediation",
  },
  {
    id: "n-4",
    title: "New finding: Key Vault network ACLs",
    body: "vault-kv-prod allows default network access (high severity).",
    severity: "high",
    time: "3 h ago",
    read: true,
    category: "finding",
  },
  {
    id: "n-5",
    title: "Sandbox account scan failed",
    body: "GCP sandbox-4452 last successful scan was 2 days ago.",
    severity: "medium",
    time: "5 h ago",
    read: true,
    category: "system",
  },
  {
    id: "n-6",
    title: "Weekly report ready",
    body: "Security Posture Report is available in Reports.",
    severity: "info",
    time: "1 d ago",
    read: true,
    category: "system",
  },
];

export const ACTIVITY_FEED = [
  { id: "af-1", text: "AI Copilot generated remediation plan RP-101-3", time: "19 min ago", kind: "ai" },
  { id: "af-2", text: "Credential ci-deploy-role revoked after key leak", time: "26 min ago", kind: "action" },
  { id: "af-3", text: "Bucket backup-7f3a quarantined (suspected staging)", time: "31 min ago", kind: "action" },
  { id: "af-4", text: "Threat chain CH-2026-08-04-01 correlated 4 alerts", time: "38 min ago", kind: "detection" },
  { id: "af-5", text: "Compliance scan: SOC 2 95% (+0.2pts)", time: "1 h ago", kind: "scan" },
  { id: "af-6", text: "New asset discovered: fn-event-ingest (GCP)", time: "2 h ago", kind: "discovery" },
];
