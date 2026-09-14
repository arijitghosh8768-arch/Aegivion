import type { ProviderId, Severity } from "@/lib/types";

export interface DiscoveryEvent {
  id: string;
  name: string;
  type: string;
  provider: ProviderId;
  region: string;
  time: string;
}

export const RECENT_DISCOVERIES: DiscoveryEvent[] = [
  { id: "d-1", name: "fn-event-ingest", type: "Cloud Function", provider: "gcp", region: "us-central1", time: "2m ago" },
  { id: "d-2", name: "kms-keys-prod", type: "KMS Key", provider: "aws", region: "us-east-1", time: "6m ago" },
  { id: "d-3", name: "vault-kv-prod", type: "Key Vault", provider: "azure", region: "eastus", time: "7m ago" },
  { id: "d-4", name: "redshift-analytics", type: "Redshift", provider: "aws", region: "us-east-1", time: "8m ago" },
  { id: "d-5", name: "gke-model-serving", type: "GKE Cluster", provider: "gcp", region: "us-central1", time: "12m ago" },
  { id: "d-6", name: "aks-shared", type: "AKS Cluster", provider: "azure", region: "westeurope", time: "14m ago" },
];

export interface TopologyFinding {
  id: string;
  title: string;
  provider: ProviderId;
  type: string;
  severity: Severity;
  confidence: number;
  time: string;
}

export const RECENT_TOPOLOGY_FINDINGS: TopologyFinding[] = [
  { id: "tf-1", title: "S3 bucket 'prod-customer-data' publicly readable", provider: "aws", type: "S3", severity: "critical", confidence: 98, time: "3m ago" },
  { id: "tf-2", title: "IAM role 'ci-deploy-role' has AdministratorAccess", provider: "aws", type: "IAM", severity: "critical", confidence: 96, time: "11m ago" },
  { id: "tf-3", title: "VM 'vm-payroll-prod' exposed on RDP 3389", provider: "azure", type: "VM", severity: "critical", confidence: 93, time: "19m ago" },
  { id: "tf-4", title: "Security group 'sg-web-lb' allows SSH from 0.0.0.0/0", provider: "aws", type: "Security Group", severity: "high", confidence: 99, time: "28m ago" },
  { id: "tf-5", title: "Service account 'sa-ml-sa-8841' has owner role", provider: "gcp", type: "IAM", severity: "high", confidence: 92, time: "41m ago" },
  { id: "tf-6", title: "CloudSQL 'cloudsql-warehouse' allows any network", provider: "gcp", type: "CloudSQL", severity: "high", confidence: 95, time: "1h ago" },
];

export interface TopologyChange {
  id: string;
  kind: "added" | "removed" | "modified" | "risk";
  label: string;
  provider: ProviderId;
  detail: string;
  time: string;
}

export const TOPOLOGY_CHANGES: TopologyChange[] = [
  { id: "tc-1", kind: "added", label: "Lambda function deployed", provider: "aws", detail: "orders-processor · eu-west-1", time: "4m ago" },
  { id: "tc-2", kind: "risk", label: "Risk score increased", provider: "aws", detail: "sg-web-lb 74 → 88", time: "9m ago" },
  { id: "tc-3", kind: "modified", label: "Security group rule changed", provider: "azure", detail: "nsg-payroll · port 3389", time: "16m ago" },
  { id: "tc-4", kind: "removed", label: "VM instance terminated", provider: "gcp", detail: "gce-build-04 · us-central1", time: "24m ago" },
  { id: "tc-5", kind: "added", label: "Service account created", provider: "gcp", detail: "sa-etl-batch-22", time: "38m ago" },
  { id: "tc-6", kind: "risk", label: "New public exposure", provider: "azure", detail: "hr-records-store · anonymous read", time: "52m ago" },
];

export const ASSET_TIMELINE = [
  { week: "W1", added: 210, removed: 40, net: 170 },
  { week: "W2", added: 260, removed: 55, net: 205 },
  { week: "W3", added: 235, removed: 62, net: 173 },
  { week: "W4", added: 290, removed: 48, net: 242 },
  { week: "W5", added: 310, removed: 70, net: 240 },
  { week: "W6", added: 285, removed: 66, net: 219 },
  { week: "W7", added: 340, removed: 58, net: 282 },
  { week: "W8", added: 360, removed: 82, net: 278 },
];
