import type { ProviderId } from "@/lib/types";

export interface Identity {
  id: string;
  name: string;
  kind: "user" | "role" | "service-account";
  provider: ProviderId;
  account: string;
  privileges: string[];
  mfa: boolean;
  keys: number;
  lastUsed: string;
  risk: number;
  access: "admin" | "high" | "medium" | "least";
  status: "active" | "suspicious" | "dormant" | "monitored";
}

export const IDENTITIES: Identity[] = [
  { id: "i-1", name: "ci-deploy-role", kind: "role", provider: "aws", account: "prod-9823", privileges: ["AdministratorAccess"], mfa: false, keys: 1, lastUsed: "41s ago", risk: 74, access: "admin", status: "suspicious" },
  { id: "i-2", name: "svc-order-api", kind: "user", provider: "aws", account: "prod-9823", privileges: ["AmazonS3FullAccess", "IAMReadOnly"], mfa: true, keys: 2, lastUsed: "3m ago", risk: 66, access: "high", status: "monitored" },
  { id: "i-3", name: "support-dmz", kind: "user", provider: "aws", account: "prod-9823", privileges: ["AdministratorAccess"], mfa: false, keys: 0, lastUsed: "5m ago", risk: 88, access: "admin", status: "suspicious" },
  { id: "i-4", name: "entra-global-admins", kind: "role", provider: "azure", account: "prod-72b9", privileges: ["Global Administrator"], mfa: false, keys: 0, lastUsed: "8m ago", risk: 84, access: "admin", status: "suspicious" },
  { id: "i-5", name: "sa-ml-sa-8841", kind: "service-account", provider: "gcp", account: "data-analytics", privileges: ["roles/owner"], mfa: false, keys: 3, lastUsed: "4m ago", risk: 77, access: "admin", status: "monitored" },
  { id: "i-6", name: "alex.rivera", kind: "user", provider: "aws", account: "prod-9823", privileges: ["PowerUserAccess"], mfa: true, keys: 1, lastUsed: "22m ago", risk: 38, access: "high", status: "active" },
  { id: "i-7", name: "terra-plan-runner", kind: "role", provider: "aws", account: "prod-9823", privileges: ["AmazonS3FullAccess", "IAMFullAccess"], mfa: true, keys: 1, lastUsed: "1h ago", risk: 52, access: "high", status: "active" },
  { id: "i-8", name: "dev-jenkins", kind: "user", provider: "aws", account: "prod-9823", privileges: ["AmazonEC2FullAccess"], mfa: false, keys: 2, lastUsed: "3d ago", risk: 44, access: "medium", status: "active" },
  { id: "i-9", name: "data-sci-04", kind: "service-account", provider: "gcp", account: "data-analytics", privileges: ["roles/bigquery.admin"], mfa: false, keys: 2, lastUsed: "1d ago", risk: 41, access: "medium", status: "active" },
  { id: "i-10", name: "legacy-root", kind: "user", provider: "aws", account: "legacy-7755", privileges: ["AdministratorAccess"], mfa: false, keys: 2, lastUsed: "12d ago", risk: 91, access: "admin", status: "dormant" },
  { id: "i-11", name: "kv-app-identity", kind: "service-account", provider: "azure", account: "prod-72b9", privileges: ["Key Vault Reader"], mfa: true, keys: 1, lastUsed: "6m ago", risk: 18, access: "least", status: "active" },
  { id: "i-12", name: "gha-oidc-pool", kind: "role", provider: "aws", account: "prod-9823", privileges: ["sts:AssumeRoleWithWebIdentity"], mfa: true, keys: 0, lastUsed: "2m ago", risk: 29, access: "least", status: "active" },
  { id: "i-13", name: "admin-sa", kind: "service-account", provider: "gcp", account: "core-project", privileges: ["roles/owner"], mfa: false, keys: 1, lastUsed: "1m ago", risk: 95, access: "admin", status: "suspicious" },
];
