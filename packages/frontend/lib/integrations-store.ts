"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";

export type IntegrationStatus = "connected" | "disconnected" | "error" | "attention";

export interface IntegrationLog {
  id: string;
  time: string;
  message: string;
  kind: "success" | "info" | "error" | "warning";
}

export interface IntegrationConfig {
  [key: string]: string | boolean;
}

export interface IntegrationState {
  status: IntegrationStatus;
  config: IntegrationConfig;
  lastSync: string;
  nextSync: string;
  health: number; // 0-100
  logs: IntegrationLog[];
  connectedAt: string;
}

export interface IntegrationDefinition {
  id: string;
  name: string;
  category: "communication" | "devops" | "ticketing" | "siem" | "notifications" | "cloud";
  description: string;
  features: string[];
  color: string; // brand tint hex
  icon: string; // key for icon map
  oauth: boolean;
  defaultStatus: IntegrationStatus;
}

export const INTEGRATION_DEFS: IntegrationDefinition[] = [
  { id: "slack", name: "Slack", category: "communication", icon: "slack", color: "#611f69", oauth: true, defaultStatus: "connected", description: "Send security alerts, daily summaries and weekly reports to your channels.", features: ["Critical alerts", "Daily summary", "Weekly reports"] },
  { id: "teams", name: "Microsoft Teams", category: "communication", icon: "teams", color: "#4b53bc", oauth: true, defaultStatus: "disconnected", description: "Post threat digests and remediation tasks into Teams channels.", features: ["Threat digests", "Remediation tasks"] },
  { id: "discord", name: "Discord", category: "communication", icon: "discord", color: "#5865f2", oauth: true, defaultStatus: "disconnected", description: "Forward critical incidents to your Discord server webhook.", features: ["Incident webhooks"] },
  { id: "pagerduty", name: "PagerDuty", category: "communication", icon: "pagerduty", color: "#ef3e42", oauth: true, defaultStatus: "connected", description: "Escalate critical and high severity alerts to on-call engineers.", features: ["Escalation policies", "Severity mapping", "Test incidents"] },
  { id: "opsgenie", name: "Opsgenie", category: "communication", icon: "opsgenie", color: "#2a5ffd", oauth: true, defaultStatus: "disconnected", description: "Route alerts to the right team with on-call scheduling.", features: ["Alert routing", "On-call schedules"] },
  { id: "github", name: "GitHub", category: "devops", icon: "github", color: "#181717", oauth: true, defaultStatus: "connected", description: "Create issues, PRs and push Terraform fixes from findings.", features: ["Secret scanning", "Dependabot", "Code scanning", "Push fixes"] },
  { id: "gitlab", name: "GitLab", category: "devops", icon: "gitlab", color: "#fc6d26", oauth: true, defaultStatus: "disconnected", description: "Sync vulnerabilities and open merge requests for fixes.", features: ["Vulnerability sync", "MR fixes"] },
  { id: "bitbucket", name: "Bitbucket", category: "devops", icon: "bitbucket", color: "#0052cc", oauth: true, defaultStatus: "disconnected", description: "Open pull requests with automated remediation changes.", features: ["PR remediation"] },
  { id: "jira", name: "Jira", category: "ticketing", icon: "jira", color: "#0052cc", oauth: true, defaultStatus: "disconnected", description: "Create and close tickets from security findings automatically.", features: ["Auto-create tickets", "Priority mapping", "Auto-close"] },
  { id: "linear", name: "Linear", category: "ticketing", icon: "linear", color: "#5e6ad2", oauth: true, defaultStatus: "disconnected", description: "Track remediation work as Linear issues with triage labels.", features: ["Issue creation", "Triage labels"] },
  { id: "servicenow", name: "ServiceNow", category: "ticketing", icon: "servicenow", color: "#3a7afe", oauth: true, defaultStatus: "disconnected", description: "Create incidents in ServiceNow for compliance workflows.", features: ["Incident creation", "CMDB sync"] },
  { id: "smtp", name: "Email SMTP", category: "notifications", icon: "mail", color: "#6d5df6", oauth: false, defaultStatus: "connected", description: "Deliver email alerts via SMTP, Office365, Gmail or Amazon SES.", features: ["SMTP", "Office365", "Gmail", "SES"] },
  { id: "webhook", name: "Webhook", category: "notifications", icon: "webhook", color: "#64748b", oauth: false, defaultStatus: "disconnected", description: "POST JSON payloads to any HTTPS endpoint with retry policy.", features: ["Custom headers", "Retry policy", "Payload preview"] },
  { id: "sentinel", name: "Microsoft Sentinel", category: "siem", icon: "sentinel", color: "#0078d4", oauth: true, defaultStatus: "disconnected", description: "Stream findings into Sentinel for investigation and hunting.", features: ["Finding streaming", "Hunting queries"] },
  { id: "splunk", name: "Splunk", category: "siem", icon: "splunk", color: "#079adb", oauth: false, defaultStatus: "disconnected", description: "Forward security events to Splunk via HEC for analytics.", features: ["HEC forwarding", "Index mapping"] },
  { id: "elastic", name: "Elastic", category: "siem", icon: "elastic", color: "#005571", oauth: false, defaultStatus: "disconnected", description: "Index findings into Elasticsearch for correlation.", features: ["Index templates", "Kibana dashboards"] },
  { id: "sns", name: "AWS SNS", category: "cloud", icon: "sns", color: "#ff9900", oauth: true, defaultStatus: "disconnected", description: "Publish alerts to SNS topics for fan-out to your tooling.", features: ["Topic publishing", "Message attributes"] },
  { id: "sqs", name: "AWS SQS", category: "cloud", icon: "sqs", color: "#e2522b", oauth: true, defaultStatus: "disconnected", description: "Queue security events for downstream consumers.", features: ["Queue delivery", "DLQ config"] },
  { id: "gchat", name: "Google Chat", category: "communication", icon: "gchat", color: "#00ac47", oauth: true, defaultStatus: "disconnected", description: "Send alerts into Google Chat spaces with webhooks.", features: ["Space webhooks", "Card messages"] },
  { id: "grafana", name: "Grafana", category: "devops", icon: "grafana", color: "#f46800", oauth: false, defaultStatus: "disconnected", description: "Export risk metrics and annotations to Grafana dashboards.", features: ["Metric export", "Annotations"] },
];

export const INTEGRATION_ICONS: Record<string, string> = {
  slack: "Slack",
  teams: "Teams",
  discord: "Discord",
  pagerduty: "PagerDuty",
  opsgenie: "Opsgenie",
  github: "GitHub",
  gitlab: "GitLab",
  bitbucket: "Bitbucket",
  jira: "Jira",
  linear: "Linear",
  servicenow: "ServiceNow",
  mail: "Mail",
  webhook: "Webhook",
  sentinel: "Sentinel",
  splunk: "Splunk",
  elastic: "Elastic",
  sns: "SNS",
  sqs: "SQS",
  gchat: "GoogleChat",
  grafana: "Grafana",
};

interface IntegrationsState {
  items: Record<string, IntegrationState>;
  connect: (id: string, config?: IntegrationConfig) => void;
  disconnect: (id: string) => void;
  updateConfig: (id: string, patch: IntegrationConfig) => void;
  setStatus: (id: string, status: IntegrationStatus) => void;
  testConnection: (id: string) => Promise<boolean>;
  addLog: (id: string, message: string, kind?: IntegrationLog["kind"]) => void;
  connectedCount: number;
}

function freshState(def: IntegrationDefinition): IntegrationState {
  const now = new Date();
  const fmt = (d: Date) => d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
  const next = new Date(now.getTime() + 30 * 60 * 1000);
  return {
    status: def.defaultStatus,
    config: {},
    lastSync: def.defaultStatus === "connected" ? fmt(now) : "—",
    nextSync: def.defaultStatus === "connected" ? fmt(next) : "—",
    health: def.defaultStatus === "connected" ? 98 : 0,
    connectedAt: def.defaultStatus === "connected" ? "Aug 3, 2026" : "",
    logs:
      def.defaultStatus === "connected"
        ? [
            { id: `${def.id}-l1`, time: fmt(now), message: `${def.name} connected successfully`, kind: "success" },
            { id: `${def.id}-l2`, time: fmt(new Date(now.getTime() - 7 * 60000)), message: "Configuration synced", kind: "info" },
          ]
        : [],
  };
}

const DEFAULTS: Record<string, IntegrationState> = Object.fromEntries(
  INTEGRATION_DEFS.map((d) => [d.id, freshState(d)])
);

export const useIntegrationsStore = create<IntegrationsState>()(
  persist(
    (set, get) => ({
      items: DEFAULTS,
      connectedCount: INTEGRATION_DEFS.filter((d) => d.defaultStatus === "connected").length,
      connect: (id, config = {}) =>
        set((s) => {
          const item = s.items[id];
          const now = new Date();
          const fmt = (d: Date) => d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
          return {
            items: {
              ...s.items,
              [id]: {
                ...item,
                status: "connected",
                config: { ...item.config, ...config },
                health: 100,
                lastSync: fmt(now),
                nextSync: fmt(new Date(now.getTime() + 30 * 60000)),
                connectedAt: "Just now",
                logs: [
                  { id: `${id}-${Date.now()}`, time: fmt(now), message: "Connected · OAuth handshake complete", kind: "success" as const },
                  ...item.logs,
                ].slice(0, 8),
              },
            },
            connectedCount: Object.values(s.items).filter((i) => i.status === "connected").length + 1,
          };
        }),
      disconnect: (id) =>
        set((s) => ({
          items: {
            ...s.items,
            [id]: { ...s.items[id], status: "disconnected", health: 0, lastSync: "—", nextSync: "—", connectedAt: "" },
          },
          connectedCount: Math.max(0, s.connectedCount - (s.items[id].status === "connected" ? 1 : 0)),
        })),
      updateConfig: (id, patch) =>
        set((s) => ({
          items: { ...s.items, [id]: { ...s.items[id], config: { ...s.items[id].config, ...patch } } },
        })),
      setStatus: (id, status) =>
        set((s) => ({ items: { ...s.items, [id]: { ...s.items[id], status } } })),
          testConnection: (id) =>
        new Promise<boolean>((resolve) => {
          const REQUIRED: Record<string, string> = {
            slack: "channel",
            github: "repository",
            jira: "project",
            pagerduty: "routingKey",
            webhook: "url",
            smtp: "host",
          };
          const missing = REQUIRED[id] && !String(get().items[id].config[REQUIRED[id]] ?? "").trim();
          setTimeout(() => {
            if (missing) {
              get().addLog(id, "Test connection failed · missing required configuration", "error");
              resolve(false);
              return;
            }
            set((s) => ({
              items: {
                ...s.items,
                [id]: { ...s.items[id], health: 100, lastSync: new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }) },
              },
            }));
            get().addLog(id, "Test connection successful", "success");
            resolve(true);
          }, 1400);
        }),
      addLog: (id, message, kind = "info") =>
        set((s) => {
          const item = s.items[id];
          const time = new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" });
          return {
            items: {
              ...s.items,
              [id]: { ...item, logs: [{ id: `${id}-${Date.now()}`, time, message, kind }, ...item.logs].slice(0, 8) },
            },
          };
        }),
    }),
    { name: "aegivion-integrations" }
  )
);
