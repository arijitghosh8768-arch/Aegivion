import type { ProviderId } from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Command Center stats — matches the Aegivion dashboard exactly        */
/* ------------------------------------------------------------------ */

export const COMMAND_STATS = [
  {
    id: "assets",
    label: "Total Assets",
    value: 32,
    format: "plain",
    subtitle: "Across 3 Clouds",
    icon: "cube" as const,
    tint: "bg-brand-purple/10 text-brand-purple",
    glow: "from-brand-purple/15",
  },
  {
    id: "critical",
    label: "Critical Risks",
    value: 2,
    format: "plain",
    subtitle: "Immediate attention",
    subtitleTint: "text-destructive",
    icon: "crosshair" as const,
    tint: "bg-destructive/10 text-destructive",
    glow: "from-destructive/15",
  },
  {
    id: "compliance",
    label: "Compliance",
    value: 75,
    format: "pct",
    subtitle: "6/8 Compliant",
    subtitleTint: "text-info",
    icon: "file-check" as const,
    tint: "bg-info/10 text-info",
    glow: "from-info/15",
  },
  {
    id: "surface",
    label: "Attack Surface",
    value: 0,
    format: "low",
    subtitle: "Exposure level",
    subtitleTint: "text-success",
    icon: "globe" as const,
    tint: "bg-brand-blue/10 text-brand-blue",
    glow: "from-brand-blue/15",
  },
];

/* ------------------------------------------------------------------ */
/* Risk trend — last 7 days (May 06 → May 12)                          */
/* ------------------------------------------------------------------ */

export const RISK_TREND_7D = [
  { day: "May 06", score: 55 },
  { day: "May 07", score: 68 },
  { day: "May 08", score: 48 },
  { day: "May 09", score: 51 },
  { day: "May 10", score: 85 },
  { day: "May 11", score: 70 },
  { day: "May 12", score: 71 },
];

/* ------------------------------------------------------------------ */
/* Live threat feed                                                    */
/* ------------------------------------------------------------------ */

export interface LiveThreatItem {
  id: string;
  title: string;
  scope: string;
  time: string;
  level: "critical" | "layers" | "network" | "info";
}

export const LIVE_THREATS: LiveThreatItem[] = [
  {
    id: "lt-1",
    title: "IAM role over-privilege detected",
    scope: "AWS Production",
    time: "2m ago",
    level: "critical",
  },
  {
    id: "lt-2",
    title: "Unusual API activity",
    scope: "Azure Environment",
    time: "5m ago",
    level: "layers",
  },
  {
    id: "lt-3",
    title: "Security group - open SSH",
    scope: "GCP VPC Network",
    time: "8m ago",
    level: "network",
  },
  {
    id: "lt-4",
    title: "Root login attempt",
    scope: "AWS Production",
    time: "12m ago",
    level: "info",
  },
];

/* ------------------------------------------------------------------ */
/* Top risky assets                                                    */
/* ------------------------------------------------------------------ */

export interface RiskyAsset {
  id: string;
  title: string;
  scope: string;
  badge: "Critical" | "High" | "Medium" | "Low";
  score: number;
  provider: ProviderId;
  kind: "bucket" | "user" | "group" | "vm";
}

export const TOP_RISKY_ASSETS: RiskyAsset[] = [
  {
    id: "ra-1",
    title: "S3 bucket - public access",
    scope: "AWS Production",
    badge: "Critical",
    score: 90,
    provider: "aws",
    kind: "bucket",
  },
  {
    id: "ra-2",
    title: "IAM user without MFA",
    scope: "AWS Production",
    badge: "High",
    score: 75,
    provider: "aws",
    kind: "user",
  },
  {
    id: "ra-3",
    title: "Security group - open SSH",
    scope: "Azure Environment",
    badge: "High",
    score: 65,
    provider: "azure",
    kind: "group",
  },
  {
    id: "ra-4",
    title: "Public VM with sensitive data",
    scope: "GCP Project",
    badge: "Medium",
    score: 45,
    provider: "gcp",
    kind: "vm",
  },
];

/* ------------------------------------------------------------------ */
/* AI security insight                                                 */
/* ------------------------------------------------------------------ */

export const AI_INSIGHT = {
  messageBefore: "I've analyzed your environment and found 1 critical misconfiguration in ",
  messageHighlight: "AWS S3 bucket policy.",
  riskLevel: "High",
  riskBars: 4, // of 6 filled
  totalBars: 6,
};
