import type { ProviderId } from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Command Center stats — matches the Aegivion dashboard exactly        */
/* ------------------------------------------------------------------ */

export const COMMAND_STATS = [
  {
    id: "assets",
    label: "Total Assets",
    value: 0,
    format: "plain",
    subtitle: "Across 3 Clouds",
    icon: "cube" as const,
    tint: "bg-brand-purple/10 text-brand-purple",
    glow: "from-brand-purple/15",
  },
  {
    id: "critical",
    label: "Critical Risks",
    value: 0,
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
    value: 0,
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
  { day: "May 06", score: 0 },
  { day: "May 07", score: 0 },
  { day: "May 08", score: 0 },
  { day: "May 09", score: 0 },
  { day: "May 10", score: 0 },
  { day: "May 11", score: 0 },
  { day: "May 12", score: 0 },
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

export const LIVE_THREATS: LiveThreatItem[] = [];

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

export const TOP_RISKY_ASSETS: RiskyAsset[] = [];

/* ------------------------------------------------------------------ */
/* AI security insight                                                 */
/* ------------------------------------------------------------------ */

export const AI_INSIGHT = {
  messageBefore: "All systems operational. No critical misconfigurations found.",
  messageHighlight: "",
  riskLevel: "Safe",
  riskBars: 0, // of 6 filled
  totalBars: 6,
};
