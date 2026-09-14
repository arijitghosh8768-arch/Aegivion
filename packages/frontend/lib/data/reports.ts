export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  audience: string;
  cadence: string;
  icon: "shield" | "chart" | "scale" | "radar";
  sections: string[];
  accent: string;
}

export const REPORT_TEMPLATES: ReportTemplate[] = [
  {
    id: "rt-1",
    name: "Executive Security Summary",
    description: "Board-ready summary of posture. Risk driven by AWS IAM and GCP public storage exposure.",
    audience: "CISO · Board",
    cadence: "Monthly",
    icon: "shield",
    sections: ["Cross-Cloud Risk Drivers", "Posture score & trend", "Critical findings summary", "Major incidents", "Compliance highlights", "Top 5 recommendations"],
    accent: "#6d5df6",
  },
  {
    id: "rt-2",
    name: "Security Posture Report",
    description: "Deep dive across all control families with per-provider breakdown.",
    audience: "Security Team",
    cadence: "Weekly",
    icon: "chart",
    sections: ["Asset inventory", "Findings by category", "IAM / network / data controls", "Provider health", "Remediation progress"],
    accent: "#4f7cf7",
  },
  {
    id: "rt-3",
    name: "Compliance Report",
    description: "Framework-by-framework evidence pack for auditors.",
    audience: "Auditors · Compliance",
    cadence: "Quarterly",
    icon: "scale",
    sections: ["SOC 2 · PCI DSS · CIS · HIPAA · NIST", "Control evidence links", "Exceptions & waivers", "POA&M register"],
    accent: "#c35df5",
  },
  {
    id: "rt-4",
    name: "Threat Intelligence Brief",
    description: "Correlated attack activity, MITRE ATT&CK coverage and predictions.",
    audience: "SOC · Threat Intel",
    cadence: "Daily",
    icon: "radar",
    sections: ["Active kill chains", "Alerts by tactic", "MITRE coverage map", "72-hour attack forecast"],
    accent: "#f59e0b",
  },
];

export const REPORT_HISTORY = [
  { id: "rh-1", name: "Executive Security Summary", date: "2026-08-01", format: "PDF", size: "2.4 MB", status: "ready", generatedBy: "AI Copilot" },
  { id: "rh-2", name: "Threat Intelligence Brief", date: "2026-08-03", format: "PDF", size: "1.1 MB", status: "ready", generatedBy: "AI Copilot" },
  { id: "rh-3", name: "Security Posture Report", date: "2026-07-28", format: "CSV", size: "860 KB", status: "ready", generatedBy: "Scheduled" },
  { id: "rh-4", name: "Compliance Report", date: "2026-07-01", format: "PDF", size: "4.7 MB", status: "ready", generatedBy: "Scheduled" },
];

// CSV rows generated from live module data
export const POSTURE_CSV_ROWS = [
  ["Provider", "Account", "Assets", "Findings", "Critical", "Health"],
  ["AWS", "prod-9823", "2841", "47", "3", "84"],
  ["AWS", "dev-1140", "862", "23", "0", "91"],
  ["AWS", "legacy-7755", "341", "38", "2", "61"],
  ["Azure", "prod-72b9", "1218", "29", "1", "86"],
  ["Azure", "shared-3c81", "204", "11", "0", "93"],
  ["GCP", "data-analytics", "774", "19", "1", "88"],
  ["GCP", "sandbox-4452", "96", "31", "2", "47"],
];
