import {
  LayoutGrid,
  Sparkles,
  Network,
  TriangleAlert,
  Boxes,
  UserRound,
  FileCheck2,
  FileBarChart,
  Workflow,
  Settings,
  Radar,
  Share2,
  TrendingUp,
  Wrench,
  History,
  Cloud,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  title: string;
  href: string;
  icon: LucideIcon;
  badge?: string;
}

export interface NavSection {
  label: string;
  items: NavItem[];
}

/** Primary navigation — matches the Aegivion dashboard sidebar. */
export const NAV_SECTIONS: NavSection[] = [
  {
    label: "Overview",
    items: [
      { title: "Command Center", href: "/", icon: LayoutGrid },
      { title: "AI Copilot", href: "/ai-copilot", icon: Sparkles },
      { title: "Cloud Topology", href: "/cloud-topology", icon: Network },
    ],
  },
  {
    label: "Security",
    items: [
      { title: "Threats", href: "/threats", icon: TriangleAlert, badge: "3" },
      { title: "Detection Engine", href: "/detection-engine", icon: Radar },
      { title: "Threat Correlation", href: "/threat-correlation", icon: Share2 },
      { title: "Prediction", href: "/prediction", icon: TrendingUp },
    ],
  },
  {
    label: "Cloud",
    items: [
      { title: "Assets", href: "/assets", icon: Boxes },
      { title: "Identities", href: "/identities", icon: UserRound },
      { title: "Compliance", href: "/compliance", icon: FileCheck2 },
      { title: "Cloud Accounts", href: "/cloud-accounts", icon: Cloud },
    ],
  },
  {
    label: "Response",
    items: [
      { title: "Remediation", href: "/remediation", icon: Wrench, badge: "5" },
      { title: "Security Memory", href: "/security-memory", icon: History },
    ],
  },
  {
    label: "Insights",
    items: [
      { title: "Reports", href: "/reports", icon: FileBarChart },
      { title: "Automation", href: "/automation", icon: Workflow },
    ],
  },
  {
    label: "Admin",
    items: [{ title: "Settings", href: "/settings", icon: Settings }],
  },
];

export const PAGE_TITLES: Record<string, string> = {
  "/": "Command Center",
  "/ai-copilot": "AI Copilot",
  "/cloud-topology": "Cloud Topology",
  "/threats": "Threats",
  "/assets": "Assets",
  "/identities": "Identities",
  "/compliance": "Compliance",
  "/reports": "Reports",
  "/automation": "Automation",
  "/settings": "Settings",
  "/cloud-accounts": "Cloud Accounts",
  "/detection-engine": "Detection Engine",
  "/threat-correlation": "Threat Correlation",
  "/prediction": "Prediction",
  "/remediation": "Remediation",
  "/security-memory": "Security Memory",
};
