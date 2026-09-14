import type { ComplianceFramework } from "@/lib/types";

export const COMPLIANCE_FRAMEWORKS: ComplianceFramework[] = [
  { id: "cf-1", name: "SOC 2 Type II", short: "SOC2", passed: 58, total: 61, score: 95, trend: 1.4, status: "pass" },
  { id: "cf-2", name: "CIS AWS Foundations v3.0", short: "CIS AWS", passed: 92, total: 132, score: 70, trend: -2.1, status: "attention" },
  { id: "cf-3", name: "PCI DSS 4.0", short: "PCI", passed: 178, total: 196, score: 91, trend: 0.8, status: "pass" },
  { id: "cf-4", name: "HIPAA Security Rule", short: "HIPAA", passed: 44, total: 49, score: 90, trend: 1.1, status: "pass" },
  { id: "cf-5", name: "NIST SP 800-53 Rev5", short: "NIST", passed: 211, total: 264, score: 80, trend: -0.6, status: "attention" },
  { id: "cf-6", name: "ISO 27001:2022", short: "ISO", passed: 89, total: 93, score: 96, trend: 0.4, status: "pass" },
  { id: "cf-7", name: "CIS GCP Foundation Benchmark v2.0", short: "CIS GCP", passed: 48, total: 50, score: 96, trend: -1.2, status: "attention" },
];
export const COMPLIANCE_TREND = [
  { week: "W1", soc2: 89, cis: 63, pci: 84, nist: 74 },
  { week: "W2", soc2: 90, cis: 64, pci: 85, nist: 75 },
  { week: "W3", soc2: 91, cis: 66, pci: 86, nist: 76 },
  { week: "W4", soc2: 91, cis: 65, pci: 87, nist: 76 },
  { week: "W5", soc2: 92, cis: 67, pci: 88, nist: 77 },
  { week: "W6", soc2: 93, cis: 68, pci: 88, nist: 78 },
  { week: "W7", soc2: 93, cis: 69, pci: 89, nist: 78 },
  { week: "W8", soc2: 94, cis: 71, pci: 90, nist: 79 },
  { week: "W9", soc2: 94, cis: 70, pci: 90, nist: 79 },
  { week: "W10", soc2: 95, cis: 72, pci: 91, nist: 80 },
  { week: "W11", soc2: 95, cis: 72, pci: 91, nist: 80 },
  { week: "W12", soc2: 95, cis: 70, pci: 91, nist: 80 },
];

export const RISK_TREND = [
  { day: "Jul 06", score: 62, critical: 6, high: 21 },
  { day: "Jul 08", score: 58, critical: 5, high: 19 },
  { day: "Jul 10", score: 60, critical: 5, high: 20 },
  { day: "Jul 12", score: 55, critical: 4, high: 18 },
  { day: "Jul 14", score: 52, critical: 4, high: 17 },
  { day: "Jul 16", score: 54, critical: 4, high: 18 },
  { day: "Jul 18", score: 49, critical: 3, high: 16 },
  { day: "Jul 20", score: 51, critical: 3, high: 17 },
  { day: "Jul 22", score: 47, critical: 3, high: 15 },
  { day: "Jul 24", score: 49, critical: 3, high: 16 },
  { day: "Jul 26", score: 45, critical: 2, high: 14 },
  { day: "Jul 28", score: 47, critical: 2, high: 15 },
  { day: "Jul 30", score: 44, critical: 2, high: 13 },
  { day: "Aug 01", score: 46, critical: 3, high: 14 },
  { day: "Aug 03", score: 42, critical: 2, high: 12 },
];

export const THREAT_TIMELINE = [
  { time: "00:00", severity: 1 },
  { time: "01:00", severity: 2 },
  { time: "02:00", severity: 1 },
  { time: "03:00", severity: 3 },
  { time: "04:00", severity: 4 },
  { time: "05:00", severity: 8 },
  { time: "06:00", severity: 5 },
  { time: "07:00", severity: 3 },
  { time: "08:00", severity: 2 },
  { time: "09:00", severity: 4 },
  { time: "10:00", severity: 3 },
  { time: "11:00", severity: 2 },
  { time: "12:00", severity: 5 },
  { time: "13:00", severity: 4 },
  { time: "14:00", severity: 6 },
  { time: "15:00", severity: 3 },
  { time: "16:00", severity: 2 },
  { time: "17:00", severity: 1 },
  { time: "18:00", severity: 2 },
  { time: "19:00", severity: 3 },
  { time: "20:00", severity: 5 },
  { time: "21:00", severity: 7 },
  { time: "22:00", severity: 9 },
  { time: "23:00", severity: 6 },
];

/* ----------------------------- Prediction ------------------------------ */

export const FORECAST = [
  { day: "Aug 04", probability: 42, low: 30, high: 58 },
  { day: "Aug 05", probability: 48, low: 34, high: 64 },
  { day: "Aug 06", probability: 51, low: 38, high: 67 },
  { day: "Aug 07", probability: 47, low: 33, high: 62 },
  { day: "Aug 08", probability: 55, low: 41, high: 71 },
  { day: "Aug 09", probability: 58, low: 44, high: 74 },
  { day: "Aug 10", probability: 53, low: 39, high: 68 },
  { day: "Aug 11", probability: 49, low: 35, high: 64 },
  { day: "Aug 12", probability: 61, low: 47, high: 77 },
  { day: "Aug 13", probability: 64, low: 50, high: 79 },
  { day: "Aug 14", probability: 57, low: 43, high: 72 },
  { day: "Aug 15", probability: 52, low: 38, high: 66 },
  { day: "Aug 16", probability: 59, low: 45, high: 74 },
  { day: "Aug 17", probability: 63, low: 49, high: 78 },
];

// Attack likelihood heatmap: 7 days x 24 hours, values 0..1
export function buildHeatmap(): number[][] {
  const rows: number[][] = [];
  for (let d = 0; d < 7; d++) {
    const row: number[] = [];
    for (let h = 0; h < 24; h++) {
      const night = h >= 20 || h <= 5 ? 0.35 : 0;
      const burst = (h === 21 || h === 22) && (d === 3 || d === 6) ? 0.3 : 0;
      const wave = 0.18 * Math.sin((h + d * 2) / 3.2);
      const noise = ((d * 13 + h * 7) % 11) / 60;
      const v = Math.min(0.98, Math.max(0.04, night + burst + 0.38 + wave + noise));
      row.push(Math.round(v * 100) / 100);
    }
    rows.push(row);
  }
  return rows;
}

export const HEATMAP_DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export const LIKELIHOOD_FACTORS = [
  { factor: "Exposed credentials on public repos", weight: 0.32, trend: "+18%" },
  { factor: "Internet-reachable management ports", weight: 0.24, trend: "-6%" },
  { factor: "Unpatched critical CVEs", weight: 0.18, trend: "+4%" },
  { factor: "Oversized IAM permissions", weight: 0.14, trend: "-11%" },
  { factor: "Weak MFA coverage (legacy accounts)", weight: 0.12, trend: "+9%" },
];
