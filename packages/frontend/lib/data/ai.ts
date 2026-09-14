export interface AiBlock {
  type: "text" | "list" | "code" | "heading" | "badge";
  content?: string;
  items?: string[];
}

export interface AiResponse {
  blocks: AiBlock[];
  sources: string[];
  latencyMs: number;
}

const SUGGESTIONS = [
  "Why is this EC2 risky?",
  "Explain today's attack chain",
  "Show all public buckets",
  "Generate remediation for f-101",
  "Generate an executive report",
  "What is my current security posture?",
];

export function getSuggestions(): string[] {
  return SUGGESTIONS;
}

export function answer(prompt: string): AiResponse {
  const p = prompt.toLowerCase();

  if (p.includes("ec2") || p.includes("instance") || p.includes("web-prod")) {
    return {
      blocks: [
        { type: "heading", content: "Why web-prod-1 is risky" },
        {
          type: "text",
          content:
            "web-prod-1 (i-0f2c9a31b8d4e7a12) carries a risk score of 82/100. Three factors drive the score:",
        },
        {
          type: "list",
          items: [
            "Security group sg-web-lb allows SSH from 0.0.0.0/0 — reachable for brute force (T1190)",
            "Instance profile references ci-deploy-role, which holds AdministratorAccess",
            "osquery telemetry shows a kernel past EOL with 14 unpatched critical CVEs",
          ],
        },
        {
          type: "text",
          content:
            "Recommendation: revoke the 0.0.0.0/0 SSH rule, swap the instance profile for a scoped role, and schedule an AMI refresh. Estimated risk reduction: 34 points.",
        },
      ],
      sources: ["Finding f-103", "Finding f-102", "Asset a-001", "CVE-2023-4911"],
      latencyMs: 812,
    };
  }

  if (p.includes("attack") || p.includes("today") || p.includes("chain") || p.includes("incident")) {
    return {
      blocks: [
        { type: "heading", content: "Today's correlated attack chain" },
        {
          type: "text",
          content:
            "Aegivion correlated 4 alerts into a single kill chain beginning at 05:41 UTC. Chain ID: CH-2026-08-04-01.",
        },
        {
          type: "list",
          items: [
            "05:41 — Initial Access: IAM keys for ci-deploy-role leaked on GitHub (T1078.004)",
            "05:47 — Persistence: backdoor user support-dmz created with AdministratorAccess (T1136.003)",
            "05:52 — Defense Evasion: CloudTrail paused in legacy account (T1562.008)",
            "05:58 — Exfiltration: 42 GB staged from prod-customer-data to ap-southeast-1 (T1567.002)",
          ],
        },
        {
          type: "text",
          content:
            "The exfiltration target bucket 'backup-7f3a' has been quarantined and the source credential revoked. Two recommended follow-ups: rotate ci-deploy-role keys and force MFA on the legacy root account.",
        },
      ],
      sources: ["Alert al-501", "Alert al-502", "Alert al-503", "Alert al-505"],
      latencyMs: 1240,
    };
  }

  if (p.includes("bucket") || p.includes("public") || p.includes("expos")) {
    return {
      blocks: [
        { type: "heading", content: "Publicly exposed buckets" },
        { type: "text", content: "Found 3 storage buckets currently reachable from the internet:" },
        {
          type: "list",
          items: [
            "s3://prod-customer-data (AWS) — public-read, 1.2M sensitive records — CRITICAL",
            "hr-records-store (Azure Storage) — anonymous blob access enabled — HIGH",
            "gs-analytics-raw (GCP) — uniform access off, 8 objects public — MEDIUM",
          ],
        },
        {
          type: "text",
          content:
            "I can auto-generate remediation for all three now — one-click Terraform plans are staged in the Remediation queue.",
        },
      ],
      sources: ["Finding f-101", "Finding f-107", "Asset a-019"],
      latencyMs: 640,
    };
  }

  if (p.includes("remedi") || p.includes("fix") || p.includes("terraform")) {
    return {
      blocks: [
        { type: "heading", content: "Remediation plan for f-101" },
        {
          type: "text",
          content:
            "Generated plan RP-101-3 for 'S3 bucket prod-customer-data is publicly readable'. Impact: low · ETA: 4 minutes · Rollback: available.",
        },
        { type: "code", content: `resource "aws_s3_bucket_public_access_block" "prod_customer_data" {
  bucket                  = aws_s3_bucket.prod_customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}` },
        {
          type: "text",
          content:
            "Approve this plan from the Remediation page and Aegivion will apply it via the CI pipeline with automatic rollback on drift. 3 other plans are queued behind it.",
        },
      ],
      sources: ["Finding f-101", "Remediation plan RP-101-3"],
      latencyMs: 1550,
    };
  }

  if (p.includes("report") || p.includes("executive")) {
    return {
      blocks: [
        { type: "heading", content: "Executive report ready" },
        {
          type: "text",
          content:
            "I prepared an executive summary for the last 30 days: security score improved from 46 → 72, 2 critical findings remediated, 1 major incident contained (key leak → exfiltration).",
        },
        {
          type: "list",
          items: [
            "Risk reduction: -38% critical findings",
            "Compliance: SOC 2 95% (+1.4pts), PCI 91% (+0.8pts)",
            "Attack surface reduced by 11% (ports closed on 214 instances)",
            "MTTR improved from 6.7h → 1.2h",
          ],
        },
        {
          type: "text",
          content:
            "Open the Reports page and choose 'Executive Report' to export the full PDF or CSV.",
        },
      ],
      sources: ["Reports module", "Compliance module"],
      latencyMs: 980,
    };
  }

  if (p.includes("score") || p.includes("posture") || p.includes("compliance") || p.includes("status")) {
    return {
      blocks: [
        { type: "heading", content: "Current security posture" },
        {
          type: "text",
          content:
            "Aggregate posture score: 72/100 (Good). Trend: +4.6 points over 14 days.",
        },
        {
          type: "list",
          items: [
            "7 cloud accounts · 9,182 assets · 1,240 findings (8 critical)",
            "SOC 2: 95% · PCI DSS: 91% · CIS AWS: 70% (below target)",
            "Active threats: 3 · Highest probability: credential-based access (58% in 72h)",
            "Attack surface: 214 exposed ports, down 11% in 30 days",
          ],
        },
        {
          type: "text",
          content:
            "Weakest control family is 'Access Management' (IAM) — 41% of open findings. Recommend prioritizing the 5 auto-fixable IAM items in the queue.",
        },
      ],
      sources: ["Dashboard module", "Compliance module", "Prediction module"],
      latencyMs: 720,
    };
  }

  return {
    blocks: [
      { type: "heading", content: "Here's what I found" },
      {
        type: "text",
        content:
          "I can answer questions about your cloud posture, explain findings, correlate threat activity, and generate remediation. Try asking about a specific asset, today's attacks, public buckets, or request a report.",
      },
      {
        type: "list",
        items: getSuggestions().slice(0, 4),
      },
    ],
    sources: ["Aegivion knowledge base"],
    latencyMs: 480,
  };
}
