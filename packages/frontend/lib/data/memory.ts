import type { IncidentMemory } from "@/lib/types";

export const INCIDENTS: IncidentMemory[] = [
  {
    id: "m-1",
    title: "Public S3 bucket exposed 1.2M customer records",
    date: "2026-04-14T03:20:00Z",
    outcome: "Contained in 6h 40m",
    summary:
      "A legacy analytics bucket 'acme-raw-export' was left with a public-read ACL. Marketing automation leaked the bucket name in a public dashboard config. 1.2M records containing PII were indexed by search engines before discovery.",
    patterns: ["Public ACL introduced by legacy deployment script", "Bucket name leaked in config files", "No public access block applied"],
    repeated: true,
    severity: "critical",
    durationHrs: 6.7,
    affected: 1200000,
  },
  {
    id: "m-2",
    title: "SSH brute-force against bastion fleet",
    date: "2026-05-02T22:10:00Z",
    outcome: "Automatically blocked in 11m",
    summary:
      "Coordinated SSH brute force from 3,400 IPs targeted the bastion fleet. Aegivion's anomaly engine flagged the pattern and enforced IP-throttling rules; no instance was compromised.",
    patterns: ["Security groups allowed SSH from 0.0.0.0/0", "No fail2ban equivalent in place"],
    repeated: false,
    severity: "high",
    durationHrs: 0.18,
    affected: 0,
  },
  {
    id: "m-3",
    title: "Crypto-miner deployed on EKS 'core-prod'",
    date: "2026-06-21T13:05:00Z",
    outcome: "Contained in 2h 15m",
    summary:
      "An attacker exploited a public-facing dashboard pod with hostPath mounts, then deployed a miner image. High CPU on 4 nodes triggered Aegivion's resource-anomaly detection.",
    patterns: ["Privileged container without securityContext", "hostPath mounts in production", "Public ingress on management dashboard"],
    repeated: true,
    severity: "high",
    durationHrs: 2.25,
    affected: 4,
  },
  {
    id: "m-4",
    title: "CloudTrail paused before credential rotation",
    date: "2026-07-19T18:44:00Z",
    outcome: "Resolved — keys rotated, logging restored",
    summary:
      "An operator with admin rights paused CloudTrail during an incident, temporarily blinding detection. Aegivion's watchdog detected the gap in 4 minutes and restored logging.",
    patterns: ["Operators can disable logging without approval", "Log integrity validation disabled"],
    repeated: false,
    severity: "medium",
    durationHrs: 0.07,
    affected: 0,
  },
];

export const LEARNED_PATTERNS = [
  {
    id: "lp-1",
    pattern: "Buckets referenced in public configs get read from within 72h",
    confidence: 91,
    firstSeen: "Apr 2026",
    occurrences: 3,
    action: "Auto-applies Public Access Block to any bucket whose name appears in scanned public repos.",
  },
  {
    id: "lp-2",
    pattern: "New admin IAM users follow exposed-key incidents by <15 minutes",
    confidence: 88,
    firstSeen: "Apr 2026",
    occurrences: 2,
    action: "Raises any CreateUser+AttachAdminPolicy sequence to critical and pages on-call.",
  },
  {
    id: "lp-3",
    pattern: "Mining workloads spike CPU > 92% for 6+ minutes on k8s",
    confidence: 94,
    firstSeen: "Jun 2026",
    occurrences: 4,
    action: "Pre-built YAML quarantine applies taint + cordon on matching pods.",
  },
  {
    id: "lp-4",
    pattern: "Logging pauses precede data exfiltration by ~22 minutes",
    confidence: 84,
    firstSeen: "Jul 2026",
    occurrences: 2,
    action: "Triggers write-only log replica in secondary region and alerts SOC.",
  },
];

export const REPEATED_MISTAKES = [
  { mistake: "Public ACLs on S3/GCS buckets from legacy scripts", count: 3, first: "Apr 2026", last: "Aug 2026", status: "mitigating" },
  { mistake: "Privileged containers with hostPath in prod clusters", count: 2, first: "Jun 2026", last: "Jul 2026", status: "mitigating" },
  { mistake: "SSH/RDP open to 0.0.0.0/0 on internet-facing groups", count: 5, first: "Feb 2026", last: "Aug 2026", status: "recurring" },
  { mistake: "Long-lived access keys without rotation", count: 4, first: "Mar 2026", last: "Aug 2026", status: "recurring" },
];

export const MEMORY_TREND = [
  { month: "Mar", incidents: 9, repeatRate: 44 },
  { month: "Apr", incidents: 7, repeatRate: 43 },
  { month: "May", incidents: 5, repeatRate: 40 },
  { month: "Jun", incidents: 6, repeatRate: 33 },
  { month: "Jul", incidents: 4, repeatRate: 25 },
  { month: "Aug", incidents: 3, repeatRate: 33 },
];
