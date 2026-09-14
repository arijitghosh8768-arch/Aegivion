"use client";

import { useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { Workflow, Zap, ShieldCheck, Clock3, ArrowRight, Play, Pause, Wrench } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

interface Rule {
  id: string;
  name: string;
  desc: string;
  trigger: string;
  action: string;
  runs: number;
  lastRun: string;
  enabled: boolean;
  target: string;
  accent: string;
}

const INITIAL_RULES: Rule[] = [
  {
    id: "r-1",
    name: "Auto-quarantine public S3 buckets",
    desc: "When a bucket policy becomes public, immediately block public ACLs and alert the data owner.",
    trigger: "S3 bucket · public-read",
    action: "Apply public access block",
    runs: 14,
    lastRun: "18m ago",
    enabled: true,
    target: "/remediation",
    accent: "bg-destructive/12 text-destructive",
  },
  {
    id: "r-2",
    name: "Revoke leaked IAM keys",
    desc: "On secret-scanner match, disable the access key, notify the owner and stage a rotation plan.",
    trigger: "GitHub secret scan · AKIA key",
    action: "Disable access key + stage rotation",
    runs: 6,
    lastRun: "1h ago",
    enabled: true,
    target: "/remediation",
    accent: "bg-warning/15 text-warning",
  },
  {
    id: "r-3",
    name: "Close internet-exposed SSH",
    desc: "Revoke 0.0.0.0/0 ingress on port 22 and replace with the corporate CIDR range.",
    trigger: "Security group · tcp/22 0.0.0.0/0",
    action: "Rewrite ingress rule",
    runs: 9,
    lastRun: "3h ago",
    enabled: true,
    target: "/detection-engine",
    accent: "bg-info/12 text-info",
  },
  {
    id: "r-4",
    name: "Re-enable disabled CloudTrail",
    desc: "Watchdog restores logging within 5 minutes of a StopLogging call on any trail.",
    trigger: "CloudTrail · StopLogging",
    action: "Restart trail + audit log",
    runs: 3,
    lastRun: "1d ago",
    enabled: true,
    target: "/security-memory",
    accent: "bg-brand-purple/12 text-brand-purple",
  },
  {
    id: "r-5",
    name: "Nightly compliance snapshot",
    desc: "Run a full CIS/SOC2 sweep at 02:00 UTC and post the delta to the Reports workspace.",
    trigger: "Schedule · 02:00 UTC",
    action: "Generate compliance snapshot",
    runs: 112,
    lastRun: "11h ago",
    enabled: true,
    target: "/reports",
    accent: "bg-success/12 text-success",
  },
  {
    id: "r-6",
    name: "Auto-suspend dormant admin users",
    desc: "Flag and suspend admin identities with no activity for 30+ days. Requires manual re-activation.",
    trigger: "IAM · 30d inactive admin",
    action: "Suspend identity + notify",
    runs: 2,
    lastRun: "2d ago",
    enabled: false,
    target: "/identities",
    accent: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  },
];

export default function AutomationPage() {
  const [rules, setRules] = useState(INITIAL_RULES);
  const [allPaused, setAllPaused] = useState(false);

  const toggle = (id: string) => setRules((rs) => rs.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)));
  const toggleAll = () => {
    setAllPaused((p) => !p);
    setRules((rs) => rs.map((r) => ({ ...r, enabled: !allPaused })));
  };

  const enabled = rules.filter((r) => r.enabled).length;
  const totalRuns = rules.reduce((s, r) => s + r.runs, 0);

  return (
    <div>
      <PageHeader
        title="Automation"
        description="Self-healing runbooks that remediate known issues without human intervention — every action is logged."
      >
        <Button variant="outline" onClick={toggleAll}>
          {allPaused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
          {allPaused ? "Resume all" : "Pause all"}
        </Button>
        <Button variant="gradient" asChild>
          <Link href="/remediation">
            <Wrench className="h-4 w-4" /> Remediation queue
          </Link>
        </Button>
      </PageHeader>

      {/* summary */}
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Active runbooks", value: enabled, tint: "text-success" },
          { label: "Total rules", value: rules.length },
          { label: "Executions (30d)", value: totalRuns, tint: "text-primary" },
          { label: "Auto-resolved", value: "128", tint: "text-success" },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="rounded-2xl border border-border bg-card p-4 shadow-soft"
          >
            <div className="text-[11px] font-medium text-muted-foreground">{s.label}</div>
            <div className={cn("mt-1 text-2xl font-bold tracking-tight tabular-nums", s.tint)}>{s.value}</div>
          </motion.div>
        ))}
      </div>

      {/* rules */}
      <div className="space-y-3">
        {rules.map((r, i) => (
          <motion.div
            key={r.id}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.04 }}
            className={cn(
              "rounded-2xl border bg-card p-4 shadow-soft transition-colors",
              r.enabled ? "border-border" : "border-border/60 opacity-70"
            )}
          >
            <div className="flex flex-wrap items-center gap-3">
              <span className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-xl", r.accent)}>
                {r.enabled ? <Zap className="h-4.5 w-4.5" /> : <Workflow className="h-4.5 w-4.5" />}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-[13.5px] font-semibold">{r.name}</span>
                  {!r.enabled && <Badge variant="soft">Paused</Badge>}
                </div>
                <p className="mt-0.5 line-clamp-1 text-[11.5px] text-muted-foreground">{r.desc}</p>
              </div>
              <div className="hidden items-center gap-4 md:flex">
                <div className="text-right">
                  <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Trigger</div>
                  <div className="text-[11.5px] font-medium">{r.trigger}</div>
                </div>
                <div className="text-right">
                  <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Action</div>
                  <div className="text-[11.5px] font-medium">{r.action}</div>
                </div>
                <div className="text-right">
                  <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Runs</div>
                  <div className="text-[11.5px] font-medium tabular-nums">{r.runs}</div>
                </div>
              </div>
              <Switch checked={r.enabled} onCheckedChange={() => toggle(r.id)} aria-label={`Toggle ${r.name}`} />
            </div>
            <div className="mt-3 flex items-center gap-3 border-t border-border/60 pt-2.5 text-[10.5px] text-muted-foreground">
              <Clock3 className="h-3 w-3" /> Last run {r.lastRun}
              <Link href={r.target} className="ml-auto flex items-center gap-0.5 font-semibold text-primary transition hover:gap-1.5">
                View related <ArrowRight className="h-3 w-3" />
              </Link>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="mt-6 flex items-start gap-2.5 rounded-2xl border border-success/25 bg-success/8 p-4">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-success" />
        <p className="text-[12px] leading-relaxed text-muted-foreground">
          <span className="font-semibold text-foreground">Guardrails:</span> runbooks only execute write actions through
          your CI/CD identity, run in canary mode first, and every change ships with an automatic rollback plan. See the{" "}
          <Link href="/settings" className="font-semibold text-primary hover:underline">
            Settings
          </Link>{" "}
          page to manage approval policies.
        </p>
      </div>
    </div>
  );
}
