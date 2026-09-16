"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Wrench, Check, X, Loader2, RotateCcw, ChevronDown, ChevronUp, ShieldCheck } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { SeverityBadge, StatusPill } from "@/components/shared/severity";
import { ProviderMark } from "@/components/shared/provider-mark";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Finding } from "@/lib/types";

type PlanStatus = "pending" | "approved" | "rejected" | "applied" | "failed";

interface Plan {
  finding: Finding;
  status: PlanStatus;
  applying: boolean;
}

const IMPACT: Record<Finding["severity"], { impact: string; eta: number; risk: string }> = {
  critical: { impact: "medium", eta: 4, risk: "low" },
  high: { impact: "low", eta: 6, risk: "low" },
  medium: { impact: "low", eta: 9, risk: "low" },
  low: { impact: "low", eta: 12, risk: "low" },
  info: { impact: "low", eta: 15, risk: "low" },
};

export default function RemediationPage() {
  const [plans, setPlans] = useState<Plan[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    async function fetchPlans() {
      try {
        const res = await fetch("/api/v1/findings?status=remediating");
        if (res.ok) {
          const data = await res.json();
          setPlans(data || []);
        }
      } catch (e) {
      } finally {
        setLoading(false);
      }
    }
    fetchPlans();
  }, []);
  const [runAll, setRunAll] = useState(false);

  const pending = plans.filter((p) => p.status === "pending").length;
  const approved = plans.filter((p) => p.status === "approved").length;

  const setStatus = (id: string, status: PlanStatus) =>
    setPlans((ps) => ps.map((p) => (p.finding.id === id ? { ...p, status } : p)));

  const apply = (id: string) => {
    setPlans((ps) => ps.map((p) => (p.finding.id === id ? { ...p, applying: true } : p)));
    setTimeout(() => {
      setPlans((ps) => ps.map((p) => (p.finding.id === id ? { ...p, applying: false, status: "applied" } : p)));
    }, 2200);
  };

  const applyAll = () => {
    setRunAll(true);
    const ids = plans.filter((p) => p.status === "approved").map((p) => p.finding.id);
    ids.forEach((id, i) => setTimeout(() => apply(id), i * 900));
    setTimeout(() => setRunAll(false), ids.length * 900 + 2400);
  };

  return (
    <div>
      <PageHeader
        title="Remediation"
        description="AI-generated fixes with Terraform, CLI and rollback plans — approved changes are applied via your CI pipeline."
      >
        <Button variant="outline">
          <RotateCcw className="h-4 w-4" /> Rollback log
        </Button>
        <Button variant="gradient" onClick={applyAll} disabled={approved === 0 || runAll}>
          {runAll ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Applying queue…
            </>
          ) : (
            <>
              <Wrench className="h-4 w-4" /> Apply approved ({approved})
            </>
          )}
        </Button>
      </PageHeader>

      {/* summary */}
      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Pending approval", value: pending, tint: "text-warning" },
          { label: "Approved", value: approved, tint: "text-info" },
          { label: "Applied", value: plans.filter((p) => p.status === "applied").length, tint: "text-success" },
          { label: "Rejected", value: plans.filter((p) => p.status === "rejected").length },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="rounded-2xl border border-border bg-card p-4 shadow-soft"
          >
            <div className="text-xs font-medium text-muted-foreground">{s.label}</div>
            <div className={cn("mt-1 text-2xl font-bold tabular-nums tracking-tight", s.tint)}>{s.value}</div>
          </motion.div>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-12"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
      ) : plans.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-border py-12 text-center bg-card">
          <Wrench className="mb-3 h-8 w-8 text-muted-foreground" />
          <h3 className="text-[14px] font-semibold">No data yet</h3>
          <p className="mt-1 text-[12.5px] text-muted-foreground">There are no pending remediations at this time.</p>
        </div>
      ) : (
        <div className="space-y-3">
        {plans.map((plan: any, i: number) => {
          const f = plan.finding;
          const meta = IMPACT[f.severity as keyof typeof IMPACT] || IMPACT["low"];
          const isOpen = expanded === f.id;
          return (
            <motion.div
              key={f.id}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.04 }}
              className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft"
            >
              <div className="flex items-center gap-3 px-4 py-3.5">
                <span
                  className={cn(
                    "flex h-8 w-8 shrink-0 items-center justify-center rounded-xl",
                    plan.status === "applied"
                      ? "bg-success/12 text-success"
                      : plan.status === "rejected"
                        ? "bg-muted text-muted-foreground"
                        : "bg-primary/10 text-primary"
                  )}
                >
                  {plan.status === "applied" ? <ShieldCheck className="h-4 w-4" /> : <Wrench className="h-4 w-4" />}
                </span>
                <button onClick={() => setExpanded(isOpen ? null : f.id)} className="min-w-0 flex-1 cursor-pointer text-left">
                  <div className="truncate text-sm font-semibold">{f.title}</div>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-muted-foreground">
                    <ProviderMark provider={f.provider} size={16} />
                    <span>{f.service}</span>
                    <span>·</span>
                    <span>ETA {meta.eta} min</span>
                    <span>·</span>
                    <span>Impact {meta.impact}</span>
                    <span>·</span>
                    <span>Rollback available</span>
                  </div>
                </button>
                <SeverityBadge severity={f.severity} showDot={false} className="hidden w-[74px] justify-center sm:flex" />
                <div className="hidden w-[110px] sm:block">
                  <StatusPill status={plan.status} />
                </div>
                {isOpen ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
              </div>

              {isOpen && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="border-t border-border bg-muted/20 px-4 py-4">
                  <div className="grid gap-4 lg:grid-cols-2">
                    <div>
                      <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                        Terraform plan
                      </div>
                      <pre className="code-block max-h-56 overflow-auto rounded-xl border border-border bg-card p-3">{f.terraform || "// No Terraform module — CLI-only fix"}</pre>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                          AWS / provider CLI
                        </div>
                        <pre className="code-block max-h-28 overflow-auto rounded-xl border border-border bg-card p-3">{f.cli || "// No CLI available"}</pre>
                      </div>
                      <div>
                        <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                          Rollback plan
                        </div>
                        <pre className="code-block max-h-28 overflow-auto rounded-xl border border-destructive/30 bg-destructive/5 p-3 text-destructive">{f.rollback || "Snapshot restore"}</pre>
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 flex flex-wrap items-center gap-2">
                    <div className="mr-auto flex flex-wrap gap-1.5">
                      <Badge variant="soft">Change risk: {meta.risk}</Badge>
                      <Badge variant="soft">Auto-rollback on drift</Badge>
                      <Badge variant="soft">Source: {f.evidence.split("|")[0].trim()}</Badge>
                    </div>
                    {plan.status === "pending" && (
                      <>
                        <Button size="sm" variant="success" onClick={() => setStatus(f.id, "approved")}>
                          <Check className="h-3.5 w-3.5" /> Approve fix
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setStatus(f.id, "rejected")}>
                          <X className="h-3.5 w-3.5" /> Reject
                        </Button>
                      </>
                    )}
                    {plan.status === "approved" && (
                      <Button size="sm" variant="gradient" onClick={() => apply(f.id)} disabled={plan.applying}>
                        {plan.applying ? (
                          <>
                            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Applying via CI…
                          </>
                        ) : (
                          <>
                            <Wrench className="h-3.5 w-3.5" /> Apply fix
                          </>
                        )}
                      </Button>
                    )}
                    {plan.status === "applied" && (
                      <div className="flex items-center gap-2 text-[12px] font-semibold text-success">
                        <ShieldCheck className="h-4 w-4" /> Applied · drift watch active · rollback window 24h
                      </div>
                    )}
                    {plan.status === "rejected" && (
                      <Button size="sm" variant="outline" onClick={() => setStatus(f.id, "pending")}>
                        Re-open
                      </Button>
                    )}
                  </div>
                </motion.div>
              )}
            </motion.div>
          );
        })}
      </div>
      )}

      <div className="mt-6 flex items-start gap-2.5 rounded-2xl border border-info/25 bg-info/5 p-4">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-info" />
        <p className="text-[12px] leading-relaxed text-muted-foreground">
          <span className="font-semibold text-foreground">Safety net:</span> every fix runs through a canary stage in
          your CI pipeline, validates against 214 drift checks, and automatically rolls back within 10 minutes if any
          resource enters an error state. Rejected plans are logged to the audit trail with the approver&apos;s identity.
        </p>
      </div>
    </div>
  );
}
