"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { FileCheck2, ArrowRight, TrendingDown, TrendingUp, ShieldCheck, TriangleAlert } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { ScoreRing } from "@/components/shared/score-ring";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { COMPLIANCE_FRAMEWORKS, COMPLIANCE_TREND } from "@/lib/data/compliance";
import { cn } from "@/lib/utils";

const STATUS_UI = {
  pass: { label: "Passing", cls: "bg-success/12 text-success" },
  attention: { label: "Attention", cls: "bg-warning/15 text-warning" },
  fail: { label: "Failing", cls: "bg-destructive/12 text-destructive" },
} as const;

export default function CompliancePage() {
  const passed = COMPLIANCE_FRAMEWORKS.reduce((s, f) => s + f.passed, 0);
  const total = COMPLIANCE_FRAMEWORKS.reduce((s, f) => s + f.total, 0);
  const avg = Math.round(COMPLIANCE_FRAMEWORKS.reduce((s, f) => s + f.score, 0) / COMPLIANCE_FRAMEWORKS.length);
  const attention = COMPLIANCE_FRAMEWORKS.filter((f) => f.status === "attention").length;

  return (
    <div>
      <PageHeader
        title="Compliance"
        description="Continuous compliance posture across SOC 2, CIS, PCI DSS, HIPAA, NIST and ISO 27001."
      >
        <Button variant="gradient" asChild>
          <Link href="/reports?type=compliance">
            <FileCheck2 className="h-4 w-4" /> Compliance report
          </Link>
        </Button>
      </PageHeader>

      {/* summary */}
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Controls passed", value: `${passed}/${total}`, tint: "text-success" },
          { label: "Avg compliance", value: `${avg}%`, tint: "text-primary" },
          { label: "Frameworks", value: String(COMPLIANCE_FRAMEWORKS.length) },
          { label: "Need attention", value: attention, tint: "text-warning" },
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

      {/* framework cards */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {COMPLIANCE_FRAMEWORKS.map((f, i) => {
          const st = STATUS_UI[f.status];
          return (
            <motion.div
              key={f.id}
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="card-hover rounded-2xl border border-border bg-card p-5 shadow-soft"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-[14.5px] font-semibold leading-tight">{f.name}</div>
                  <div className="mt-0.5 text-[11px] text-muted-foreground">
                    {f.passed}/{f.total} controls
                  </div>
                </div>
                <Badge className={st.cls}>{st.label}</Badge>
              </div>
              <div className="mt-4 flex items-center gap-4">
                <ScoreRing value={f.score} size={88} stroke={8} label="score" />
                <div className="flex-1 space-y-2">
                  <div>
                    <div className="mb-1 flex items-center justify-between text-[11px]">
                      <span className="text-muted-foreground">Trend</span>
                      <span className={cn("flex items-center gap-0.5 font-semibold tabular-nums", f.trend >= 0 ? "text-success" : "text-destructive")}>
                        {f.trend >= 0 ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
                        {Math.abs(f.trend)} pts
                      </span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                      <motion.div
                        className="h-full rounded-full bg-brand-gradient"
                        initial={{ width: 0 }}
                        animate={{ width: `${f.score}%` }}
                        transition={{ duration: 1, delay: 0.3 }}
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-1 text-[11px] text-muted-foreground">
                    {f.status === "pass" ? <ShieldCheck className="h-3.5 w-3.5 text-success" /> : <TriangleAlert className="h-3.5 w-3.5 text-warning" />}
                    {f.status === "pass" ? "All critical controls passing" : "Remediation backlog detected"}
                  </div>
                </div>
              </div>
              <Link
                href="/detection-engine?framework=CIS"
                className="mt-4 flex items-center gap-1 text-[11.5px] font-semibold text-primary transition hover:gap-1.5"
              >
                View failing controls <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </motion.div>
          );
        })}
      </div>

      {/* 12-week trend */}
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="mt-6 rounded-2xl border border-border bg-card p-5 shadow-soft"
      >
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-[14px] font-bold tracking-tight">COMPLIANCE TREND</h3>
            <p className="text-[11.5px] text-muted-foreground">Score by framework · last 12 weeks</p>
          </div>
          <Badge variant="soft">W1 → W12</Badge>
        </div>
        <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-muted">
          <motion.div
            className="h-full rounded-full bg-brand-gradient"
            initial={{ width: 0 }}
            animate={{ width: `${COMPLIANCE_TREND[COMPLIANCE_TREND.length - 1].soc2}%` }}
            transition={{ duration: 1.2 }}
          />
        </div>
        <div className="mt-2 flex justify-between text-[10px] text-muted-foreground">
          <span>12 weeks ago</span>
          <span className="font-semibold text-primary">SOC 2 {COMPLIANCE_TREND[COMPLIANCE_TREND.length - 1].soc2}%</span>
        </div>
      </motion.div>
    </div>
  );
}
