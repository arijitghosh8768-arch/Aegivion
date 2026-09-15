"use client";

import { useMemo } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { FileCheck2, ArrowRight, TrendingDown, TrendingUp, ShieldCheck, TriangleAlert } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "@/lib/api-client";
import { PageHeader } from "@/components/shared/page-header";
import { ScoreRing } from "@/components/shared/score-ring";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const STATUS_UI = {
  pass: { label: "Passing", cls: "bg-success/12 text-success" },
  attention: { label: "Attention", cls: "bg-warning/15 text-warning" },
  fail: { label: "Failing", cls: "bg-destructive/12 text-destructive" },
} as const;

type FrameworkStatus = keyof typeof STATUS_UI;

interface Framework {
  id: string;
  name: string;
  score: number;
  passed: number;
  total: number;
  trend: number;
  status: FrameworkStatus;
}

function mapFramework(f: any): Framework {
  const score: number = f.score ?? f.percent ?? f.pass_rate ?? 0;
  const passed: number = f.passed ?? f.passed_controls ?? 0;
  const total: number = f.total ?? f.total_controls ?? 0;
  const status: FrameworkStatus =
    score >= 80 ? "pass" : score >= 50 ? "attention" : "fail";
  return {
    id: f.id ?? f.framework_id ?? f.title ?? String(Math.random()),
    name: f.title ?? f.name ?? f.framework_name ?? "Unknown",
    score,
    passed,
    total,
    trend: f.trend ?? f.score_delta ?? 0,
    status: (f.status as FrameworkStatus) ?? status,
  };
}

export default function CompliancePage() {
  const { data: rawData, isLoading } = useQuery({
    queryKey: ["compliance-summary"],
    queryFn: () => fetchApi<any>("/v1/compliance/summary"),
  });

  const frameworks = useMemo<Framework[]>(() => {
    if (!rawData?.frameworks) return [];
    return rawData.frameworks.map(mapFramework).filter((f: Framework) => f.total > 0);
  }, [rawData]);

  const passed = frameworks.reduce((s, f) => s + f.passed, 0);
  const total = frameworks.reduce((s, f) => s + f.total, 0);
  const avg = frameworks.length
    ? Math.round(frameworks.reduce((s, f) => s + f.score, 0) / frameworks.length)
    : 0;
  const attention = frameworks.filter((f) => f.status === "attention").length;

  if (!isLoading && frameworks.length === 0) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader
          title="Compliance"
          description="Continuous compliance posture across SOC 2, CIS, PCI DSS, HIPAA, NIST and ISO 27001."
        />
        <div className="mt-8 flex flex-1 flex-col items-center justify-center rounded-2xl border border-dashed border-border bg-card/30 p-8 text-center">
          <ShieldCheck className="mb-4 h-12 w-12 text-muted-foreground/30" />
          <h3 className="text-lg font-semibold">No Compliance Data</h3>
          <p className="mt-2 max-w-sm text-sm text-muted-foreground">
            Connect your cloud environments and run an initial scan to begin tracking your compliance posture against major frameworks.
          </p>
        </div>
      </div>
    );
  }

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
          { label: "Frameworks", value: String(frameworks.length) },
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
      {isLoading ? (
        <div className="py-14 text-center text-sm text-muted-foreground">Loading compliance data…</div>
      ) : frameworks.length === 0 ? (
        <div className="py-14 text-center text-sm text-muted-foreground">
          No compliance data yet. Connect a cloud account and run a scan to assess compliance posture.
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {frameworks.map((f, i) => {
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
      )}

      {/* 12-week trend — only shown when we have data */}
      {!isLoading && frameworks.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mt-6 rounded-2xl border border-border bg-card p-5 shadow-soft"
        >
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-[14px] font-bold tracking-tight">COMPLIANCE TREND</h3>
              <p className="text-[11.5px] text-muted-foreground">Avg score across frameworks</p>
            </div>
            <Badge variant="soft">Live</Badge>
          </div>
          <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-muted">
            <motion.div
              className="h-full rounded-full bg-brand-gradient"
              initial={{ width: 0 }}
              animate={{ width: `${avg}%` }}
              transition={{ duration: 1.2 }}
            />
          </div>
          <div className="mt-2 flex justify-between text-[10px] text-muted-foreground">
            <span>0%</span>
            <span className="font-semibold text-primary">Avg {avg}%</span>
          </div>
        </motion.div>
      )}
    </div>
  );
}

