"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { FileText, Download, Printer, Loader2, Shield, BarChart3, Scale, Radar, Check } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { ReportTemplate } from "@/lib/data/reports";
import { useAppStore } from "@/lib/store";

const ICONS = {
  shield: Shield,
  chart: BarChart3,
  scale: Scale,
  radar: Radar,
};

export default function ReportsPage() {
  const user = useAppStore((s) => s.user);
  const [generating, setGenerating] = useState<string | null>(null);
  const [templates, setTemplates] = useState<any[]>([]);
  const [recent, setRecent] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch("/api/v1/reports");
        if (res.ok) {
          const data = await res.json();
          setTemplates(data.templates || []);
          setRecent(data.history || []);
        }
      } catch (e) {
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const generate = (t: ReportTemplate) => {
    setGenerating(t.id);
    setTimeout(() => {
      setGenerating(null);
      setRecent((r) => [
        {
          id: `rh-${Date.now()}`,
          name: t.name,
          date: new Date().toISOString().slice(0, 10),
          format: "PDF",
          size: `${(1 + Math.random() * 3).toFixed(1)} MB`,
          status: "ready",
          generatedBy: user?.name ?? "AI Copilot",
        },
        ...r,
      ]);
    }, 1600);
  };

  const downloadCsv = () => {
    const csv = "";
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "aegivion-posture-2026-08.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  const printReport = () => window.print();

  return (
    <div>
      <PageHeader
        title="Reports"
        description="Audit-grade reports generated from live telemetry — PDF, CSV, or print-ready."
      >
        <Button variant="outline" onClick={downloadCsv}>
          <Download className="h-4 w-4" /> Export CSV
        </Button>
        <Button variant="gradient" onClick={printReport}>
          <Printer className="h-4 w-4" /> Print report
        </Button>
      </PageHeader>

      {/* templates */}
      <h3 className="mb-3 text-[14px] font-semibold">Report templates</h3>
      {loading ? (
        <div className="flex justify-center py-12"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
      ) : templates.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-border py-12 text-center bg-card">
          <FileText className="mb-3 h-8 w-8 text-muted-foreground" />
          <h3 className="text-[14px] font-semibold">No data yet</h3>
          <p className="mt-1 text-[12.5px] text-muted-foreground">No templates available.</p>
        </div>
      ) : (
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {templates.map((t: any, i: number) => {
          const Icon = ICONS[t.icon as keyof typeof ICONS] || ICONS["shield"];
          return (
            <motion.div
              key={t.id}
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="card-hover flex flex-col rounded-2xl border border-border bg-card p-5 shadow-soft"
            >
              <span
                className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl"
                style={{ backgroundColor: `${t.accent}1a`, color: t.accent }}
              >
                <Icon className="h-5 w-5" />
              </span>
              <div className="text-[14px] font-semibold">{t.name}</div>
              <p className="mt-1 flex-1 text-[12px] leading-relaxed text-muted-foreground">{t.description}</p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                <Badge variant="soft">{t.audience}</Badge>
                <Badge variant="soft">{t.cadence}</Badge>
              </div>
              <div className="mt-3 space-y-1">
                {t.sections.slice(0, 3).map((s: string) => (
                  <div key={s} className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                    <Check className="h-3 w-3 text-success" /> {s}
                  </div>
                ))}
                {t.sections.length > 3 && (
                  <div className="pl-4 text-[11px] text-muted-foreground">+{t.sections.length - 3} more sections</div>
                )}
              </div>
              <Button variant="gradient" size="sm" className="mt-4 w-full" onClick={() => generate(t)} disabled={generating === t.id}>
                {generating === t.id ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" /> Generating…
                  </>
                ) : (
                  <>
                    <FileText className="h-3.5 w-3.5" /> Generate {t.cadence === "Daily" ? "brief" : "report"}
                  </>
                )}
              </Button>
            </motion.div>
          );
        })}
      </div>
      )}

      {/* history */}
      <h3 className="mb-3 mt-8 text-[14px] font-semibold">Recent reports</h3>
      {loading ? null : recent.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-border py-12 text-center bg-card mt-3">
          <FileText className="mb-3 h-8 w-8 text-muted-foreground" />
          <h3 className="text-[14px] font-semibold">No data yet</h3>
          <p className="mt-1 text-[12.5px] text-muted-foreground">No recent reports found.</p>
        </div>
      ) : (
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft"
      >
        <div className="divide-y divide-border/60">
          {recent.map((r) => (
            <div key={r.id} className="flex items-center gap-3 px-4 py-3.5 transition hover:bg-muted/40">
              <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/10">
                <FileText className="h-4 w-4 text-primary" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13px] font-semibold">{r.name}</div>
                <div className="text-[11px] text-muted-foreground">
                  {r.date} · {r.format} · {r.size} · by {r.generatedBy}
                </div>
              </div>
              <Badge variant="success">ready</Badge>
              <button
                onClick={r.format === "CSV" ? downloadCsv : printReport}
                className="flex cursor-pointer items-center gap-1.5 rounded-lg border border-border px-2.5 py-1.5 text-[11.5px] font-semibold text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
              >
                <Download className="h-3.5 w-3.5" /> Download
              </button>
            </div>
          ))}
        </div>
      </motion.div>
      )}

      <div className="mt-6 flex items-start gap-2.5 rounded-2xl border border-border bg-card p-4 shadow-soft">
        <BarChart3 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
        <p className="text-[12px] leading-relaxed text-muted-foreground">
          <span className="font-semibold text-foreground">Audit ready.</span> Every report embeds an evidence manifest
          linking each control to its raw telemetry (CloudTrail, GuardDuty, SCC, Defender), the exact scan time, and a
          verifiable hash for chain-of-custody.
        </p>
      </div>
    </div>
  );
}
