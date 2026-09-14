"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, ShieldCheck, Radar, Lock, CheckCircle2 } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { SeverityBadge, StatusPill } from "@/components/shared/severity";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ALERTS, MITRE_COVERAGE } from "@/lib/data/alerts";
import { cn } from "@/lib/utils";
import type { Alert } from "@/lib/types";

export default function ThreatsPage() {
  const [alerts, setAlerts] = useState(ALERTS);
  const [expanded, setExpanded] = useState<string | null>(ALERTS[0]?.id ?? null);

  const bySeverity = (s: Alert["severity"]) => alerts.filter((a) => a.severity === s).length;
  const active = alerts.filter((a) => a.status === "active" || a.status === "investigating").length;

  const update = (id: string, status: Alert["status"]) =>
    setAlerts((as) => as.map((a) => (a.id === id ? { ...a, status } : a)));

  return (
    <div>
      <PageHeader
        title="Threats"
        description="Correlated alerts with evidence, MITRE ATT&CK mapping and containment actions."
      >
        <Button variant="outline">
          <Radar className="h-4 w-4" /> Watch mode
        </Button>
        <Button variant="gradient">
          <Lock className="h-4 w-4" /> Contain all active
        </Button>
      </PageHeader>

      {/* summary */}
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <SummaryCard label="Active alerts" value={active} tint="text-destructive" icon={<ShieldAlert className="h-4 w-4" />} />
        <SummaryCard label="Critical" value={bySeverity("critical")} tint="text-destructive" />
        <SummaryCard label="High" value={bySeverity("high")} tint="text-warning" />
        <SummaryCard label="Contained / resolved" value={alerts.length - active} tint="text-success" icon={<ShieldCheck className="h-4 w-4" />} />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_320px]">
        {/* alert list */}
        <div className="space-y-3">
          {alerts.map((a, i) => (
            <motion.div
              key={a.id}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft"
            >
              <button
                onClick={() => setExpanded(expanded === a.id ? null : a.id)}
                className="flex w-full cursor-pointer items-center gap-3 px-4 py-3.5 text-left transition hover:bg-muted/30"
              >
                <SeverityBadge severity={a.severity} showDot={false} className="w-[76px] justify-center" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13.5px] font-semibold">{a.title}</div>
                  <div className="mt-0.5 truncate text-[11.5px] text-muted-foreground">
                    {a.tactic} · {a.technique} ({a.techniqueId})
                  </div>
                </div>
                <div className="hidden sm:block">
                  <StatusPill status={a.status} />
                </div>
                <span className="text-[11px] tabular-nums text-muted-foreground">{timeShort(a.timestamp)}</span>
              </button>

              {expanded === a.id && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="border-t border-border bg-muted/20 px-4 py-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2 text-[12.5px]">
                      <div className="flex gap-2">
                        <span className="w-24 shrink-0 font-semibold text-muted-foreground">Source</span>
                        <span>{a.source}</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="w-24 shrink-0 font-semibold text-muted-foreground">Target</span>
                        <span>{a.target}</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="w-24 shrink-0 font-semibold text-muted-foreground">Confidence</span>
                        <span className="font-semibold tabular-nums">{a.confidence}%</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="w-24 shrink-0 font-semibold text-muted-foreground">MITRE</span>
                        <Badge variant="purple">{a.techniqueId}</Badge>
                      </div>
                    </div>
                    <div>
                      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                        Evidence
                      </div>
                      <ul className="space-y-1.5">
                        {a.evidence.map((ev, j) => (
                          <li key={j} className="flex gap-1.5 text-[12px] leading-snug text-muted-foreground">
                            <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />
                            {ev}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                  <div className="mt-4 flex flex-wrap items-center gap-2">
                    {a.status === "active" && (
                      <>
                        <Button size="sm" onClick={() => update(a.id, "investigating")}>
                          <Radar className="h-3.5 w-3.5" /> Start investigation
                        </Button>
                        <Button size="sm" variant="success" onClick={() => update(a.id, "contained")}>
                          <Lock className="h-3.5 w-3.5" /> Contain
                        </Button>
                      </>
                    )}
                    {a.status === "investigating" && (
                      <Button size="sm" variant="success" onClick={() => update(a.id, "contained")}>
                        <Lock className="h-3.5 w-3.5" /> Mark contained
                      </Button>
                    )}
                    {(a.status === "contained" || a.status === "investigating") && (
                      <Button size="sm" variant="outline" onClick={() => update(a.id, "resolved")}>
                        <CheckCircle2 className="h-3.5 w-3.5" /> Resolve
                      </Button>
                    )}
                    <Button size="sm" variant="ghost" onClick={() => setExpanded(null)}>
                      Close
                    </Button>
                  </div>
                </motion.div>
              )}
            </motion.div>
          ))}
        </div>

        {/* MITRE coverage */}
        <motion.div
          initial={{ opacity: 0, x: 12 }}
          animate={{ opacity: 1, x: 0 }}
          className="h-fit space-y-4 rounded-2xl border border-border bg-card p-5 shadow-soft xl:sticky xl:top-4"
        >
          <div>
            <h3 className="text-[14px] font-semibold">MITRE ATT&CK Coverage</h3>
            <p className="text-[11.5px] text-muted-foreground">Tactics observed in the last 30 days</p>
          </div>
          <div className="space-y-3">
            {MITRE_COVERAGE.map((m) => (
              <div key={m.tactic}>
                <div className="mb-1 flex items-center justify-between text-[11.5px]">
                  <span className="font-medium text-muted-foreground">{m.tactic}</span>
                  <span className="font-semibold tabular-nums">
                    {m.techniques} tech{m.techniques > 1 ? "s" : ""}
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <motion.div
                    className="h-full rounded-full"
                    style={{ background: m.color }}
                    initial={{ width: 0 }}
                    animate={{ width: `${Math.min(100, m.techniques * 28)}%` }}
                    transition={{ duration: 0.9, delay: 0.2 }}
                  />
                </div>
              </div>
            ))}
          </div>
          <div className="rounded-xl bg-muted/50 p-3 text-[11px] leading-relaxed text-muted-foreground">
            <span className="font-semibold text-foreground">Aegivion insight:</span> 3 new techniques detected this
            week — coverage is expanding as telemetry grows.
          </div>
        </motion.div>
      </div>
    </div>
  );
}

function SummaryCard({
  label,
  value,
  tint,
  icon,
}: {
  label: string;
  value: number;
  tint?: string;
  icon?: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-border bg-card p-4 shadow-soft">
      <div className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className={cn("mt-1 text-2xl font-bold tabular-nums tracking-tight", tint)}>{value}</div>
    </div>
  );
}

function timeShort(iso: string) {
  const d = new Date(iso);
  const mins = Math.max(0, Math.round((Date.now() - d.getTime()) / 60000));
  if (mins < 60) return `${mins}m ago`;
  return d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}
