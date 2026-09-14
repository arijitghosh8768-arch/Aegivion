"use client";

import { motion } from "framer-motion";
import {
  Line,
  LineChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { History, BrainCircuit, Repeat2, TrendingDown, Lightbulb } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { ChartTooltip } from "@/components/shared/chart-tooltip";
import { SeverityBadge } from "@/components/shared/severity";
import { Badge } from "@/components/ui/badge";
import { INCIDENTS, LEARNED_PATTERNS, REPEATED_MISTAKES, MEMORY_TREND } from "@/lib/data/memory";
import { cn } from "@/lib/utils";

const axisStyle = { fontSize: 10.5, fill: "var(--muted-foreground)" };

export default function SecurityMemoryPage() {
  return (
    <div>
      <PageHeader
        title="Security Memory"
        description="Aegivion remembers every incident, learns the patterns behind them, and stops the repeats."
      >
        <Badge variant="soft" className="gap-1.5">
          <BrainCircuit className="h-3.5 w-3.5 text-primary" /> Learning engine active
        </Badge>
      </PageHeader>

      {/* trend */}
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-5 rounded-2xl border border-border bg-card p-5 shadow-soft"
      >
        <div className="mb-3 flex items-center justify-between">
          <div>
            <h3 className="text-[14px] font-semibold">Incidents & repeat rate</h3>
            <p className="text-[11.5px] text-muted-foreground">Last 6 months · repeat rate down 25%</p>
          </div>
          <div className="flex items-center gap-1.5 rounded-full bg-success/10 px-2.5 py-1 text-[11px] font-bold text-success">
            <TrendingDown className="h-3.5 w-3.5" /> Improving
          </div>
        </div>
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={MEMORY_TREND} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 6" stroke="var(--border)" vertical={false} />
            <XAxis dataKey="month" tick={axisStyle} axisLine={false} tickLine={false} />
            <YAxis tick={axisStyle} axisLine={false} tickLine={false} />
            <Tooltip content={<ChartTooltip />} />
            <Line type="monotone" dataKey="incidents" name="Incidents" stroke="#6d5df6" strokeWidth={2.4} dot={{ r: 3 }} />
            <Line type="monotone" dataKey="repeatRate" name="Repeat rate %" stroke="#f59e0b" strokeWidth={2} dot={{ r: 3 }} />
          </LineChart>
        </ResponsiveContainer>
      </motion.div>

      <div className="grid gap-5 xl:grid-cols-2">
        {/* incidents */}
        <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <h3 className="mb-3 flex items-center gap-2 text-[14px] font-semibold">
            <History className="h-4 w-4 text-primary" /> Historical incidents
          </h3>
          <div className="space-y-3">
            {INCIDENTS.map((inc) => (
              <div key={inc.id} className="card-hover rounded-2xl border border-border bg-card p-4 shadow-soft">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5">
                    <SeverityBadge severity={inc.severity} showDot={false} />
                    <span className="text-[12px] font-semibold tabular-nums text-muted-foreground">
                      {new Date(inc.date).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                    </span>
                  </div>
                  {inc.repeated && (
                    <Badge variant="warning" className="gap-1">
                      <Repeat2 className="h-3 w-3" /> repeated
                    </Badge>
                  )}
                </div>
                <div className="mt-2 text-[14px] font-semibold">{inc.title}</div>
                <p className="mt-1 text-[12px] leading-relaxed text-muted-foreground">{inc.summary}</p>
                <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
                  <Badge variant="success">{inc.outcome}</Badge>
                  <Badge variant="soft">MTTR {inc.durationHrs}h</Badge>
                  <Badge variant="soft">
                    {inc.affected.toLocaleString()} affected record{inc.affected !== 1 ? "s" : ""}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        {/* learned patterns */}
        <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <h3 className="mb-3 flex items-center gap-2 text-[14px] font-semibold">
            <BrainCircuit className="h-4 w-4 text-primary" /> Learned patterns
          </h3>
          <div className="space-y-3">
            {LEARNED_PATTERNS.map((p) => (
              <div key={p.id} className="rounded-2xl border border-border bg-card p-4 shadow-soft transition hover:border-primary/30">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-brand-purple/10">
                      <Lightbulb className="h-3.5 w-3.5 text-brand-purple" />
                    </span>
                    <span className="text-[13px] font-semibold leading-snug">{p.pattern}</span>
                  </div>
                  <span className="shrink-0 rounded-full bg-primary/10 px-2 py-0.5 text-[10.5px] font-bold tabular-nums text-primary">
                    {p.confidence}% sure
                  </span>
                </div>
                <p className="mt-2 text-[12px] leading-relaxed text-muted-foreground">{p.action}</p>
                <div className="mt-2 flex items-center gap-2 text-[10.5px] text-muted-foreground">
                  <Badge variant="soft">First seen {p.firstSeen}</Badge>
                  <Badge variant="soft">{p.occurrences} occurrences</Badge>
                </div>
              </div>
            ))}
          </div>

          <h3 className="mb-3 mt-6 flex items-center gap-2 text-[14px] font-semibold">
            <Repeat2 className="h-4 w-4 text-primary" /> Repeated mistakes
          </h3>
          <div className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft">
            <div className="divide-y divide-border/60">
              {REPEATED_MISTAKES.map((m) => (
                <div key={m.mistake} className="flex items-center gap-3 px-4 py-3">
                  <span
                    className={cn(
                      "h-1.5 w-1.5 shrink-0 rounded-full",
                      m.status === "recurring" ? "bg-destructive" : "bg-warning"
                    )}
                  />
                  <span className="flex-1 text-[12.5px] font-medium">{m.mistake}</span>
                  <Badge variant="soft">{m.count}×</Badge>
                  <Badge variant={m.status === "recurring" ? "destructive" : "warning"}>{m.status}</Badge>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
