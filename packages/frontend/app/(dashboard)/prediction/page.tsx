"use client";

import { useMemo } from "react";
import { motion } from "framer-motion";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { TrendingUp, CalendarClock, AlertTriangle, Sparkles } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { ChartTooltip } from "@/components/shared/chart-tooltip";
import { ScoreRing } from "@/components/shared/score-ring";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FORECAST, buildHeatmap, HEATMAP_DAYS, LIKELIHOOD_FACTORS } from "@/lib/data/compliance";
import { cn } from "@/lib/utils";

const axisStyle = { fontSize: 10.5, fill: "var(--muted-foreground)" };

export default function PredictionPage() {
  const heatmap = useMemo(() => buildHeatmap(), []);
  const peakDay = 6;
  const peakHour = 21;
  const peakValue = heatmap[peakDay][peakHour];

  return (
    <div>
      <PageHeader
        title="Prediction"
        description="ML-driven forecasts of attack probability across your estate for the next 14 days."
      >
        <Button variant="outline">
          <CalendarClock className="h-4 w-4" /> 72h forecast
        </Button>
        <Button variant="gradient">
          <Sparkles className="h-4 w-4" /> Explain predictions
        </Button>
      </PageHeader>

      <div className="grid gap-5 xl:grid-cols-3">
        {/* forecast chart */}
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl border border-border bg-card p-5 shadow-soft xl:col-span-2"
        >
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h3 className="flex items-center gap-2 text-[14px] font-semibold">
                <TrendingUp className="h-4 w-4 text-primary" /> Attack probability forecast
              </h3>
              <p className="text-[11.5px] text-muted-foreground">Next 14 days · confidence band shown</p>
            </div>
            <Badge variant="warning">
              <AlertTriangle className="h-3 w-3" /> Peak: Aug 13 (64%)
            </Badge>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={FORECAST} margin={{ top: 6, right: 8, left: -14, bottom: 0 }}>
              <defs>
                <linearGradient id="forecast-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="band-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#6d5df6" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#6d5df6" stopOpacity={0.04} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 6" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="day" tick={axisStyle} axisLine={false} tickLine={false} interval={1} />
              <YAxis tick={axisStyle} axisLine={false} tickLine={false} domain={[0, 100]} unit="%" />
              <Tooltip content={<ChartTooltip />} />
              <Area type="monotone" dataKey="high" name="Upper bound" stroke="none" fill="url(#band-grad)" />
              <Area type="monotone" dataKey="low" name="Lower bound" stroke="none" fill="url(#band-grad)" />
              <Area type="monotone" dataKey="probability" name="Probability" stroke="#f59e0b" strokeWidth={2.4} fill="url(#forecast-grad)" />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* right column */}
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="space-y-5"
        >
          <div className="rounded-2xl border border-border bg-card p-5 shadow-soft">
            <h3 className="text-[14px] font-semibold">Next-72h likelihood</h3>
            <p className="mb-4 text-[11.5px] text-muted-foreground">Credential-based access</p>
            <div className="flex items-center justify-center">
              <ScoreRing value={58} size={150} label="likelihood" sublabel="72h · elevated" color="#f59e0b" />
            </div>
            <div className="mt-4 space-y-2">
              {LIKELIHOOD_FACTORS.slice(0, 3).map((f) => (
                <div key={f.factor} className="flex items-center justify-between text-[11.5px]">
                  <span className="text-muted-foreground">{f.factor}</span>
                  <span className={cn("font-bold tabular-nums", f.trend.startsWith("+") ? "text-destructive" : "text-success")}>
                    {f.weight * 100}% {f.trend}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-warning/25 bg-warning/5 p-5">
            <h3 className="flex items-center gap-2 text-[14px] font-semibold">
              <AlertTriangle className="h-4 w-4 text-warning" /> Highest-risk window
            </h3>
            <p className="mt-2 text-[12px] leading-relaxed text-muted-foreground">
              Model predicts elevated activity around <span className="font-semibold text-foreground">Sunday 21:00–23:00 UTC</span> —
              coincides with the prior exfiltration pattern and low SOC staffing.
            </p>
            <div className="mt-3 flex gap-2">
              <Button size="sm" variant="gradient">Schedule guard duty</Button>
              <Button size="sm" variant="outline">Review model factors</Button>
            </div>
          </div>
        </motion.div>
      </div>

      {/* heatmap */}
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
        className="mt-5 rounded-2xl border border-border bg-card p-5 shadow-soft"
      >
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h3 className="text-[14px] font-semibold">Attack likelihood heatmap</h3>
            <p className="text-[11.5px] text-muted-foreground">Predicted probability by hour · next 7 days</p>
          </div>
          <div className="flex items-center gap-1.5 text-[10.5px] text-muted-foreground">
            Lower
            {[0.15, 0.3, 0.45, 0.6, 0.75, 0.9].map((v) => (
              <span key={v} className="h-3 w-3 rounded-sm" style={{ background: heatColor(v) }} />
            ))}
            Higher
          </div>
        </div>
        <div className="overflow-x-auto">
          <div className="min-w-[720px]">
            <div className="mb-1.5 grid grid-cols-[52px_repeat(24,1fr)] gap-1">
              <span />
              {Array.from({ length: 24 }, (_, h) => (
                <span key={h} className="text-center text-[9px] font-medium text-muted-foreground">
                  {h === 0 ? "00" : h === 12 ? "12" : h % 4 === 0 ? String(h).padStart(2, "0") : ""}
                </span>
              ))}
            </div>
            {heatmap.map((row, d) => (
              <div key={d} className="mb-1 grid grid-cols-[52px_repeat(24,1fr)] items-center gap-1">
                <span className="text-[10px] font-semibold text-muted-foreground">{HEATMAP_DAYS[d]}</span>
                {row.map((v, h) => (
                  <motion.div
                    key={h}
                    initial={{ opacity: 0, scale: 0.6 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: (d * 24 + h) * 0.0012 }}
                    className={cn("h-5 rounded-[5px]", d === peakDay && h === peakHour && "ring-2 ring-primary ring-offset-1")}
                    style={{ background: heatColor(v) }}
                    title={`${HEATMAP_DAYS[d]} ${String(h).padStart(2, "0")}:00 — ${Math.round(v * 100)}%`}
                  />
                ))}
              </div>
            ))}
            <p className="mt-2 text-[11px] text-muted-foreground">
              Peak cell: <span className="font-semibold text-foreground">Sun 21:00 — {Math.round(peakValue * 100)}%</span> · 14 of 168 cells exceed 70%.
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

function heatColor(v: number): string {
  if (v < 0.2) return "rgba(34,197,94,0.18)";
  if (v < 0.4) return "rgba(34,197,94,0.42)";
  if (v < 0.55) return "rgba(245,158,11,0.5)";
  if (v < 0.7) return "rgba(245,158,11,0.72)";
  if (v < 0.85) return "rgba(239,68,68,0.72)";
  return "rgba(239,68,68,0.92)";
}
