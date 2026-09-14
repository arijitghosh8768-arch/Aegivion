"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import { ChevronDown, ArrowRight, Settings2, Lock, ShieldAlert, MonitorSmartphone } from "lucide-react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { RISK_TREND_7D, TOP_RISKY_ASSETS } from "@/lib/data/dashboard";
import { ChartTooltip } from "@/components/shared/chart-tooltip";
import { CountUp } from "@/components/shared/count-up";
import { cn } from "@/lib/utils";
import type { ProviderId } from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Risk Trend — Last 7 Days                                            */
/* ------------------------------------------------------------------ */

export function RiskTrend({ className }: { className?: string }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 0);
    return () => clearTimeout(t);
  }, []);

  return (
    <div className={cn("flex flex-col rounded-2xl border border-border bg-card p-4 shadow-soft", className)}>
      <div className="flex items-center justify-between">
        <h3 className="text-[13.5px] font-bold tracking-tight">RISK TREND (Last 7 Days)</h3>
        <button className="flex h-7 cursor-pointer items-center gap-1 rounded-lg border border-border bg-muted/40 px-2.5 text-[11px] font-semibold text-muted-foreground transition hover:text-foreground">
          Overall Risk <ChevronDown className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="mt-2 flex-1">
        {!mounted && <div className="h-[230px] w-full" />}
        {mounted && <ResponsiveContainer width="100%" height={230}>
          <AreaChart data={RISK_TREND_7D} margin={{ top: 8, right: 8, left: -22, bottom: 0 }}>
            <defs>
              <linearGradient id="risk7-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#6d5df6" stopOpacity={0.32} />
                <stop offset="100%" stopColor="#6d5df6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 6" stroke="var(--border)" vertical={false} />
            <XAxis dataKey="day" tick={{ fontSize: 10.5, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} />
            <YAxis
              tick={{ fontSize: 10.5, fill: "var(--muted-foreground)" }}
              axisLine={false}
              tickLine={false}
              domain={[0, 100]}
              ticks={[0, 25, 50, 75, 100]}
            />
            <Tooltip content={<ChartTooltip />} />
            <Area
              type="monotone"
              dataKey="score"
              name="Risk score"
              stroke="#6d5df6"
              strokeWidth={2.4}
              fill="url(#risk7-grad)"
              dot={{ r: 3.5, fill: "#6d5df6", strokeWidth: 2, stroke: "var(--card)" }}
              activeDot={{ r: 5 }}
            />
          </AreaChart>
        </ResponsiveContainer>}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Top Risky Assets table                                              */
/* ------------------------------------------------------------------ */

const KIND_META: Record<string, { color: string; bg: string; icon: React.ComponentType<{ className?: string }> }> = {
  bucket: { color: "#ef4444", bg: "bg-destructive/10", icon: Settings2 },
  user: { color: "#ef4444", bg: "bg-destructive/10", icon: Lock },
  group: { color: "#4f7cf7", bg: "bg-info/12", icon: ShieldAlert },
  vm: { color: "#4f7cf7", bg: "bg-info/12", icon: MonitorSmartphone },
};

const BADGE_TINT: Record<string, string> = {
  Critical: "bg-destructive/12 text-destructive",
  High: "bg-warning/15 text-warning",
  Medium: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  Low: "bg-success/12 text-success",
};

const PROVIDER_LABEL: Record<ProviderId, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
};

export function TopRiskyAssets({ className }: { className?: string }) {
  return (
    <div className={cn("flex flex-col rounded-2xl border border-border bg-card p-4 shadow-soft", className)}>
      <div className="flex items-center justify-between">
        <h3 className="text-[13.5px] font-bold tracking-tight">TOP RISKY ASSETS</h3>
        <Link href="/assets" className="flex items-center gap-0.5 text-[11px] font-semibold text-primary transition hover:gap-1.5">
          View All <ArrowRight className="h-3 w-3" />
        </Link>
      </div>

      <div className="mt-2 flex-1 divide-y divide-border/60">
        {TOP_RISKY_ASSETS.map((a, i) => {
          const kind = KIND_META[a.kind];
          const Icon = kind.icon;
          return (
            <Link
              key={a.id}
              href={a.kind === "vm" ? "/assets?filter=exposed" : a.kind === "user" ? "/identities" : "/detection-engine"}
              className="group flex items-center gap-3 py-2.5 transition"
            >
              <motion.span
                initial={{ opacity: 0, scale: 0.7 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: i * 0.06 }}
                className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-full", kind.bg)}
                style={{ color: kind.color }}
              >
                <Icon className="h-4 w-4" />
              </motion.span>
              <div className="min-w-0 flex-1">
                <div className="truncate text-[12px] font-semibold transition group-hover:text-primary">{a.title}</div>
                <div className="truncate text-[10.5px] text-muted-foreground">
                  {PROVIDER_LABEL[a.provider]} {a.scope.replace(PROVIDER_LABEL[a.provider], "").trim()}
                </div>
              </div>
              <span className={cn("shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-bold", BADGE_TINT[a.badge])}>
                {a.badge}
              </span>
              <span className="flex shrink-0 items-center gap-2 border-l border-border pl-2.5">
                <span className="w-7 text-right text-[13px] font-bold tabular-nums" style={{ color: kind.color }}>
                  <CountUp value={a.score} />
                </span>
              </span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
