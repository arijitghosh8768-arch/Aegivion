"use client";

import { motion } from "framer-motion";
import { Boxes, Crosshair, ShieldCheck, FileText, Globe2 } from "lucide-react";
import { COMMAND_STATS } from "@/lib/data/dashboard";
import { CountUp } from "@/components/shared/count-up";
import { cn } from "@/lib/utils";

const ICONS = {
  cube: Boxes,
  crosshair: Crosshair,
  "shield-check": ShieldCheck,
  "file-check": FileText,
  globe: Globe2,
} as const;

export function MetricCards() {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {COMMAND_STATS.map((m, i) => {
        const Icon = ICONS[m.icon];
        return (
          <motion.div
            key={m.id}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.06, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
            className="card-hover group relative overflow-hidden rounded-2xl border border-border bg-card p-3.5 shadow-soft"
          >
            <div
              className={cn(
                "pointer-events-none absolute -right-8 -top-8 h-24 w-24 rounded-full bg-gradient-to-br to-transparent opacity-0 transition-opacity duration-500 group-hover:opacity-100",
                m.glow
              )}
            />
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground">
                  {m.label}
                </div>
                <div className="mt-1.5 flex items-baseline gap-1 text-[24px] font-bold leading-none tracking-tight">
                  {m.format === "score" ? (
                    <>
                      <CountUp value={m.value} />
                      <span className="text-sm font-semibold text-muted-foreground">/100</span>
                    </>
                  ) : m.format === "pct" ? (
                    <CountUp value={m.value} suffix="%" />
                  ) : m.format === "low" ? (
                    <span className="text-[26px]">Low</span>
                  ) : (
                    <CountUp value={m.value} />
                  )}
                </div>
                <div className={cn("mt-1 text-[11px] font-medium", m.subtitleTint ?? "text-muted-foreground")}>
                  {m.subtitle}
                </div>
              </div>
              <span
                className={cn(
                  "flex h-8 w-8 shrink-0 items-center justify-center rounded-xl transition-transform duration-300 group-hover:scale-110",
                  m.tint
                )}
              >
                <Icon className="h-4 w-4" />
              </span>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}
