"use client";

import { useMemo } from "react";
import { motion } from "framer-motion";
import { Boxes, Crosshair, ShieldCheck, FileText, Globe2 } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { COMMAND_STATS } from "@/lib/data/dashboard";
import { CountUp } from "@/components/shared/count-up";
import { fetchApi } from "@/lib/api-client";
import { cn } from "@/lib/utils";

const ICONS = {
  cube: Boxes,
  crosshair: Crosshair,
  "shield-check": ShieldCheck,
  "file-check": FileText,
  globe: Globe2,
} as const;

export function MetricCards() {
  const { data: riskData } = useQuery({
    queryKey: ["risk-intelligence"],
    queryFn: () => fetchApi<any>("/v1/risk/intelligence"),
  });

  const { data: complianceData } = useQuery({
    queryKey: ["compliance-summary"],
    queryFn: () => fetchApi<any>("/v1/compliance/summary"),
  });

  const dynamicStats = useMemo(() => {
    return COMMAND_STATS.map((m) => {
      let value = m.value;
      let subtitle = m.subtitle;
      let format = m.format as string;
      let subtitleTint = m.subtitleTint;
      let tint = m.tint;
      let glow = m.glow;

      if (m.id === "assets" && riskData) {
        value = riskData.asset_count ?? value;
      } else if (m.id === "critical" && riskData) {
        value = riskData.critical_count ?? value;
      } else if (m.id === "compliance" && complianceData) {
        value = complianceData.overall?.pass_rate ?? value;
        const passed = complianceData.overall?.passed ?? 0;
        const total = complianceData.overall?.total_controls ?? 0;
        subtitle = `${passed}/${total} Compliant`;
      } else if (m.id === "surface" && riskData) {
        const level = riskData.overall_risk?.level?.toLowerCase() ?? "low";
        format = level;
        
        // Dynamically update the color based on the risk level
        if (level === "critical") {
          subtitleTint = "text-destructive";
          tint = "bg-destructive/10 text-destructive";
          glow = "from-destructive/15";
        } else if (level === "high") {
          subtitleTint = "text-orange-500";
          tint = "bg-orange-500/10 text-orange-500";
          glow = "from-orange-500/15";
        } else if (level === "medium" || level === "moderate") {
          subtitleTint = "text-yellow-500";
          tint = "bg-yellow-500/10 text-yellow-500";
          glow = "from-yellow-500/15";
        } else {
          subtitleTint = "text-success";
          tint = "bg-brand-blue/10 text-brand-blue";
          glow = "from-brand-blue/15";
        }
      }

      return { ...m, value, subtitle, format, subtitleTint, tint, glow };
    });
  }, [riskData, complianceData]);

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {dynamicStats.map((m, i) => {
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
                      <CountUp value={m.value as number} />
                      <span className="text-sm font-semibold text-muted-foreground">/100</span>
                    </>
                  ) : m.format === "pct" ? (
                    <CountUp value={m.value as number} suffix="%" />
                  ) : ["low", "moderate", "medium", "high", "critical"].includes(m.format) ? (
                    <span className="text-[26px] capitalize">{m.format}</span>
                  ) : (
                    <CountUp value={m.value as number} />
                  )}
                </div>
                <div className={cn("mt-1 text-xs font-medium", m.subtitleTint ?? "text-muted-foreground")}>
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
