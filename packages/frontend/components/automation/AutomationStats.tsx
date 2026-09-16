"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

export function AutomationStats({ overview }: { overview: any }) {
  const stats = [
    { label: "Active runbooks", value: overview?.active_runbooks ?? 0, tint: "text-success" },
    { label: "Total rules", value: overview?.total_rules ?? 0 },
    { label: "Executions (30d)", value: overview?.total_executions ?? 0, tint: "text-primary" },
    { label: "Auto-resolved", value: overview?.successful ?? 0, tint: "text-success" },
    { label: "Pending Approvals", value: overview?.pending_approvals ?? 0, tint: "text-amber-500" },
  ];

  return (
    <div className="mb-6 grid grid-cols-2 gap-3 xl:grid-cols-5">
      {stats.map((s, i) => (
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
  );
}
