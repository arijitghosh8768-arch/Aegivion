"use client";

import { motion } from "framer-motion";
import { CountUp } from "@/components/shared/count-up";
import { cn } from "@/lib/utils";

export function ScoreRing({
  value,
  size = 140,
  stroke = 11,
  label,
  sublabel,
  color = "var(--brand-purple)",
  className,
}: {
  value: number;
  size?: number;
  stroke?: number;
  label?: string;
  sublabel?: string;
  color?: string;
  className?: string;
}) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, value));

  const scoreColor =
    pct >= 80 ? "#22c55e" : pct >= 60 ? color : pct >= 40 ? "#f59e0b" : "#ef4444";

  return (
    <div className={cn("relative inline-flex items-center justify-center", className)} style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--muted)" strokeWidth={stroke} />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={scoreColor}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: c - (c * pct) / 100 }}
          transition={{ duration: 1.4, ease: [0.22, 1, 0.36, 1] }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <CountUp value={pct} className="text-3xl font-bold tracking-tight" suffix="" />
        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{label ?? "score"}</span>
        {sublabel && <span className="mt-0.5 text-[10px] text-muted-foreground">{sublabel}</span>}
      </div>
    </div>
  );
}
