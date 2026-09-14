"use client";

import { useCountUp } from "@/lib/hooks";
import { cn } from "@/lib/utils";

interface CountUpProps {
  value: number;
  className?: string;
  duration?: number;
  decimals?: number;
  prefix?: string;
  suffix?: string;
  compact?: boolean;
}

export function CountUp({
  value,
  className,
  duration,
  decimals,
  prefix,
  suffix,
  compact,
}: CountUpProps) {
  const v = useCountUp(value, duration, decimals ?? (compact ? 0 : 0));
  const formatted = compact
    ? new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(v)
    : new Intl.NumberFormat("en-US").format(v);

  return (
    <span className={cn("tabular-nums", className)}>
      {prefix}
      {formatted}
      {suffix}
    </span>
  );
}
