import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

export const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; text: string; bg: string; dot: string }
> = {
  critical: {
    label: "Critical",
    text: "text-destructive",
    bg: "bg-destructive/10 border-destructive/25",
    dot: "bg-destructive",
  },
  high: {
    label: "High",
    text: "text-orange-500 dark:text-orange-400",
    bg: "bg-orange-500/10 border-orange-500/25",
    dot: "bg-orange-500",
  },
  medium: {
    label: "Medium",
    text: "text-amber-500 dark:text-amber-400",
    bg: "bg-amber-500/10 border-amber-500/25",
    dot: "bg-amber-500",
  },
  low: {
    label: "Low",
    text: "text-sky-600 dark:text-sky-400",
    bg: "bg-sky-500/10 border-sky-500/25",
    dot: "bg-sky-500",
  },
  info: {
    label: "Info",
    text: "text-muted-foreground",
    bg: "bg-muted border-border",
    dot: "bg-muted-foreground",
  },
};

export function SeverityBadge({
  severity,
  className,
  showDot = true,
}: {
  severity: Severity;
  className?: string;
  showDot?: boolean;
}) {
  const cfg = SEVERITY_CONFIG[severity];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold capitalize",
        cfg.bg,
        cfg.text,
        className
      )}
    >
      {showDot && <span className={cn("h-1.5 w-1.5 rounded-full", cfg.dot)} />}
      {cfg.label}
    </span>
  );
}

export function StatusPill({
  status,
  className,
}: {
  status: string;
  className?: string;
}) {
  const dot =
    status === "active" || status === "open" || status === "connected" || status === "ready"
      ? "bg-success"
      : status === "investigating" || status === "remediating" || status === "degraded" || status === "attention"
        ? "bg-warning"
        : status === "resolved" || status === "remediated" || status === "applied"
          ? "bg-success"
          : status === "contained" || status === "acknowledged"
            ? "bg-info"
            : "bg-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/60 px-2 py-0.5 text-[11px] font-medium capitalize text-muted-foreground",
        className
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", dot)} />
      {status}
    </span>
  );
}
