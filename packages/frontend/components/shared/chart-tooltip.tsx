import { cn } from "@/lib/utils";

export function ChartTooltip({
  active,
  payload,
  label,
  formatter,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number | string; color?: string; fill?: string }>;
  label?: string;
  formatter?: (value: number | string, name: string) => string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-xl border border-border bg-popover/95 px-3.5 py-2.5 shadow-lift backdrop-blur-md">
      {label && <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{label}</div>}
      <div className="space-y-1">
        {payload.map((p, i) => (
          <div key={i} className="flex items-center justify-between gap-6 text-xs">
            <span className="flex items-center gap-1.5 text-muted-foreground">
              <span className="h-2 w-2 rounded-full" style={{ background: p.color ?? p.fill }} />
              {p.name}
            </span>
            <span className={cn("font-semibold tabular-nums")}>
              {formatter ? formatter(p.value ?? 0, p.name ?? "") : p.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
