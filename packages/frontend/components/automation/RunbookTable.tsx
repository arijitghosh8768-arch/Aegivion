"use client";

import { motion } from "framer-motion";
import { Zap, Workflow } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

export function RunbookTable({ rules, isAdmin, onToggle }: { rules: any[]; isAdmin: boolean; onToggle: (id: string) => void }) {
  if (!rules || rules.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-border bg-card/30 p-8 text-center">
        <Workflow className="mb-4 h-12 w-12 text-muted-foreground/30" />
        <h3 className="text-lg font-semibold">No Runbooks Active</h3>
        <p className="mt-2 max-w-sm text-sm text-muted-foreground">
          Create a runbook to automatically remediate known issues.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {rules.map((r, i) => (
        <motion.div
          key={r.id || i}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: i * 0.04 }}
          className={cn(
            "rounded-2xl border bg-card p-4 shadow-soft transition-colors",
            r.enabled ? "border-border" : "border-border/60 opacity-70"
          )}
        >
          <div className="flex flex-wrap items-center gap-3">
            <span className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-xl", r.accent || "bg-primary/10 text-primary")}>
              {r.enabled ? <Zap className="h-4.5 w-4.5" /> : <Workflow className="h-4.5 w-4.5" />}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate text-[13.5px] font-semibold">{r.name}</span>
                {!r.enabled && <Badge variant="soft">Paused</Badge>}
              </div>
              <p className="mt-0.5 line-clamp-1 text-[11.5px] text-muted-foreground">{r.description || r.desc}</p>
            </div>
            <div className="hidden items-center gap-4 md:flex">
              <div className="text-right">
                <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Trigger</div>
                <div className="text-[11.5px] font-medium">{r.trigger}</div>
              </div>
              <div className="text-right">
                <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Action</div>
                <div className="text-[11.5px] font-medium">{r.action}</div>
              </div>
              <div className="text-right">
                <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Runs</div>
                <div className="text-[11.5px] font-medium tabular-nums">{r.runs || 0}</div>
              </div>
              {isAdmin && (
                <div className="ml-2 flex items-center border-l pl-4">
                  <Switch
                    checked={r.enabled}
                    onCheckedChange={() => onToggle(r.id)}
                  />
                </div>
              )}
            </div>
          </div>
        </motion.div>
      ))}
    </div>
  );
}
