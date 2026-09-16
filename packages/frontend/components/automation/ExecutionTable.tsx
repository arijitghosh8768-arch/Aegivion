"use client";

import { CheckCircle2, XCircle, Clock, Search } from "lucide-react";
import { cn } from "@/lib/utils";

export function ExecutionTable({ executions }: { executions: any[] }) {
  if (!executions || executions.length === 0) return null;

  return (
    <div className="mt-8 rounded-2xl border border-border bg-card">
      <div className="border-b border-border p-4 flex items-center justify-between">
        <h3 className="text-sm font-semibold">Recent Executions</h3>
      </div>
      <div className="divide-y divide-border/50">
        {executions.map((exec, i) => (
          <div key={exec.id || i} className="flex items-center justify-between p-4 hover:bg-muted/20 transition-colors">
            <div className="flex items-center gap-3">
              {exec.status === "SUCCESS" ? (
                <CheckCircle2 className="h-4 w-4 text-success" />
              ) : exec.status === "FAILED" ? (
                <XCircle className="h-4 w-4 text-destructive" />
              ) : (
                <Clock className="h-4 w-4 text-amber-500" />
              )}
              <div>
                <div className="text-sm font-medium">{exec.action_type || "Action Executed"}</div>
                <div className="text-[11px] text-muted-foreground mt-0.5">
                  {exec.provider} • {exec.resource_id}
                </div>
              </div>
            </div>
            <div className="text-right">
              <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{exec.status}</div>
              <div className="text-[10px] text-muted-foreground mt-0.5">{new Date(exec.created_at || Date.now()).toLocaleString()}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
