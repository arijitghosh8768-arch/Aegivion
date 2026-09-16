"use client";

import { motion } from "framer-motion";
import { AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";

export function PendingApprovals({ approvals, isAdmin }: { approvals: any[]; isAdmin: boolean }) {
  if (!approvals || approvals.length === 0) return null;

  return (
    <div className="mb-8">
      <h3 className="mb-4 text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 text-amber-500" /> Pending Approvals
      </h3>
      <div className="grid gap-3 lg:grid-cols-2">
        {approvals.map((app, i) => (
          <motion.div
            key={app.id || i}
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            className="flex flex-col justify-between rounded-xl border border-amber-500/30 bg-amber-500/5 p-4"
          >
            <div>
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="text-sm font-semibold text-foreground">{app.action_type || "Unknown Action"}</h4>
                  <p className="mt-1 text-xs text-muted-foreground">{app.finding_id || app.incident_id || "Target unspecified"}</p>
                </div>
                <div className="text-right">
                  <div className="text-[10px] uppercase text-muted-foreground">Risk Score</div>
                  <div className="font-bold tabular-nums text-destructive">{app.risk_score || "High"}</div>
                </div>
              </div>
            </div>
            {isAdmin && (
              <div className="mt-4 flex gap-2">
                <Button size="sm" variant="default" className="flex-1 bg-success hover:bg-success/90">
                  <CheckCircle className="mr-1.5 h-3.5 w-3.5" /> Approve
                </Button>
                <Button size="sm" variant="outline" className="flex-1 text-destructive hover:text-destructive">
                  <XCircle className="mr-1.5 h-3.5 w-3.5" /> Reject
                </Button>
              </div>
            )}
          </motion.div>
        ))}
      </div>
    </div>
  );
}
