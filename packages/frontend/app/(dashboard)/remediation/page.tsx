"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Wrench, Check, X, Loader2, RotateCcw, ChevronDown, ChevronUp, ShieldCheck, AlertTriangle } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { StatusPill } from "@/components/shared/severity";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  getRemediationPlans,
  approveRemediationPlan,
  rejectRemediationPlan,
  executeRemediationPlan,
  rollbackRemediationPlan,
  RemediationPlanItem
} from "@/lib/api-client";

export default function RemediationPage() {
  const [plans, setPlans] = useState<RemediationPlanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  // Confirmation dialog state
  const [confirmModal, setConfirmModal] = useState<{
    open: boolean;
    type: "execute" | "rollback";
    plan: RemediationPlanItem | null;
  }>({
    open: false,
    type: "execute",
    plan: null,
  });

  const loadPlans = async () => {
    try {
      setLoading(true);
      const res = await getRemediationPlans();
      if (res && res.data) {
        setPlans(res.data);
      }
    } catch (e) {
      console.error("Failed to load remediation plans", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPlans();
  }, []);

  const handleApprove = async (planId: string) => {
    setActionLoading(planId);
    try {
      await approveRemediationPlan(planId);
      await loadPlans();
    } catch (err: any) {
      alert("Failed to approve plan: " + err.message);
    } finally {
      setActionLoading(null);
    }
  };

  const handleReject = async (planId: string) => {
    setActionLoading(planId);
    try {
      await rejectRemediationPlan(planId, "Rejected by security operator");
      await loadPlans();
    } catch (err: any) {
      alert("Failed to reject plan: " + err.message);
    } finally {
      setActionLoading(null);
    }
  };

  const triggerExecute = async () => {
    if (!confirmModal.plan) return;
    const planId = confirmModal.plan.id;
    setConfirmModal({ open: false, type: "execute", plan: null });
    setActionLoading(planId);
    try {
      await executeRemediationPlan(planId);
      await loadPlans();
    } catch (err: any) {
      alert("Failed to execute remediation: " + err.message);
    } finally {
      setActionLoading(null);
    }
  };

  const triggerRollback = async () => {
    if (!confirmModal.plan) return;
    const planId = confirmModal.plan.id;
    setConfirmModal({ open: false, type: "rollback", plan: null });
    setActionLoading(planId);
    try {
      await rollbackRemediationPlan(planId, "Manual rollback requested by operator");
      await loadPlans();
    } catch (err: any) {
      alert("Failed to rollback plan: " + err.message);
    } finally {
      setActionLoading(null);
    }
  };

  const pending = plans.filter((p) => p.status === "PENDING_APPROVAL").length;
  const approved = plans.filter((p) => p.status === "APPROVED").length;
  const verified = plans.filter((p) => p.status === "VERIFIED" || p.status === "EXECUTED").length;
  const rolledBack = plans.filter((p) => p.status === "ROLLED_BACK").length;

  return (
    <div>
      <PageHeader
        title="Remediation"
        description="Zero-Trust safe remediation engine — human-in-the-loop approvals, pre-state snapshots, live verification, and auto-rollback."
      >
        <Button variant="outline" onClick={loadPlans} disabled={loading}>
          <RotateCcw className={cn("h-4 w-4", loading && "animate-spin")} /> Refresh
        </Button>
      </PageHeader>

      {/* Summary Metrics */}
      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Pending approval", value: pending, tint: "text-warning" },
          { label: "Approved (Ready)", value: approved, tint: "text-info" },
          { label: "Verified / Executed", value: verified, tint: "text-success" },
          { label: "Rolled back", value: rolledBack, tint: "text-destructive" },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="rounded-2xl border border-border bg-card p-4 shadow-soft"
          >
            <div className="text-xs font-medium text-muted-foreground">{s.label}</div>
            <div className={cn("mt-1 text-2xl font-bold tabular-nums tracking-tight", s.tint)}>{s.value}</div>
          </motion.div>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : plans.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-dashed border-border py-12 text-center bg-card">
          <Wrench className="mb-3 h-8 w-8 text-muted-foreground" />
          <h3 className="text-[14px] font-semibold">No remediation plans yet</h3>
          <p className="mt-1 text-[12.5px] text-muted-foreground">
            Remediation plans generated for active findings will appear here for review and execution.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {plans.map((plan, i) => {
            const isOpen = expanded === plan.id;
            const isProcessing = actionLoading === plan.id;
            const action = plan.actions && plan.actions[0];
            const actionType = action?.action_type || plan.action_type || "REMEDIATION_ACTION";

            return (
              <motion.div
                key={plan.id}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft"
              >
                <div className="flex items-center gap-3 px-4 py-3.5">
                  <span
                    className={cn(
                      "flex h-8 w-8 shrink-0 items-center justify-center rounded-xl",
                      plan.status === "VERIFIED"
                        ? "bg-success/12 text-success"
                        : plan.status === "ROLLED_BACK" || plan.status === "FAILED_VERIFICATION"
                        ? "bg-destructive/12 text-destructive"
                        : plan.status === "APPROVED"
                        ? "bg-info/12 text-info"
                        : "bg-warning/12 text-warning"
                    )}
                  >
                    {plan.status === "VERIFIED" ? (
                      <ShieldCheck className="h-4 w-4" />
                    ) : plan.status === "ROLLED_BACK" ? (
                      <RotateCcw className="h-4 w-4" />
                    ) : (
                      <Wrench className="h-4 w-4" />
                    )}
                  </span>

                  <button
                    onClick={() => setExpanded(isOpen ? null : plan.id)}
                    className="min-w-0 flex-1 cursor-pointer text-left"
                  >
                    <div className="truncate text-sm font-semibold">{actionType.replace(/_/g, " ")}</div>
                    <div className="mt-0.5 flex items-center gap-2 text-xs text-muted-foreground">
                      <span className="font-mono">{plan.resource_id}</span>
                      <span>·</span>
                      <span>{plan.created_at ? new Date(plan.created_at).toLocaleDateString() : "Recent"}</span>
                      {plan.expires_at && plan.status === "PENDING_APPROVAL" && (
                        <>
                          <span>·</span>
                          <span className="text-warning">TTL: {new Date(plan.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        </>
                      )}
                    </div>
                  </button>

                  <Badge
                    variant={
                      plan.status === "VERIFIED"
                        ? "success"
                        : plan.status === "APPROVED"
                        ? "default"
                        : plan.status === "PENDING_APPROVAL"
                        ? "secondary"
                        : "destructive"
                    }
                    className="font-mono text-[11px]"
                  >
                    {plan.status}
                  </Badge>

                  {isOpen ? (
                    <ChevronUp className="h-4 w-4 text-muted-foreground" />
                  ) : (
                    <ChevronDown className="h-4 w-4 text-muted-foreground" />
                  )}
                </div>

                {isOpen && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    className="border-t border-border bg-muted/20 px-4 py-4"
                  >
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div>
                        <div className="mb-1 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">
                          Action Parameters
                        </div>
                        <pre className="code-block max-h-40 overflow-auto rounded-xl border border-border bg-card p-2 text-xs">
                          {JSON.stringify(action?.parameters || {}, null, 2)}
                        </pre>
                      </div>
                      <div>
                        <div className="mb-1 text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">
                          Audit & Verification Details
                        </div>
                        <div className="rounded-xl border border-border bg-card p-3 text-xs space-y-1">
                          <div><strong>Plan ID:</strong> <span className="font-mono">{plan.id}</span></div>
                          {plan.finding_id && <div><strong>Finding ID:</strong> <span className="font-mono">{plan.finding_id}</span></div>}
                          {action?.aws_request_id && <div><strong>AWS Request ID:</strong> <span className="font-mono">{action.aws_request_id}</span></div>}
                          <div><strong>Execution Status:</strong> {plan.status}</div>
                        </div>
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-border/70 pt-3">
                      {plan.status === "PENDING_APPROVAL" && (
                        <>
                          <Button
                            size="sm"
                            variant="success"
                            onClick={() => handleApprove(plan.id)}
                            disabled={isProcessing}
                          >
                            <Check className="h-3.5 w-3.5" /> Approve Plan
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleReject(plan.id)}
                            disabled={isProcessing}
                          >
                            <X className="h-3.5 w-3.5" /> Reject Plan
                          </Button>
                        </>
                      )}

                      {plan.status === "APPROVED" && (
                        <Button
                          size="sm"
                          variant="gradient"
                          onClick={() => setConfirmModal({ open: true, type: "execute", plan })}
                          disabled={isProcessing}
                        >
                          <Wrench className="h-3.5 w-3.5" /> Execute Safe Modification
                        </Button>
                      )}

                      {(plan.status === "VERIFIED" || plan.status === "EXECUTED" || plan.status === "FAILED_VERIFICATION") && (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => setConfirmModal({ open: true, type: "rollback", plan })}
                          disabled={isProcessing}
                        >
                          <RotateCcw className="h-3.5 w-3.5" /> Rollback to Snapshot
                        </Button>
                      )}

                      {plan.status === "ROLLED_BACK" && (
                        <div className="flex items-center gap-2 text-xs font-semibold text-muted-foreground">
                          <Check className="h-3.5 w-3.5 text-success" /> Pre-state successfully restored
                        </div>
                      )}

                      {isProcessing && (
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Processing request…
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </motion.div>
            );
          })}
        </div>
      )}

      {/* Confirmation Modal */}
      <Dialog open={confirmModal.open} onOpenChange={(o) => setConfirmModal((prev) => ({ ...prev, open: o }))}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-warning" />
              {confirmModal.type === "execute" ? "Confirm Remediation Execution" : "Confirm Remediation Rollback"}
            </DialogTitle>
            <DialogDescription>
              {confirmModal.type === "execute"
                ? `You are about to execute the live cloud change for ${confirmModal.plan?.resource_id}. A pre-state snapshot will be captured immediately before execution.`
                : `You are about to restore the pre-state snapshot for ${confirmModal.plan?.resource_id}. This will revert the AWS resource to its exact prior configuration.`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setConfirmModal({ open: false, type: "execute", plan: null })}>
              Cancel
            </Button>
            <Button
              variant={confirmModal.type === "execute" ? "gradient" : "destructive"}
              onClick={confirmModal.type === "execute" ? triggerExecute : triggerRollback}
            >
              {confirmModal.type === "execute" ? "Execute Modification" : "Rollback Resource"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
