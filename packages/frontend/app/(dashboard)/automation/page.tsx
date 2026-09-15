"use client";

import { useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/lib/store";
import { fetchApi } from "@/lib/api-client";
import { Workflow, Zap, ShieldCheck, Clock3, ArrowRight, Play, Pause, Wrench, Plus } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

interface Rule {
  id: string;
  name: string;
  desc: string;
  trigger: string;
  action: string;
  runs: number;
  lastRun: string;
  enabled: boolean;
  target: string;
  accent: string;
}

export default function AutomationPage() {
  const queryClient = useQueryClient();
  const user = useAppStore((s) => s.user);
  const isAdmin = user?.role === "Super Admin" || user?.role === "organization_admin";

  const [createOpen, setCreateOpen] = useState(false);
  const [newRule, setNewRule] = useState({ name: "", description: "", trigger: "", action: "" });

  const { data: telemetry, isLoading: loadingTelemetry } = useQuery<{ asset_count: number }>({
    queryKey: ["risk-intelligence"],
    queryFn: () => fetchApi<{ asset_count: number }>("/v1/risk/intelligence"),
  });

  const { data: rulesData, isLoading: loadingRules } = useQuery<{ rules: Rule[] }>({
    queryKey: ["automation-rules"],
    queryFn: () => fetchApi<{ rules: Rule[] }>("/v1/automation/rules"),
  });

  const createMutation = useMutation({
    mutationFn: (rule: typeof newRule) => fetchApi("/v1/automation/rules", { method: "POST", body: JSON.stringify(rule) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["automation-rules"] });
      setCreateOpen(false);
      setNewRule({ name: "", description: "", trigger: "", action: "" });
    }
  });

  const toggleMutation = useMutation({
    mutationFn: (id: string) => fetchApi(`/v1/automation/rules/${id}/toggle`, { method: "PATCH" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["automation-rules"] })
  });

  const rules = rulesData?.rules || [];
  const enabled = rules.filter((r) => r.enabled).length;
  const totalRuns = rules.reduce((s, r) => s + r.runs, 0);

  if (!loadingTelemetry && telemetry && telemetry.asset_count === 0 && rules.length === 0) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader
          title="Automation"
          description="Self-healing runbooks that remediate known issues without human intervention — every action is logged."
        />
        <div className="mt-8 flex flex-1 flex-col items-center justify-center rounded-2xl border border-dashed border-border bg-card/30 p-8 text-center">
          <Workflow className="mb-4 h-12 w-12 text-muted-foreground/30" />
          <h3 className="text-lg font-semibold">No Runbooks Active</h3>
          <p className="mt-2 max-w-sm text-sm text-muted-foreground">
            Connect your cloud environment to automatically provision baseline remediation runbooks.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="Automation"
        description="Self-healing runbooks that remediate known issues without human intervention — every action is logged."
      >
        {isAdmin && (
          <Button variant="outline" onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4" /> Create Rule
          </Button>
        )}
        <Button variant="gradient" asChild>
          <Link href="/remediation">
            <Wrench className="h-4 w-4" /> Remediation queue
          </Link>
        </Button>
      </PageHeader>

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Active runbooks", value: enabled, tint: "text-success" },
          { label: "Total rules", value: rules.length },
          { label: "Executions (30d)", value: totalRuns, tint: "text-primary" },
          { label: "Auto-resolved", value: "128", tint: "text-success" },
        ].map((s, i) => (
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

      <div className="space-y-3">
        {rules.map((r, i) => (
          <motion.div
            key={r.id}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.04 }}
            className={cn(
              "rounded-2xl border bg-card p-4 shadow-soft transition-colors",
              r.enabled ? "border-border" : "border-border/60 opacity-70"
            )}
          >
            <div className="flex flex-wrap items-center gap-3">
              <span className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-xl", r.accent)}>
                {r.enabled ? <Zap className="h-4.5 w-4.5" /> : <Workflow className="h-4.5 w-4.5" />}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-[13.5px] font-semibold">{r.name}</span>
                  {!r.enabled && <Badge variant="soft">Paused</Badge>}
                </div>
                <p className="mt-0.5 line-clamp-1 text-[11.5px] text-muted-foreground">{r.desc}</p>
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
                  <div className="text-[11.5px] font-medium tabular-nums">{r.runs}</div>
                </div>
              </div>
              {isAdmin ? (
                <Switch checked={r.enabled} onCheckedChange={() => toggleMutation.mutate(r.id)} aria-label={`Toggle ${r.name}`} />
              ) : (
                <Badge variant="outline">{r.enabled ? "Active" : "Paused"}</Badge>
              )}
            </div>
            <div className="mt-3 flex items-center gap-3 border-t border-border/60 pt-2.5 text-[10.5px] text-muted-foreground">
              <Clock3 className="h-3 w-3" /> Last run {r.lastRun}
              <Link href={r.target} className="ml-auto flex items-center gap-0.5 font-semibold text-primary transition hover:gap-1.5">
                View related <ArrowRight className="h-3 w-3" />
              </Link>
            </div>
          </motion.div>
        ))}
        {!loadingRules && rules.length === 0 && (
          <div className="py-8 text-center text-sm text-muted-foreground border rounded-2xl bg-card border-dashed">
            No automation rules configured yet.
          </div>
        )}
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Automation Rule</DialogTitle>
            <DialogDescription>Define a trigger and action to automate your security operations.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Rule Name</Label>
              <Input value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} placeholder="e.g., Auto-quarantine public S3 buckets" />
            </div>
            <div className="space-y-2">
              <Label>Description</Label>
              <Input value={newRule.description} onChange={e => setNewRule({...newRule, description: e.target.value})} placeholder="What does this rule do?" />
            </div>
            <div className="space-y-2">
              <Label>Trigger Condition</Label>
              <Input value={newRule.trigger} onChange={e => setNewRule({...newRule, trigger: e.target.value})} placeholder="e.g., S3 bucket > public-read" />
            </div>
            <div className="space-y-2">
              <Label>Action</Label>
              <Input value={newRule.action} onChange={e => setNewRule({...newRule, action: e.target.value})} placeholder="e.g., Apply public access block" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button onClick={() => createMutation.mutate(newRule)} disabled={createMutation.isPending || !newRule.name}>
              {createMutation.isPending ? "Creating..." : "Create Rule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
