"use client";

import { useState } from "react";
import Link from "next/link";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/lib/store";
import { fetchApi } from "@/lib/api-client";
import { Wrench, Plus, Workflow } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Button } from "@/components/ui/button";

import { AutomationStats } from "@/components/automation/AutomationStats";
import { AgentControlCenter } from "@/components/automation/AgentControlCenter";
import { RunbookTable } from "@/components/automation/RunbookTable";
import { PendingApprovals } from "@/components/automation/PendingApprovals";
import { ExecutionTable } from "@/components/automation/ExecutionTable";
import { CreateRunbookDialog } from "@/components/automation/CreateRunbookDialog";

export default function AutomationPage() {
  const queryClient = useQueryClient();
  const user = useAppStore((s) => s.user);
  const isAdmin = user?.role === "Super Admin" || user?.role === "organization_admin";

  const { data: telemetry, isLoading: loadingTelemetry } = useQuery<any>({
    queryKey: ["risk-intelligence"],
    queryFn: () => fetchApi("/v1/risk/intelligence"),
  });

  const { data: overview, isLoading: loadingOverview } = useQuery<any>({
    queryKey: ["automation-overview"],
    queryFn: () => fetchApi("/v1/automation/overview"),
    refetchInterval: 10000,
  });
  
  const { data: agent, isLoading: loadingAgent } = useQuery<any>({
    queryKey: ["automation-agent"],
    queryFn: () => fetchApi("/v1/automation/agent/status"),
    refetchInterval: 5000,
  });

  const { data: rulesData, isLoading: loadingRules } = useQuery<any>({
    queryKey: ["automation-rules"],
    queryFn: () => fetchApi("/v1/automation/rules"),
    refetchInterval: 10000,
  });

  const { data: approvalsData, isLoading: loadingApprovals } = useQuery<any>({
    queryKey: ["automation-approvals"],
    queryFn: () => fetchApi("/v1/automation/approvals"),
    refetchInterval: 10000,
  });

  const { data: executionsData, isLoading: loadingExecutions } = useQuery<any>({
    queryKey: ["automation-executions"],
    queryFn: () => fetchApi("/v1/automation/executions"),
    refetchInterval: 10000,
  });

  const toggleMutation = useMutation({
    mutationFn: (id: string) => fetchApi(`/v1/automation/rules/${id}/toggle`, { method: "PATCH" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["automation-rules"] })
  });

  const rules = rulesData?.rules || [];
  const approvals = approvalsData?.approvals || [];
  const executions = executionsData?.executions || [];

  if (!loadingTelemetry && telemetry?.asset_count === 0 && rules.length === 0) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader
          title="Automation Control Center"
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
        title="Automation Control Center"
        description="Self-healing runbooks that remediate known issues without human intervention — every action is logged."
      >
        {isAdmin && (
          <CreateRunbookDialog />
        )}
        <Button variant="gradient" asChild>
          <Link href="/remediation">
            <Wrench className="h-4 w-4 mr-1.5" /> Remediation queue
          </Link>
        </Button>
      </PageHeader>

      <AgentControlCenter agent={agent} isAdmin={isAdmin} />
      <AutomationStats overview={overview} />
      
      <PendingApprovals approvals={approvals} isAdmin={isAdmin} />

      <h3 className="mb-4 text-sm font-semibold tracking-tight text-foreground">Active Runbooks</h3>
      <RunbookTable 
        rules={rules} 
        isAdmin={isAdmin} 
        onToggle={(id) => toggleMutation.mutate(id)} 
      />

      <ExecutionTable executions={executions} />
    </div>
  );
}
