"use client";

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Radar, ShieldCheck, Bug, FileCheck2, ChevronDown, ChevronUp, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchApi } from "@/lib/api-client";
import { PageHeader } from "@/components/shared/page-header";
import { SeverityBadge, StatusPill } from "@/components/shared/severity";
import { ProviderMark } from "@/components/shared/provider-mark";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import type { ProviderId } from "@/lib/types";

type FindingStatus = "open" | "acknowledged" | "remediating" | "remediated";

interface LiveFinding {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: FindingStatus;
  rule_id: string;
  resource_id: string;
  resource_name: string;
  resource_type: string;
  cloud_provider: string;
  resource_region: string;
  risk_score: number;
  evidence: Record<string, unknown>;
  mitre_technique?: string;
  mitre_tactic?: string;
  remediation?: string[];
}

function getCategoryFromType(type: string, ruleId: string): string {
  const t = ((type || "") + " " + (ruleId || "")).toLowerCase();
  if (t.includes("iam") || t.includes("user") || t.includes("role")) return "iam";
  if (t.includes("s3") || t.includes("bucket")) return "s3";
  if (t.includes("ec2") || t.includes("instance")) return "ec2";
  if (t.includes("sg") || t.includes("security_group") || t.includes("nsg")) return "security-group";
  if (t.includes("cloudtrail") || t.includes("trail")) return "cloudtrail";
  if (t.includes("cloudwatch") || t.includes("log")) return "cloudwatch";
  if (t.includes("k8s") || t.includes("gke") || t.includes("eks") || t.includes("kubernetes")) return "k8s";
  if (t.includes("rds") || t.includes("sql") || t.includes("db") || t.includes("database")) return "database";
  return "all";
}

const CATEGORIES = [
  { id: "all", label: "All" },
  { id: "iam", label: "IAM" },
  { id: "s3", label: "S3" },
  { id: "ec2", label: "EC2" },
  { id: "security-group", label: "Security Groups" },
  { id: "cloudtrail", label: "CloudTrail" },
  { id: "cloudwatch", label: "CloudWatch" },
  { id: "k8s", label: "Kubernetes" },
  { id: "database", label: "Databases" },
] as const;

export default function DetectionEnginePage() {
  const queryClient = useQueryClient();
  const [category, setCategory] = useState<string>("all");
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data: rawData, isLoading, isError } = useQuery({
    queryKey: ["findings-list"],
    queryFn: () => fetchApi<{ findings: LiveFinding[] }>("/v1/findings"),
    refetchInterval: 30000,
  });

  const findings: LiveFinding[] = useMemo(() => rawData?.findings ?? [], [rawData]);

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: FindingStatus }) =>
      fetchApi(`/v1/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["findings-list"] }),
  });

  const scanMutation = useMutation({
    mutationFn: () => fetchApi("/v1/findings/scan", { method: "POST" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["findings-list"] }),
  });

  const filtered = useMemo(() => {
    if (category === "all") return findings;
    return findings.filter((f) => getCategoryFromType(f.resource_type, f.rule_id) === category);
  }, [findings, category]);

  const open = findings.filter((f) => f.status === "open").length;
  const critical = findings.filter((f) => f.severity === "critical").length;
  const autoFixable = findings.filter((f) => f.status === "open" && (f.remediation?.length ?? 0) > 0).length;

  return (
    <div>
      <PageHeader
        title="Detection Engine"
        description="Misconfigurations, vulnerabilities and compliance drift — with evidence and confidence scores."
      >
        <Button variant="outline" onClick={() => scanMutation.mutate()} disabled={scanMutation.isPending}>
          {scanMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
          {scanMutation.isPending ? "Scanning…" : "Scan now"}
        </Button>
        <Button variant="gradient" disabled={autoFixable === 0}>
          <ShieldCheck className="h-4 w-4" /> Auto-fix ({autoFixable})
        </Button>
      </PageHeader>

      {/* summary */}
      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Total findings", value: isLoading ? "…" : findings.length, icon: <Bug className="h-4 w-4" /> },
          { label: "Open", value: isLoading ? "…" : open, tint: open > 0 ? "text-destructive" : "" },
          { label: "Critical", value: isLoading ? "…" : critical, tint: critical > 0 ? "text-destructive" : "" },
          { label: "Auto-fixable", value: isLoading ? "…" : autoFixable, tint: "text-success", icon: <FileCheck2 className="h-4 w-4" /> },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="rounded-2xl border border-border bg-card p-4 shadow-soft"
          >
            <div className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
              {s.icon}
              {s.label}
            </div>
            <div className={cn("mt-1 text-2xl font-bold tabular-nums tracking-tight", s.tint)}>{s.value}</div>
          </motion.div>
        ))}
      </div>

      <Tabs defaultValue="misconfigurations">
        <TabsList>
          <TabsTrigger value="misconfigurations">Misconfigurations</TabsTrigger>
          <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
        </TabsList>

        <TabsContent value="misconfigurations">
          <FilterChips category={category} setCategory={setCategory} />
          {isLoading && (
            <div className="flex items-center justify-center py-16 text-muted-foreground gap-2">
              <Loader2 className="h-5 w-5 animate-spin" /> Loading findings…
            </div>
          )}
          {isError && (
            <div className="rounded-2xl border border-destructive/30 bg-destructive/5 py-10 text-center text-sm text-destructive">
              Failed to load findings. Make sure the backend is running.
            </div>
          )}
          {!isLoading && !isError && (
            <FindingsList
              findings={filtered}
              expanded={expanded}
              setExpanded={setExpanded}
              updateStatus={(id, status) => updateMutation.mutate({ id, status })}
            />
          )}
        </TabsContent>

        <TabsContent value="vulnerabilities">
          <FilterChips category={category} setCategory={setCategory} showVulnOnly />
          {!isLoading && (
            <FindingsList
              findings={filtered.filter((f) => f.mitre_technique || f.mitre_tactic)}
              expanded={expanded}
              setExpanded={setExpanded}
              updateStatus={(id, status) => updateMutation.mutate({ id, status })}
            />
          )}
        </TabsContent>

        <TabsContent value="compliance">
          <ComplianceView />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function FilterChips({
  category,
  setCategory,
  showVulnOnly,
}: {
  category: string;
  setCategory: (c: string) => void;
  showVulnOnly?: boolean;
}) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-1.5">
      {CATEGORIES.map((c) => {
        const on = category === c.id;
        return (
          <button
            key={c.id}
            onClick={() => setCategory(c.id)}
            className={cn(
              "cursor-pointer rounded-full border px-3 py-1 text-[11.5px] font-medium transition",
              on
                ? "border-primary/30 bg-primary/10 text-primary"
                : "border-border bg-card text-muted-foreground hover:border-primary/30 hover:text-foreground"
            )}
          >
            {c.label}
          </button>
        );
      })}
      {showVulnOnly && (
        <Badge variant="warning" className="ml-1">
          14 CVEs tracked
        </Badge>
      )}
    </div>
  );
}

function FindingsList({
  findings,
  expanded,
  setExpanded,
  updateStatus,
}: {
  findings: LiveFinding[];
  expanded: string | null;
  setExpanded: (id: string | null) => void;
  updateStatus: (id: string, status: FindingStatus) => void;
}) {
  if (findings.length === 0) {
    return (
      <div className="rounded-2xl border border-border bg-card py-14 text-center text-sm text-muted-foreground">
        No findings detected. 🎉 Your environment looks clean!
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {findings.map((f) => {
        const isOpen = expanded === f.id;
        const provider = (f.cloud_provider?.toLowerCase() ?? "aws") as ProviderId;
        const evidenceStr = typeof f.evidence === "object"
          ? JSON.stringify(f.evidence, null, 2)
          : String(f.evidence ?? "No evidence available");

        return (
          <motion.div
            key={f.id}
            layout
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft"
          >
            <button
              onClick={() => setExpanded(isOpen ? null : f.id)}
              className="flex w-full cursor-pointer items-center gap-3 px-4 py-3.5 text-left transition hover:bg-muted/30"
            >
              <SeverityBadge severity={f.severity} showDot={false} className="w-[74px] justify-center" />
              <ProviderMark provider={provider} size={28} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13.5px] font-semibold">{f.title}</div>
                <div className="mt-0.5 flex items-center gap-2 text-[11.5px] text-muted-foreground">
                  <span>{f.resource_type}</span>
                  <span className="h-0.5 w-0.5 rounded-full bg-muted-foreground" />
                  <span>Risk {f.risk_score}/100</span>
                  {f.mitre_technique && (
                    <>
                      <span className="h-0.5 w-0.5 rounded-full bg-muted-foreground" />
                      <span className="font-semibold text-warning">{f.mitre_technique}</span>
                    </>
                  )}
                </div>
              </div>
              <div className="hidden sm:block">
                <StatusPill status={f.status} />
              </div>
              {isOpen ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
            </button>

            {isOpen && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="border-t border-border bg-muted/20 px-4 py-4">
                <p className="text-[12.5px] leading-relaxed text-muted-foreground">{f.description || "No description available."}</p>

                <div className="mt-3 rounded-xl border border-border bg-card/70 p-3">
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Evidence</div>
                  <code className="whitespace-pre-wrap text-[11.5px] text-foreground">{evidenceStr}</code>
                </div>

                {(f.remediation?.length ?? 0) > 0 && (
                  <div className="mt-3 rounded-xl border border-border bg-card/70 p-3">
                    <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Remediation Steps</div>
                    <code className="whitespace-pre-wrap text-[11.5px] text-foreground">
                      {Array.isArray(f.remediation) ? f.remediation.join("\n") : f.remediation}
                    </code>
                  </div>
                )}

                <div className="mt-3 flex flex-wrap gap-1.5">
                  {f.rule_id && <Badge variant="soft">{f.rule_id}</Badge>}
                  {f.mitre_technique && <Badge variant="purple">{f.mitre_technique}</Badge>}
                  {f.mitre_tactic && <Badge variant="purple">{f.mitre_tactic}</Badge>}
                  {(f.remediation?.length ?? 0) > 0 && <Badge variant="success">Auto-fix available</Badge>}
                </div>

                {f.status === "open" && (
                  <div className="mt-4 flex flex-wrap gap-2">
                    <Button size="sm" onClick={() => updateStatus(f.id, "acknowledged")}>
                      <CheckCircle2 className="h-3.5 w-3.5" /> Acknowledge
                    </Button>
                    <Button size="sm" variant="success" onClick={() => updateStatus(f.id, "remediating")}>
                      <ShieldCheck className="h-3.5 w-3.5" /> Start remediation
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => updateStatus(f.id, "remediated")}>
                      <XCircle className="h-3.5 w-3.5" /> Mark remediated
                    </Button>
                  </div>
                )}
              </motion.div>
            )}
          </motion.div>
        );
      })}
    </div>
  );
}

function ComplianceView() {
  const { data: complianceData, isLoading } = useQuery({
    queryKey: ["compliance-summary"],
    queryFn: () => fetchApi<any>("/v1/compliance/summary"),
  });

  const framework = complianceData?.frameworks?.[0];
  const items: any[] = framework?.items ?? [];
  const overall = complianceData?.overall;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground gap-2">
        <Loader2 className="h-5 w-5 animate-spin" /> Loading compliance data…
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="rounded-2xl border border-border bg-card py-14 text-center text-sm text-muted-foreground">
        No compliance data yet. Run a scan to generate compliance results.
      </div>
    );
  }

  const passRate = overall?.pass_rate ?? 0;
  const passVariant = passRate >= 80 ? "success" : passRate >= 60 ? "warning" : "destructive";

  return (
    <div className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft">
      <div className="grid grid-cols-[1fr_auto] items-center gap-4 border-b border-border bg-muted/40 px-5 py-3.5">
        <div>
          <h3 className="text-[14px] font-semibold">{framework?.title ?? "CIS AWS Benchmark"} — evidence pack</h3>
          <p className="text-[11.5px] text-muted-foreground">
            {overall?.total_controls ?? 0} controls checked
          </p>
        </div>
        <Badge variant={passVariant}>{passRate}% compliant</Badge>
      </div>
      <div className="divide-y divide-border/60">
        {items.map((r: any) => (
          <div key={r.control_code} className="flex items-center gap-4 px-5 py-3">
            <span className="w-16 shrink-0 font-mono text-[11px] font-bold text-primary">{r.control_code}</span>
            <span className="flex-1 text-[12.5px] font-medium">{r.title}</span>
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-24 overflow-hidden rounded-full bg-muted">
                <div
                  className={cn(
                    "h-full rounded-full",
                    r.status === "pass" ? "bg-success" : r.status === "fail" ? "bg-destructive" : "bg-muted-foreground"
                  )}
                  style={{ width: r.status === "pass" ? "100%" : r.status === "fail" ? "30%" : "60%" }}
                />
              </div>
              <span className="w-20 text-right text-[11.5px] font-semibold tabular-nums text-muted-foreground capitalize">
                {r.status}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

