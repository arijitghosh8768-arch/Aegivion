"use client";

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Radar, ShieldCheck, Bug, FileCheck2, ChevronDown, ChevronUp, CheckCircle2, XCircle } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { SeverityBadge, StatusPill } from "@/components/shared/severity";
import { ProviderMark } from "@/components/shared/provider-mark";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { FINDINGS } from "@/lib/data/findings";
import { cn } from "@/lib/utils";
import type { Finding, FindingStatus } from "@/lib/types";

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
  const [findings, setFindings] = useState(FINDINGS);
  const [category, setCategory] = useState<string>("all");
  const [expanded, setExpanded] = useState<string | null>(FINDINGS[0]?.id ?? null);

  const filtered = useMemo(
    () => findings.filter((f) => category === "all" || f.category === category),
    [findings, category]
  );

  const updateStatus = (id: string, status: FindingStatus) =>
    setFindings((fs) => fs.map((f) => (f.id === id ? { ...f, status } : f)));

  const open = findings.filter((f) => f.status === "open").length;
  const critical = findings.filter((f) => f.severity === "critical").length;
  const autoFixable = findings.filter((f) => f.autoFixable && f.status === "open").length;

  return (
    <div>
      <PageHeader
        title="Detection Engine"
        description="Misconfigurations, vulnerabilities and compliance drift — with evidence and confidence scores."
      >
        <Button variant="outline">
          <Radar className="h-4 w-4" /> Scan now
        </Button>
        <Button variant="gradient">
          <ShieldCheck className="h-4 w-4" /> Auto-fix ({autoFixable})
        </Button>
      </PageHeader>

      {/* summary */}
      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Total findings", value: findings.length, icon: <Bug className="h-4 w-4" /> },
          { label: "Open", value: open, tint: "text-destructive" },
          { label: "Critical", value: critical, tint: "text-destructive" },
          { label: "Auto-fixable", value: autoFixable, tint: "text-success", icon: <FileCheck2 className="h-4 w-4" /> },
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
          <FindingsList
            findings={filtered}
            expanded={expanded}
            setExpanded={setExpanded}
            updateStatus={updateStatus}
          />
        </TabsContent>

        <TabsContent value="vulnerabilities">
          <FilterChips category={category} setCategory={setCategory} showVulnOnly />
          <FindingsList
            findings={filtered.filter((f) => f.cve || f.mitre?.length)}
            expanded={expanded}
            setExpanded={setExpanded}
            updateStatus={updateStatus}
          />
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
  findings: Finding[];
  expanded: string | null;
  setExpanded: (id: string | null) => void;
  updateStatus: (id: string, status: FindingStatus) => void;
}) {
  return (
    <div className="space-y-3">
      {findings.map((f) => {
        const isOpen = expanded === f.id;
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
              <ProviderMark provider={f.provider} size={28} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13.5px] font-semibold">{f.title}</div>
                <div className="mt-0.5 flex items-center gap-2 text-[11.5px] text-muted-foreground">
                  <span>{f.service}</span>
                  <span className="h-0.5 w-0.5 rounded-full bg-muted-foreground" />
                  <span>Confidence {f.confidence}%</span>
                  {f.cve && (
                    <>
                      <span className="h-0.5 w-0.5 rounded-full bg-muted-foreground" />
                      <span className="font-semibold text-warning">{f.cve}</span>
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
                <p className="text-[12.5px] leading-relaxed text-muted-foreground">{f.description}</p>

                <div className="mt-3 rounded-xl border border-border bg-card/70 p-3">
                  <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Evidence</div>
                  <code className="code-block text-[11.5px] text-foreground">{f.evidence}</code>
                </div>

                <div className="mt-3 flex flex-wrap gap-1.5">
                  <Badge variant="soft">{f.framework ?? "Custom policy"}</Badge>
                  {f.mitre?.map((m) => (
                    <Badge key={m} variant="purple">
                      {m}
                    </Badge>
                  ))}
                  {f.autoFixable && <Badge variant="success">Auto-fix available</Badge>}
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
      {findings.length === 0 && (
        <div className="rounded-2xl border border-border bg-card py-14 text-center text-sm text-muted-foreground">
          No findings in this category. 🎉
        </div>
      )}
    </div>
  );
}

function ComplianceView() {
  const rows = [
    { control: "IAM.1", title: "No root account access keys", passed: 5, total: 5 },
    { control: "S3.3", title: "Public access blocks enabled", passed: 3, total: 5 },
    { control: "EC2.2", title: "Security groups restrict management ports", passed: 4, total: 6 },
    { control: "LOG.4", title: "CloudTrail multi-region & validated", passed: 4, total: 7 },
    { control: "DB.1", title: "Storage encryption at rest", passed: 5, total: 6 },
    { control: "NET.6", title: "No default network ACL rules", passed: 2, total: 5 },
  ];
  return (
    <div className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft">
      <div className="grid grid-cols-[1fr_auto] items-center gap-4 border-b border-border bg-muted/40 px-5 py-3.5">
        <div>
          <h3 className="text-[14px] font-semibold">CIS AWS Foundations v3.0 — evidence pack</h3>
          <p className="text-[11.5px] text-muted-foreground">Scored across 7 connected accounts · 132 checks</p>
        </div>
        <Badge variant="warning">70% · attention</Badge>
      </div>
      <div className="divide-y divide-border/60">
        {rows.map((r) => (
          <div key={r.control} className="flex items-center gap-4 px-5 py-3">
            <span className="w-16 shrink-0 font-mono text-[11px] font-bold text-primary">{r.control}</span>
            <span className="flex-1 text-[12.5px] font-medium">{r.title}</span>
            <div className="flex items-center gap-2">
              <div className="h-1.5 w-24 overflow-hidden rounded-full bg-muted">
                <div
                  className={cn(
                    "h-full rounded-full",
                    r.passed === r.total ? "bg-success" : r.passed / r.total >= 0.6 ? "bg-warning" : "bg-destructive"
                  )}
                  style={{ width: `${(r.passed / r.total) * 100}%` }}
                />
              </div>
              <span className="w-10 text-right text-[11.5px] font-semibold tabular-nums text-muted-foreground">
                {r.passed}/{r.total}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
