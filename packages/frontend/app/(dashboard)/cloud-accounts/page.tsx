"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Plus, RefreshCw, ArrowRight, CheckCircle2, Loader2 } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { ProviderMark } from "@/components/shared/provider-mark";
import { StatusPill } from "@/components/shared/severity";
import { ScoreRing } from "@/components/shared/score-ring";
import { CountUp } from "@/components/shared/count-up";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import type { CloudAccount, ProviderId } from "@/lib/types";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchApi } from "@/lib/api-client";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const STATUS_UI: Record<CloudAccount["status"], string> = {
  connected: "Connected",
  degraded: "Degraded",
  error: "Scan error",
};

const PROVIDER_META: Record<
  string,
  { name: string; short: string; color: string; soft: string }
> = {
  aws: { name: "Amazon Web Services", short: "AWS", color: "#FF9900", soft: "rgba(255,153,0,0.14)" },
  azure: { name: "Microsoft Azure", short: "Azure", color: "#0078D4", soft: "rgba(0,120,212,0.14)" },
  gcp: { name: "Google Cloud", short: "GCP", color: "#4285F4", soft: "rgba(66,133,244,0.14)" },
};

export default function CloudAccountsPage() {
  const [connectOpen, setConnectOpen] = useState(false);
  const [connectStep, setConnectStep] = useState(0);
  const [scanning, setScanning] = useState<string | null>(null);

  const [selectedProvider, setSelectedProvider] = useState<ProviderId>("aws");
  const [accessKey, setAccessKey] = useState("");
  const [secretKey, setSecretKey] = useState("");

  const queryClient = useQueryClient();

  const { data: accountsData, isLoading } = useQuery<{ success: boolean; data: Record<string, unknown>[] }>({
    queryKey: ["cloud_accounts"],
    queryFn: () => fetchApi("/v1/cloud-accounts"),
  });

  const accounts: CloudAccount[] = (accountsData?.data || []).map((acc: any) => ({
    id: acc.id || "unknown",
    provider: (acc.provider as ProviderId) || "aws",
    name: acc.account_name || "Unknown",
    accountId: acc.account_id || "Unknown",
    status: acc.connection_status?.toLowerCase() === "failed" ? "error" : "connected",
    regions: acc.default_region ? 1 : 0,
    lastScan: new Date().toISOString(),
    resources: 0,
    findings: 0,
    critical: 0,
    healthScore: 100,
    coverage: ["EC2", "S3", "IAM"],
    plan: "Pro",
  }));

  const total = accounts.length;
  const connected = accounts.filter((a) => a.status === "connected").length;
  const critical = accounts.reduce((s, a) => s + a.critical, 0);
  const avgHealth = total > 0 ? Math.round(accounts.reduce((s, a) => s + a.healthScore, 0) / total) : 0;

  const connectMutation = useMutation({
    mutationFn: async () => {
      return fetchApi("/v1/cloud-accounts", {
        method: "POST",
        body: JSON.stringify({
          account_name: `My ${selectedProvider.toUpperCase()}`,
          provider: selectedProvider,
          account_id: "auto",
          default_region: selectedProvider === "aws" ? "us-east-1" : selectedProvider === "azure" ? "eastus" : "us-central1",
          ...(selectedProvider === "aws" ? {
            aws_access_key_id: accessKey,
            aws_secret_access_key: secretKey,
          } : {}),
        }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cloud_accounts"] });
      setConnectOpen(false);
      setConnectStep(0);
      setAccessKey("");
      setSecretKey("");
    },
    onError: (error: Error) => {
      alert("Error: " + error.message);
    }
  });

  const runScan = (id: string) => {
    setScanning(id);
    setTimeout(() => {
      setScanning(null);
      // In a real app we'd trigger a mutation here too
    }, 1600);
  };

  return (
    <div>
      <PageHeader
        title="Cloud Accounts"
        description="Connect and monitor your AWS, Azure and Google Cloud environments."
      >
        <Button variant="gradient" onClick={() => setConnectOpen(true)}>
          <Plus className="h-4 w-4" /> Connect account
        </Button>
      </PageHeader>

      {/* summary strip */}
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Total accounts", value: total },
          { label: "Connected", value: connected, tint: "text-success" },
          { label: "Critical findings", value: critical, tint: "text-destructive" },
          { label: "Avg health", value: `${avgHealth}%`, tint: "text-primary" },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="rounded-2xl border border-border bg-card p-4 shadow-soft"
          >
            <div className="text-[11px] font-medium text-muted-foreground">{s.label}</div>
            <div className={cn("mt-1 text-2xl font-bold tracking-tight tabular-nums", s.tint)}>
              <CountUp value={typeof s.value === "number" ? s.value : 0} />
              {typeof s.value === "string" ? s.value : ""}
            </div>
          </motion.div>
        ))}
      </div>

      {/* account cards */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {accounts.map((a, i) => {
          return (
            <motion.div
              key={a.id}
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.04 }}
              className="card-hover rounded-2xl border border-border bg-card p-5 shadow-soft"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <ProviderMark provider={a.provider} size={40} />
                  <div>
                    <div className="text-[14px] font-semibold leading-tight">{a.name}</div>
                    <div className="text-[11px] text-muted-foreground">Account {a.accountId}</div>
                  </div>
                </div>
                <StatusPill status={STATUS_UI[a.status]} />
              </div>

              <div className="mt-4 flex items-center gap-4">
                <ScoreRing value={a.healthScore} size={72} stroke={7} label="health" sublabel="" />
                <div className="grid flex-1 grid-cols-2 gap-x-4 gap-y-2">
                  <Stat label="Resources" value={a.resources.toLocaleString()} />
                  <Stat label="Findings" value={String(a.findings)} accent={a.findings > 0} />
                  <Stat label="Regions" value={String(a.regions)} />
                  <Stat label="Critical" value={String(a.critical)} accent={a.critical > 0} />
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-1.5">
                {a.coverage.slice(0, 5).map((c) => (
                  <Badge key={c} variant="soft">
                    {c}
                  </Badge>
                ))}
                {a.coverage.length > 5 && <Badge variant="soft">+{a.coverage.length - 5}</Badge>}
              </div>

              <div className="mt-4 flex items-center justify-between border-t border-border/70 pt-3">
                <span className="text-[11px] text-muted-foreground">
                  Last scan · <span className="font-medium text-foreground">{formatScan(a.lastScan)}</span>
                </span>
                <button
                  onClick={() => runScan(a.id)}
                  disabled={scanning === a.id}
                  className="flex cursor-pointer items-center gap-1.5 rounded-lg px-2 py-1 text-[11px] font-semibold text-primary transition hover:bg-primary/10 disabled:opacity-60"
                >
                  <RefreshCw className={cn("h-3 w-3", scanning === a.id && "animate-spin")} />
                  {scanning === a.id ? "Scanning…" : "Scan now"}
                </button>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* connect dialog */}
      <Dialog open={connectOpen} onOpenChange={(o) => !connectMutation.isPending && setConnectOpen(o)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Connect a cloud account</DialogTitle>
            <DialogDescription>
              Choose a provider, then grant Aegivion read-only access with a single CloudFormation / Bicep / Deployment
              template.
            </DialogDescription>
          </DialogHeader>

          {connectStep === 0 && (
            <div className="grid gap-3 py-2">
              {(Object.keys(PROVIDER_META) as ProviderId[]).map((p) => (
                <button
                  key={p}
                  onClick={() => { setSelectedProvider(p); setConnectStep(1); }}
                  className="group flex cursor-pointer items-center gap-3 rounded-2xl border border-border bg-muted/30 p-4 text-left transition hover:border-primary/40 hover:bg-primary/5"
                >
                  <ProviderMark provider={p} size={40} />
                  <div className="flex-1">
                    <div className="text-[14px] font-semibold">{PROVIDER_META[p].name}</div>
                    <div className="text-[11.5px] text-muted-foreground">
                      {p === "aws" ? "CloudFormation stack · 5 min" : p === "azure" ? "Bicep deployment · 5 min" : "Deployment Manager · 5 min"}
                    </div>
                  </div>
                  <ArrowRight className="h-4 w-4 text-muted-foreground transition group-hover:translate-x-0.5 group-hover:text-primary" />
                </button>
              ))}
            </div>
          )}

          {connectStep === 1 && (
            <div className="space-y-4 py-2">
              {selectedProvider === "aws" ? (
                <div className="grid gap-4">
                  <div className="grid gap-2">
                    <Label htmlFor="accessKey">AWS Access Key ID</Label>
                    <Input
                      id="accessKey"
                      value={accessKey}
                      onChange={(e) => setAccessKey(e.target.value)}
                      placeholder="AKIA..."
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="secretKey">AWS Secret Access Key</Label>
                    <Input
                      id="secretKey"
                      type="password"
                      value={secretKey}
                      onChange={(e) => setSecretKey(e.target.value)}
                      placeholder="••••••••••••••••••••••••"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <StepRow n={1} title="Launch the template" done>
                    Run the Aegivion read-only role template in your provider console.
                  </StepRow>
                  <StepRow n={2} title="Paste the external ID" active>
                    Copy the external ID <Code className="mx-1">aegivion-7f3a-2026</Code> into the template parameter to
                    prevent confused-deputy attacks.
                  </StepRow>
                  <StepRow n={3} title="Verify connection" />
                  <div className="rounded-xl bg-muted/50 p-3 text-[11.5px] leading-relaxed text-muted-foreground">
                    Aegivion will discover resources within ~2 minutes. No write permissions are granted — remediation
                    flows use your existing CI/CD identity.
                  </div>
                </div>
              )}
            </div>
          )}

          <DialogFooter>
            {connectStep === 1 && (
              <Button variant="ghost" onClick={() => setConnectStep(0)} disabled={connectMutation.isPending}>
                Back
              </Button>
            )}
            {connectStep === 1 && (
              <Button variant="gradient" onClick={() => connectMutation.mutate()} disabled={connectMutation.isPending}>
                {connectMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" /> Verifying…
                  </>
                ) : (
                  "Connect"
                )}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div>
      <div className={cn("text-[15px] font-bold tabular-nums", accent && "text-destructive")}>{value}</div>
      <div className="text-[10px] text-muted-foreground">{label}</div>
    </div>
  );
}function StepRow({
  n,
  title,
  active,
  done,
  children,
}: {
  n: number;
  title: string;
  active?: boolean;
  done?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3">
      <span
        className={cn(
          "flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-bold",
          done ? "bg-success/15 text-success" : active ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground"
        )}
      >
        {done ? <CheckCircle2 className="h-3.5 w-3.5" /> : n}
      </span>
      <div>
        <div className="text-[13px] font-semibold">{title}</div>
        {children && <div className="mt-0.5 text-[11.5px] leading-relaxed text-muted-foreground">{children}</div>}
      </div>
    </div>
  );
}

function Code({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <code className={cn("code-block rounded-md bg-foreground/[0.06] px-1.5 py-0.5 text-[11px] text-primary", className)}>
      {children}
    </code>
  );
}

function formatScan(iso: string) {
  const d = new Date(iso);
  const mins = Math.round((Date.now() - d.getTime()) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  return d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}
