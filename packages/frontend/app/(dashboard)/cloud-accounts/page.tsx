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
import { CLOUD_ACCOUNTS } from "@/lib/data/providers";
import { PROVIDER_META } from "@/lib/data/providers";
import { cn } from "@/lib/utils";
import type { CloudAccount, ProviderId } from "@/lib/types";

const STATUS_UI: Record<CloudAccount["status"], string> = {
  connected: "Connected",
  degraded: "Degraded",
  error: "Scan error",
};

export default function CloudAccountsPage() {
  const [accounts, setAccounts] = useState(CLOUD_ACCOUNTS);
  const [connectOpen, setConnectOpen] = useState(false);
  const [connectStep, setConnectStep] = useState(0);
  const [connecting, setConnecting] = useState(false);
  const [scanning, setScanning] = useState<string | null>(null);

  const total = accounts.length;
  const connected = accounts.filter((a) => a.status === "connected").length;
  const critical = accounts.reduce((s, a) => s + a.critical, 0);
  const avgHealth = Math.round(accounts.reduce((s, a) => s + a.healthScore, 0) / total);

  const runScan = (id: string) => {
    setScanning(id);
    setTimeout(() => {
      setScanning(null);
      setAccounts((as) => as.map((a) => (a.id === id ? { ...a, lastScan: new Date().toISOString(), status: "connected" } : a)));
    }, 1600);
  };

  const connectAccount = () => {
    setConnecting(true);
    setTimeout(() => {
      setConnecting(false);
      setConnectOpen(false);
      setConnectStep(0);
      setAccounts((as) => [
        {
          id: `acct-${Date.now()}`,
          provider: "aws" as ProviderId,
          name: "Acme Analytics (AWS)",
          accountId: "3301-8821-4417",
          status: "connected",
          regions: 4,
          lastScan: new Date().toISOString(),
          resources: 128,
          findings: 0,
          critical: 0,
          healthScore: 94,
          coverage: ["EC2", "S3", "IAM", "Athena", "Glue"],
          plan: "Pro",
        },
        ...as,
      ]);
    }, 1800);
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
      <Dialog open={connectOpen} onOpenChange={(o) => !connecting && setConnectOpen(o)}>
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
                  onClick={() => setConnectStep(1)}
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

          <DialogFooter>
            {connectStep === 1 && (
              <Button variant="ghost" onClick={() => setConnectStep(0)} disabled={connecting}>
                Back
              </Button>
            )}
            {connectStep === 1 && (
              <Button variant="gradient" onClick={connectAccount} disabled={connecting}>
                {connecting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" /> Verifying…
                  </>
                ) : (
                  "I've deployed the template"
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
