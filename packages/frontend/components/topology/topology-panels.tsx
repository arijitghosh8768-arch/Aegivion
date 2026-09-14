"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  Search,
  RefreshCw,
  Download,
  Clock3,
  Plus,
  X,
  ArrowRight,
  Boxes,
  CircleAlert,
  GitBranch,
  TrendingUp,
  History,
  Layers,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { PROVIDER_META, CLOUD_ACCOUNTS } from "@/lib/data/providers";
import { TOPOLOGY_PROVIDERS } from "@/lib/data/topology";
import {
  RECENT_DISCOVERIES,
  RECENT_TOPOLOGY_FINDINGS,
  TOPOLOGY_CHANGES,
  ASSET_TIMELINE,
} from "@/lib/data/topology-activity";
import { FINDINGS } from "@/lib/data/findings";
import { SeverityBadge } from "@/components/shared/severity";
import { ProviderMark } from "@/components/shared/provider-mark";
import { ChartTooltip } from "@/components/shared/chart-tooltip";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { ProviderId } from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Top toolbar                                                         */
/* ------------------------------------------------------------------ */

export function TopologyToolbar({
  query,
  onQuery,
  region,
  onRegion,
  risk,
  onRisk,
  refreshing,
  onRefresh,
  lastScan,
}: {
  query: string;
  onQuery: (v: string) => void;
  region: string;
  onRegion: (v: string) => void;
  risk: string;
  onRisk: (v: string) => void;
  refreshing: boolean;
  onRefresh: () => void;
  lastScan: string;
}) {
  const exportCsv = () => {
    const rows = [
      "id,title,service,provider,severity,confidence,detectedAt",
      ...FINDINGS.map((f) =>
        [f.id, `"${f.title}"`, f.service, f.provider, f.severity, f.confidence, f.detectedAt].join(",")
      ),
    ].join("\n");
    const blob = new Blob([rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "aegivion-topology-export.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-2xl border border-border bg-card p-2.5 shadow-soft">
      <div className="relative min-w-[180px] flex-1 sm:max-w-xs">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
        <input
          value={query}
          onChange={(e) => onQuery(e.target.value)}
          placeholder="Search resources, nodes…"
          className="h-9 w-full rounded-xl border border-input bg-muted/40 pl-9 pr-3 text-[12.5px] outline-none transition focus:border-primary/50 focus:ring-2 focus:ring-ring/40"
        />
      </div>

      <select
        value={region}
        onChange={(e) => onRegion(e.target.value)}
        className="h-9 cursor-pointer rounded-xl border border-input bg-muted/40 px-2.5 text-[12.5px] outline-none transition focus:border-primary/50"
        aria-label="Region filter"
      >
        <option value="all">All regions</option>
        <option value="us-east-1">us-east-1</option>
        <option value="eu-west-1">eu-west-1</option>
        <option value="eastus">eastus</option>
        <option value="westeurope">westeurope</option>
        <option value="us-central1">us-central1</option>
      </select>

      <select
        value={risk}
        onChange={(e) => onRisk(e.target.value)}
        className="h-9 cursor-pointer rounded-xl border border-input bg-muted/40 px-2.5 text-[12.5px] outline-none transition focus:border-primary/50"
        aria-label="Risk filter"
      >
        <option value="all">All risk</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
      </select>

      <div className="ml-auto flex items-center gap-2">
        <span className="hidden items-center gap-1.5 text-[11px] text-muted-foreground xl:flex">
          <Clock3 className="h-3.5 w-3.5" /> Last scan · {lastScan}
        </span>
        <button
          onClick={onRefresh}
          disabled={refreshing}
          className="flex h-9 cursor-pointer items-center gap-1.5 rounded-xl border border-border bg-card px-3 text-[12.5px] font-semibold text-muted-foreground transition hover:text-foreground disabled:opacity-60"
        >
          <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} /> Refresh
        </button>
        <button
          onClick={exportCsv}
          className="flex h-9 cursor-pointer items-center gap-1.5 rounded-xl bg-brand-gradient px-3 text-[12.5px] font-semibold text-white shadow-soft transition hover:brightness-110"
        >
          <Download className="h-4 w-4" /> Export
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Connected Clouds sidebar                                            */
/* ------------------------------------------------------------------ */

export function ConnectedCloudsSidebar({
  connected,
  onConnect,
  onDisconnect,
}: {
  connected: ProviderId[];
  onConnect: (p: ProviderId) => void;
  onDisconnect: (p: ProviderId) => void;
}) {
  const available = (Object.keys(PROVIDER_META) as ProviderId[]).filter((p) => !connected.includes(p));
  const totalAssets = TOPOLOGY_PROVIDERS.filter((p) => connected.includes(p.id)).reduce(
    (s, p) => s + p.resourceCount,
    0
  );

  const healthFor = (p: ProviderId) => {
    const accts = CLOUD_ACCOUNTS.filter((a) => a.provider === p);
    if (!accts.length) return 0;
    return Math.round(accts.reduce((s, a) => s + a.healthScore, 0) / accts.length);
  };
  const scoreColor = (v: number) => (v >= 80 ? "#22c55e" : v >= 60 ? "#f59e0b" : "#ef4444");

  return (
    <div className="space-y-4 rounded-2xl border border-border bg-card p-4 shadow-soft xl:sticky xl:top-4 xl:self-start">
      <div>
        <h3 className="flex items-center gap-1.5 text-[13px] font-bold tracking-tight">
          <Layers className="h-4 w-4 text-primary" /> Connected Clouds
        </h3>
        <p className="mt-0.5 text-[11px] text-muted-foreground">
          {connected.length} of 3 providers · {totalAssets.toLocaleString()} assets
        </p>
      </div>

      <div className="space-y-2.5">
        {connected.map((p) => {
          const meta = PROVIDER_META[p];
          const tp = TOPOLOGY_PROVIDERS.find((x) => x.id === p)!;
          const critical = tp.critical;
          const findings = FINDINGS.filter((f) => f.provider === p).length;
          return (
            <motion.div
              key={p}
              layout
              initial={{ opacity: 0, x: 12 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 12 }}
              className="rounded-xl border border-border bg-muted/30 p-3"
            >
              <div className="flex items-center gap-2.5">
                <ProviderMark provider={p} size={30} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[12.5px] font-semibold">{meta.name}</div>
                  <div className="flex items-center gap-1 text-[10.5px] font-medium text-success">
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="absolute h-full w-full animate-ping rounded-full bg-success opacity-60" />
                      <span className="relative h-1.5 w-1.5 rounded-full bg-success" />
                    </span>
                    Connected
                  </div>
                </div>
                <button
                  onClick={() => onDisconnect(p)}
                  className="flex h-7 w-7 cursor-pointer items-center justify-center rounded-lg text-muted-foreground transition hover:bg-destructive/10 hover:text-destructive"
                  aria-label={`Disconnect ${meta.name}`}
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
              <div className="mt-2.5 grid grid-cols-3 gap-1.5 text-center">
                <div className="rounded-lg bg-card px-1 py-1.5">
                  <div className="text-[12px] font-bold tabular-nums">{tp.resourceCount.toLocaleString()}</div>
                  <div className="text-[9px] text-muted-foreground">Assets</div>
                </div>
                <div className={cn("rounded-lg bg-card px-1 py-1.5", critical > 0 && "ring-1 ring-destructive/25")}>
                  <div className={cn("text-[12px] font-bold tabular-nums", critical > 0 && "text-destructive")}>
                    {critical}
                  </div>
                  <div className="text-[9px] text-muted-foreground">Critical</div>
                </div>
                <div className="rounded-lg bg-card px-1 py-1.5">
                  <div className="text-[12px] font-bold tabular-nums">{findings}</div>
                  <div className="text-[9px] text-muted-foreground">Findings</div>
                </div>
              </div>
              <div className="mt-2.5">
                <div className="mb-1 flex items-center justify-between text-[10px]">
                  <span className="text-muted-foreground">Security Score</span>
                  <span className="font-bold tabular-nums" style={{ color: scoreColor(healthFor(p)) }}>
                    {healthFor(p)}/100
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                  <motion.div
                    className="h-full rounded-full"
                    style={{ background: scoreColor(healthFor(p)) }}
                    initial={{ width: 0 }}
                    animate={{ width: `${healthFor(p)}%` }}
                    transition={{ duration: 1, delay: 0.2 }}
                  />
                </div>
              </div>
              <div className="mt-2 flex items-center justify-between border-t border-border/60 pt-2 text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Clock3 className="h-3 w-3" /> 4m ago
                </span>
                <Link href={`/detection-engine?provider=${p}`} className="font-semibold text-primary hover:underline">
                  Open
                </Link>
              </div>
            </motion.div>
          );
        })}
      </div>

      {available.length > 0 && (
        <div className="space-y-2">
          <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            Available to connect
          </div>
          {available.map((p) => (
            <button
              key={p}
              onClick={() => onConnect(p)}
              className="group flex w-full cursor-pointer items-center gap-2.5 rounded-xl border border-dashed border-border px-3 py-2.5 text-left transition hover:border-primary/40 hover:bg-primary/5"
            >
              <ProviderMark provider={p} size={26} />
              <span className="flex-1 text-[12.5px] font-medium">{PROVIDER_META[p].name}</span>
              <Plus className="h-4 w-4 text-muted-foreground transition group-hover:text-primary" />
            </button>
          ))}
        </div>
      )}

      <Link
        href="/cloud-accounts"
        className="flex items-center justify-center gap-1 rounded-xl border border-border bg-muted/30 py-2 text-[11.5px] font-semibold text-muted-foreground transition hover:text-foreground"
      >
        Manage accounts <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Bottom panel — Recent activity                                      */
/* ------------------------------------------------------------------ */

const CHANGE_META: Record<string, { cls: string; icon: React.ReactNode }> = {
  added: { cls: "bg-success/12 text-success", icon: <Plus className="h-3 w-3" /> },
  removed: { cls: "bg-destructive/12 text-destructive", icon: <X className="h-3 w-3" /> },
  modified: { cls: "bg-info/12 text-info", icon: <GitBranch className="h-3 w-3" /> },
  risk: { cls: "bg-warning/15 text-warning", icon: <CircleAlert className="h-3 w-3" /> },
};

type Tab = "discoveries" | "findings" | "changes" | "timeline";

export function BottomPanel({ region = "all", risk = "all" }: { region?: string; risk?: string }) {
  const [tab, setTab] = useState<Tab>("discoveries");

  const discoveries = useMemo(
    () => RECENT_DISCOVERIES.filter((d) => region === "all" || d.region === region),
    [region]
  );
  const findings = useMemo(
    () => RECENT_TOPOLOGY_FINDINGS.filter((f) => risk === "all" || f.severity === risk),
    [risk]
  );

  const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: "discoveries", label: "Recent Discoveries", icon: <Boxes className="h-3.5 w-3.5" /> },
    { id: "findings", label: "Recent Findings", icon: <CircleAlert className="h-3.5 w-3.5" /> },
    { id: "changes", label: "Topology Changes", icon: <History className="h-3.5 w-3.5" /> },
    { id: "timeline", label: "Asset Timeline", icon: <TrendingUp className="h-3.5 w-3.5" /> },
  ];

  return (
    <div className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft">
      <div className="flex flex-wrap gap-1 border-b border-border px-3 pt-2">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              "flex cursor-pointer items-center gap-1.5 rounded-t-xl border-b-2 px-3 py-2 text-[12px] font-semibold transition",
              tab === t.id
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            )}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      <div className="p-4">
        {tab === "discoveries" && (
          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {discoveries.length === 0 && (
              <p className="col-span-full py-8 text-center text-[12.5px] text-muted-foreground">
                No discoveries match the current region filter.
              </p>
            )}
            {discoveries.map((d, i) => (
              <motion.div
                key={d.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                className="flex items-center gap-3 rounded-xl border border-border/70 px-3 py-2.5"
              >
                <ProviderMark provider={d.provider} size={26} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[12px] font-semibold">{d.name}</div>
                  <div className="truncate text-[10.5px] text-muted-foreground">
                    {d.type} · {d.region}
                  </div>
                </div>
                <span className="shrink-0 text-[10px] text-muted-foreground">{d.time}</span>
              </motion.div>
            ))}
          </div>
        )}

        {tab === "findings" && (
          <div className="space-y-1.5">
            {findings.length === 0 && (
              <p className="py-8 text-center text-[12.5px] text-muted-foreground">
                No findings match the current risk filter.
              </p>
            )}
            {findings.map((f, i) => (
              <motion.div
                key={f.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
                className="flex items-center gap-3 rounded-xl border border-border/70 px-3 py-2.5"
              >
                <SeverityBadge severity={f.severity} showDot={false} className="w-[72px] justify-center" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[12px] font-semibold">{f.title}</div>
                  <div className="truncate text-[10.5px] text-muted-foreground">
                    {f.type} · {PROVIDER_META[f.provider].name}
                  </div>
                </div>
                <span className="hidden shrink-0 text-[10px] font-medium tabular-nums text-muted-foreground sm:block">
                  {f.confidence}% conf
                </span>
                <span className="shrink-0 text-[10px] text-muted-foreground">{f.time}</span>
              </motion.div>
            ))}
            <Link href="/detection-engine" className="mt-2 flex items-center justify-center gap-1 py-1 text-[11.5px] font-semibold text-primary hover:underline">
              View all findings <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
        )}

        {tab === "changes" && (
          <div className="space-y-1.5">
            {TOPOLOGY_CHANGES.map((c, i) => {
              const m = CHANGE_META[c.kind];
              return (
                <motion.div
                  key={c.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.04 }}
                  className="flex items-center gap-3 rounded-xl border border-border/70 px-3 py-2.5"
                >
                  <span className={cn("flex h-6 w-6 shrink-0 items-center justify-center rounded-lg", m.cls)}>
                    {m.icon}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="text-[12px] font-semibold">{c.label}</div>
                    <div className="truncate text-[10.5px] text-muted-foreground">{c.detail}</div>
                  </div>
                  <Badge variant="soft" className="shrink-0">
                    {PROVIDER_META[c.provider].short}
                  </Badge>
                  <span className="shrink-0 text-[10px] text-muted-foreground">{c.time}</span>
                </motion.div>
              );
            })}
          </div>
        )}

        {tab === "timeline" && (
          <div className="h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={ASSET_TIMELINE} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="tl-grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#6d5df6" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#6d5df6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 6" stroke="var(--border)" vertical={false} />
                <XAxis dataKey="week" tick={{ fontSize: 10.5, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10.5, fill: "var(--muted-foreground)" }} axisLine={false} tickLine={false} />
                <Tooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="net" name="Net assets" stroke="#6d5df6" strokeWidth={2.2} fill="url(#tl-grad)" dot={{ r: 2.5 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}
