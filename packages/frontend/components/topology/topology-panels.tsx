"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "@/lib/api-client";
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
          placeholder="Search resources, nodesâ€¦"
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
          <Clock3 className="h-3.5 w-3.5" /> Last scan Â· {lastScan}
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

  const { data: cloudAccountsRes } = useQuery({ queryKey: ['cloud-accounts'], queryFn: () => fetchApi('/v1/cloud-accounts') });
  const { data: findingsRes } = useQuery({ queryKey: ['findings'], queryFn: () => fetchApi('/v1/findings') });
  const { data: topologyRes } = useQuery({ queryKey: ['topology'], queryFn: () => fetchApi('/v1/topology') });
  
  const liveAccounts = cloudAccountsRes?.data || [];
  const liveFindings = findingsRes?.findings || [];
  const liveNodes = topologyRes?.nodes || [];

  const totalAssets = liveNodes.length;

  const healthFor = (p: ProviderId) => {
    const pFindings = liveFindings.filter((f: any) => f.cloud_provider?.toLowerCase() === p);
    if (!pFindings.length && !liveAccounts.find((a: any) => a.provider?.toLowerCase() === p)) return 0;
    if (!pFindings.length) return 100;
    
    const score = 100 - pFindings.reduce((acc: number, f: any) => {
        return acc + (f.severity?.toLowerCase() === 'critical' ? 5 : f.severity?.toLowerCase() === 'high' ? 2 : 1);
    }, 0);
    return Math.max(0, Math.min(100, score));
  };
  const scoreColor = (v: number) => (v >= 80 ? '#22c55e' : v >= 60 ? '#f59e0b' : '#ef4444');

  return (
    <div className="space-y-4 rounded-2xl border border-border bg-card p-4 shadow-soft xl:sticky xl:top-4 xl:self-start">
      <div>
        <h3 className="flex items-center gap-1.5 text-[13px] font-bold tracking-tight">
          <Layers className="h-4 w-4 text-primary" /> Connected Clouds
        </h3>
        <p className="mt-0.5 text-[11px] text-muted-foreground">
          {connected.length} of 3 providers — {totalAssets.toLocaleString()} assets
        </p>
      </div>

      <div className="space-y-2.5">
        {connected.map((p) => {
          const meta = PROVIDER_META[p];
          const providerNodes = liveNodes.filter((n: any) => n.provider === p);
          const providerFindings = liveFindings.filter((f: any) => f.cloud_provider?.toLowerCase() === p);
          const critical = providerFindings.filter((f: any) => f.severity?.toLowerCase() === 'critical').length;
          
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
                  <div className="text-[12px] font-bold tabular-nums">{providerNodes.length.toLocaleString()}</div>
                  <div className="text-[9px] text-muted-foreground">Assets</div>
                </div>
                <div className={cn("rounded-lg bg-card px-1 py-1.5", critical > 0 && "ring-1 ring-destructive/25")}>
                  <div className={cn("text-[12px] font-bold tabular-nums", critical > 0 && "text-destructive")}>
                    {critical}
                  </div>
                  <div className="text-[9px] text-muted-foreground">Critical</div>
                </div>
                <div className="rounded-lg bg-card px-1 py-1.5">
                  <div className="text-[12px] font-bold tabular-nums">{providerFindings.length.toLocaleString()}</div>
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
            </motion.div>
          );
        })}
      </div>

      {available.length > 0 && (
        <div className="pt-2">
          <p className="mb-2 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            Available to connect
          </p>
          <div className="space-y-1.5">
            {available.map((p) => {
              const meta = PROVIDER_META[p];
              return (
                <button
                  key={p}
                  onClick={() => onConnect(p)}
                  className="flex w-full items-center justify-between rounded-lg border border-border bg-card p-2 text-left transition hover:bg-muted/50"
                >
                  <div className="flex items-center gap-2">
                    <ProviderMark provider={p} size={20} />
                    <span className="text-[12px] font-medium">{meta.name}</span>
                  </div>
                  <Plus className="h-3.5 w-3.5 text-muted-foreground" />
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
export function BottomPanel({ region = "all", risk = "all" }: { region?: string; risk?: string }) {
  const [activeTab, setActiveTab] = useState("discoveries");
  const { data: findingsRes } = useQuery({ queryKey: ['findings'], queryFn: () => fetchApi('/v1/findings') });
  const { data: topologyRes } = useQuery({ queryKey: ['topology'], queryFn: () => fetchApi('/v1/topology') });
  
  const liveFindings = findingsRes?.findings || [];
  const liveNodes = topologyRes?.nodes || [];
  
  const recentNodes = liveNodes.slice(0, 5);
  const recentFindings = liveFindings.filter((f: any) => risk === 'all' || f.severity?.toLowerCase() === risk.toLowerCase()).slice(0, 5);

  return (
    <div className="absolute bottom-4 left-4 right-4 z-10 mx-auto max-w-5xl">
      <motion.div
        initial={{ y: 20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.1 }}
        className="overflow-hidden rounded-xl border border-border bg-card/95 shadow-xl backdrop-blur-xl"
      >
        <div className="flex border-b border-border/50">
          <button
            onClick={() => setActiveTab("discoveries")}
            className={cn(
              "flex flex-1 items-center justify-center gap-2 border-b-2 px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider transition",
              activeTab === "discoveries"
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:bg-muted/30 hover:text-foreground"
            )}
          >
            <Boxes className="h-3.5 w-3.5" /> Recent Discoveries
          </button>
          <button
            onClick={() => setActiveTab("findings")}
            className={cn(
              "flex flex-1 items-center justify-center gap-2 border-b-2 px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider transition",
              activeTab === "findings"
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:bg-muted/30 hover:text-foreground"
            )}
          >
            <CircleAlert className="h-3.5 w-3.5" /> Recent Findings
          </button>
        </div>

        <div className="p-2">
          {activeTab === "discoveries" && (
            <div className="grid grid-cols-3 gap-2">
              {recentNodes.length === 0 ? (
                <div className="col-span-3 p-4 text-center text-sm text-muted-foreground">No recent assets.</div>
              ) : (
                recentNodes.map((item: any, i: number) => (
                  <div key={item.id || i} className="flex items-center justify-between rounded-lg border border-border/50 bg-background/50 p-2.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <ProviderMark provider={item.provider || "aws"} size={20} />
                      <div className="truncate">
                        <div className="truncate text-[12px] font-medium">{item.label}</div>
                        <div className="text-[10px] text-muted-foreground">{item.type}</div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === "findings" && (
            <div className="grid grid-cols-2 gap-2">
              {recentFindings.length === 0 ? (
                <div className="col-span-2 p-4 text-center text-sm text-muted-foreground">No recent findings.</div>
              ) : (
                recentFindings.map((item: any, i: number) => (
                  <div key={item.id || i} className="flex items-center justify-between rounded-lg border border-border/50 bg-background/50 p-2.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <SeverityBadge severity={item.severity} />
                      <div className="truncate">
                        <div className="truncate text-[12px] font-medium">{item.title}</div>
                        <div className="text-[10px] text-muted-foreground">
                          {item.resource_id}
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
