"use client";

import { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Network, Boxes, Route, Zap, Filter, Plug, X, Plus, Maximize2 } from "lucide-react";
import { CloudTopology } from "@/components/topology/cloud-topology";
import { Onboarding } from "@/components/topology/onboarding";
import { ConnectModal } from "@/components/topology/connect-modal";
import { TopologyToolbar, ConnectedCloudsSidebar, BottomPanel } from "@/components/topology/topology-panels";
import { TOPOLOGY_NODES } from "@/lib/data/topology";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import type { ProviderId } from "@/lib/types";

const ALL_NODE_IDS = TOPOLOGY_NODES.map((n) => n.id);

export default function CloudTopologyPage() {
  const { connectedClouds, connectCloud, disconnectCloud, disconnectAllClouds } = useAppStore();

  const [connectFor, setConnectFor] = useState<ProviderId | null>(null);
  const [nodes, setNodes] = useState<string[]>(() => {
    if (typeof window === "undefined") return ALL_NODE_IDS;
    const p = new URLSearchParams(window.location.search).get("p");
    if (p && (p === "aws" || p === "azure" || p === "gcp")) return [p as ProviderId];
    return ALL_NODE_IDS;
  });
  const [types, setTypes] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [region, setRegion] = useState("all");
  const [risk, setRisk] = useState("all");
  const [refreshing, setRefreshing] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);

  const hasClouds = connectedClouds.length > 0;

  const allTypes = useMemo(
    () => Array.from(new Set(TOPOLOGY_NODES.flatMap((n) => n.resources.map((r) => r.type)))),
    []
  );

  /* Cloud nodes only stay visible while their account is connected */
  const visibleNodeIds = useMemo(
    () =>
      nodes.filter((id) => {
        const n = TOPOLOGY_NODES.find((x) => x.id === id);
        return n && (n.kind !== "provider" || connectedClouds.includes(n.id as ProviderId));
      }),
    [nodes, connectedClouds]
  );

  const toggleNode = (id: string) =>
    setNodes((ns) => (ns.includes(id) ? ns.filter((x) => x !== id) : [...ns, id]));
  const toggleType = (t: string) =>
    setTypes((ts) => (ts.includes(t) ? ts.filter((x) => x !== t) : [...ts, t]));

  const refresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 1400);
  };

  const totalAssets = TOPOLOGY_NODES.filter(
    (n) => n.kind !== "provider" || connectedClouds.includes(n.id as ProviderId)
  ).reduce((s, n) => s + n.resourceCount, 0);

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-[22px] font-bold tracking-tight">Cloud Topology</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {hasClouds
              ? "Living view of your cloud environment — drag to pan, scroll to zoom, double-click to center, click a node to drill in."
              : "Securely connect your cloud environments to start discovering assets, analyzing configurations, detecting security risks, and visualizing your infrastructure."}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {hasClouds ? (
            <>
              <Badge variant="soft" className="gap-1.5">
                <Network className="h-3 w-3 text-primary" /> {connectedClouds.length} clouds
              </Badge>
              <Badge variant="soft" className="gap-1.5">
                <Boxes className="h-3 w-3 text-primary" /> {totalAssets.toLocaleString()} assets
              </Badge>
              <Badge variant="soft" className="gap-1.5">
                <Route className="h-3 w-3 text-primary" /> {visibleNodeIds.length} nodes
              </Badge>
              <Button variant="outline" onClick={disconnectAllClouds} className="h-8 text-[12px]">
                <Plug className="h-3.5 w-3.5" /> Disconnect all
              </Button>
              <Button variant="gradient" onClick={() => setConnectFor("aws")} className="h-8 text-[12px]">
                <Plug className="h-3.5 w-3.5" /> Connect cloud
              </Button>
            </>
          ) : (
            <Button variant="gradient" onClick={() => setConnectFor("aws")}>
              <Plug className="h-4 w-4" /> Connect your first cloud
            </Button>
          )}
        </div>
      </div>

      {/* STATE 1 — onboarding */}
      <AnimatePresence mode="wait">
        {!hasClouds && (
          <motion.div
            key="onboarding"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.4 }}
          >
            <Onboarding onConnect={setConnectFor} />
          </motion.div>
        )}

        {/* STATE 2 — interactive topology */}
        {hasClouds && (
          <motion.div
            key="topology"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.4 }}
            className="space-y-4"
          >
            <TopologyToolbar
              query={query}
              onQuery={setQuery}
              region={region}
              onRegion={setRegion}
              risk={risk}
              onRisk={setRisk}
              refreshing={refreshing}
              onRefresh={refresh}
              lastScan="4m ago"
            />

            <div className="grid gap-4 xl:grid-cols-[250px_1fr_270px]">
              {/* Filter sidebar — keeps the picture layout */}
              <div className="space-y-5 rounded-2xl border border-border bg-card p-4 shadow-soft xl:sticky xl:top-4 xl:self-start">
                <div>
                  <div className="mb-2 flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wider text-muted-foreground">
                    <Filter className="h-3.5 w-3.5" /> Nodes
                  </div>
                  <div className="space-y-1.5">
                    {TOPOLOGY_NODES.map((n) => {
                      const isCloud = n.kind === "provider";
                      const connected = connectedClouds.includes(n.id as ProviderId);
                      if (isCloud && !connected) {
                        return (
                          <button
                            key={n.id}
                            onClick={() => setConnectFor(n.id as ProviderId)}
                            className="flex w-full cursor-pointer items-center gap-2.5 rounded-xl border border-dashed border-border px-2 py-1.5 text-left opacity-70 transition hover:border-primary/40 hover:opacity-100"
                          >
                            <span className="h-2.5 w-2.5 rounded-full border border-dashed" style={{ borderColor: n.color }} />
                            <span className="flex-1 truncate text-[13px] font-medium text-muted-foreground">{n.name}</span>
                            <Plus className="h-3.5 w-3.5 text-primary" />
                          </button>
                        );
                      }
                      const on = nodes.includes(n.id);
                      return (
                        <label
                          key={n.id}
                          className="flex cursor-pointer items-center gap-2.5 rounded-xl border border-transparent px-2 py-1.5 transition hover:bg-muted/60"
                        >
                          <input
                            type="checkbox"
                            checked={on}
                            onChange={() => toggleNode(n.id)}
                            className="h-4 w-4 rounded accent-primary"
                          />
                          <span className="h-2.5 w-2.5 rounded-full" style={{ background: n.color }} />
                          <span className="flex-1 truncate text-[13px] font-medium">{n.name}</span>
                          <span className="text-[11px] tabular-nums text-muted-foreground">
                            {n.resourceCount}
                          </span>
                        </label>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wider text-muted-foreground">
                      <Zap className="h-3.5 w-3.5" /> Resource types
                    </span>
                    {types.length > 0 && (
                      <button onClick={() => setTypes([])} className="text-[11px] font-semibold text-primary hover:underline">
                        Clear
                      </button>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {allTypes.map((t) => {
                      const on = types.includes(t);
                      return (
                        <button
                          key={t}
                          onClick={() => toggleType(t)}
                          className={cn(
                            "cursor-pointer rounded-full border px-2.5 py-1 text-[11px] font-medium transition",
                            on
                              ? "border-primary/30 bg-primary/10 text-primary"
                              : "border-border bg-muted/40 text-muted-foreground hover:border-primary/30 hover:text-foreground"
                          )}
                        >
                          {t}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="rounded-xl bg-muted/50 p-3">
                  <div className="text-[11px] font-semibold text-muted-foreground">Legend</div>
                  <div className="mt-2 space-y-1.5 text-[11px] text-muted-foreground">
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-success" /> Healthy
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-warning" /> Warning
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-destructive" /> Critical
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="h-0.5 w-5 rounded bg-brand-purple" /> Secure telemetry link
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="flex h-2 w-2">
                        <span className="h-full w-full animate-ping rounded-full bg-brand-purple opacity-60" />
                        <span className="relative h-2 w-2 rounded-full bg-brand-purple" />
                      </span>
                      Data packets
                    </div>
                  </div>
                </div>
              </div>

              {/* Topology — a single instance is mounted at a time (inline or fullscreen) */}
              <div>
                {!fullscreen && (
                  <CloudTopology
                    height={620}
                    showMiniMap
                    drawer
                    fullscreen={false}
                    onToggleFullscreen={() => setFullscreen(true)}
                    filteredProviders={visibleNodeIds}
                    filteredTypes={types}
                    query={query}
                  />
                )}
                {fullscreen && (
                  <div className="flex h-[620px] items-center justify-center rounded-2xl border border-border bg-card/60">
                    <div className="text-center">
                      <Maximize2 className="mx-auto h-6 w-6 animate-pulse text-primary" />
                      <p className="mt-2 text-[12px] text-muted-foreground">Topology in fullscreen mode</p>
                    </div>
                  </div>
                )}
                <div className="mt-4">
                  <BottomPanel region={region} risk={risk} />
                </div>
              </div>

              {/* Right sidebar */}
              <ConnectedCloudsSidebar
                connected={connectedClouds}
                onConnect={setConnectFor}
                onDisconnect={disconnectCloud}
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Connect modal */}
      <ConnectModal provider={connectFor} onClose={() => setConnectFor(null)} onConnect={connectCloud} />

      {/* Fullscreen overlay */}
      <AnimatePresence>
        {fullscreen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex flex-col bg-background/95 p-4 backdrop-blur-xl"
          >
            <div className="mb-3 flex shrink-0 items-center justify-between">
              <h2 className="text-[15px] font-bold tracking-tight">Cloud Topology — Fullscreen</h2>
              <button
                onClick={() => setFullscreen(false)}
                className="flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl border border-border bg-card text-muted-foreground transition hover:text-foreground"
                aria-label="Exit fullscreen"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="min-h-0 flex-1">
              <CloudTopology
                height="100%"
                showMiniMap
                drawer
                fullscreen
                onToggleFullscreen={() => setFullscreen(false)}
                filteredProviders={visibleNodeIds}
                filteredTypes={types}
                query={query}
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
