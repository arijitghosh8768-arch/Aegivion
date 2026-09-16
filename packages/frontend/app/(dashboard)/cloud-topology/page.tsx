"use client";

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "@/lib/api-client";
import { motion, AnimatePresence } from "framer-motion";
import { Network, Boxes, Route, Zap, Filter, Plug, X, Maximize2 } from "lucide-react";
import { Onboarding } from "@/components/topology/onboarding";
import { ConnectModal } from "@/components/topology/connect-modal";
import { TopologyToolbar, ConnectedCloudsSidebar, BottomPanel } from "@/components/topology/topology-panels";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import type { ProviderId } from "@/lib/types";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

interface TopologyNode {
  id: string;
  type: string;
  label: string;
}

interface TopologyEdge {
  source: string;
  target: string;
  type: string;
}

interface TopologyData {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export default function CloudTopologyPage() {
  const { connectedClouds, connectCloud, disconnectCloud, disconnectAllClouds } = useAppStore();
  const hasClouds = connectedClouds.length > 0;

  const [connectFor, setConnectFor] = useState<ProviderId | null>(null);

  const { data, isLoading } = useQuery<TopologyData>({
    queryKey: ["topology"],
    queryFn: () => fetchApi("/v1/topology"),
    enabled: hasClouds,
  });

  const backendNodes = data?.nodes || [];
  const backendEdges = data?.edges || [];

  const allTypes = useMemo(() => {
    return Array.from(new Set(backendNodes.map((n) => n.type)));
  }, [backendNodes]);

  const [types, setTypes] = useState<string[]>([]);
  const toggleType = (t: string) =>
    setTypes((ts) => (ts.includes(t) ? ts.filter((x) => x !== t) : [...ts, t]));

  const [query, setQuery] = useState("");
  const [region, setRegion] = useState("all");
  const [risk, setRisk] = useState("all");
  const [refreshing, setRefreshing] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);

  const refresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 1400);
  };

  const filteredNodes = useMemo(() => {
    let result = backendNodes;
    if (types.length > 0) {
      result = result.filter(n => types.includes(n.type));
    }
    if (query) {
      const q = query.toLowerCase();
      result = result.filter(n => 
        n.label.toLowerCase().includes(q) || n.type.toLowerCase().includes(q)
      );
    }
    return result;
  }, [backendNodes, types, query]);

  // Map to ReactFlow format
  const reactFlowNodes = useMemo(() => {
    const colCount = Math.ceil(Math.sqrt(filteredNodes.length)) || 1;
    return filteredNodes.map((n, i) => {
      const x = (i % colCount) * 250;
      const y = Math.floor(i / colCount) * 150;
      return {
        id: n.id,
        position: { x, y },
        data: { label: `${n.label} (${n.type})` },
        style: {
          background: "var(--card)",
          color: "var(--foreground)",
          border: "1px solid var(--border)",
          borderRadius: "8px",
          padding: "12px",
          fontSize: "12px",
          fontWeight: 500,
          boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)",
        },
      };
    });
  }, [filteredNodes]);

  const reactFlowEdges = useMemo(() => {
    const nodeIds = new Set(filteredNodes.map(n => n.id));
    return backendEdges
      .filter(e => nodeIds.has(e.source) && nodeIds.has(e.target))
      .map((e, i) => ({
        id: `e-${e.source}-${e.target}-${i}`,
        source: e.source,
        target: e.target,
        label: e.type,
        animated: true,
        labelStyle: { fontSize: 10, fill: "var(--muted-foreground)" },
        labelBgStyle: { fill: "var(--card)", fillOpacity: 0.9 },
        markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: "#6d5df6" },
        style: { stroke: "#6d5df6", strokeWidth: 2 },
      }));
  }, [backendEdges, filteredNodes]);

  const totalAssets = backendNodes.length;

  const renderFlow = (height: string | number) => (
    <div className="relative overflow-hidden rounded-2xl border border-border bg-card/60" style={{ height }}>
      {isLoading ? (
        <div className="flex h-full items-center justify-center">
          <p className="animate-pulse text-sm text-muted-foreground">Loading topology...</p>
        </div>
      ) : (
        <ReactFlow
          nodes={reactFlowNodes}
          edges={reactFlowEdges}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.1}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
        >
          <Background variant={BackgroundVariant.Dots} gap={24} size={1.2} color="var(--border)" />
          <Controls position="bottom-left" showInteractive={false} />
          <MiniMap 
            position="bottom-right" 
            nodeColor="#6d5df6"
            maskColor="rgba(109,93,246,0.06)"
            pannable 
            zoomable 
          />
        </ReactFlow>
      )}
    </div>
  );

  return (
    <div>
      <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-[22px] font-bold tracking-tight">Cloud Topology</h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {hasClouds
              ? "Living view of your cloud environment."
              : "Securely connect your cloud environments to start discovering assets."}
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
                <Route className="h-3 w-3 text-primary" /> {filteredNodes.length} nodes
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
              <div className="space-y-5 rounded-2xl border border-border bg-card p-4 shadow-soft xl:sticky xl:top-4 xl:self-start">
                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-[12px] font-semibold uppercase tracking-wider text-muted-foreground">
                      <Zap className="h-3.5 w-3.5" /> Resource types
                    </span>
                    {types.length > 0 && (
                      <button onClick={() => setTypes([])} className="text-xs font-semibold text-primary hover:underline">
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
                            "cursor-pointer rounded-full border px-2.5 py-1 text-xs font-medium transition",
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
                  <div className="text-xs font-semibold text-muted-foreground">Information</div>
                  <div className="mt-2 space-y-1.5 text-xs text-muted-foreground">
                    <div>Connected directly to live backend.</div>
                    <div>Drag to pan, scroll to zoom.</div>
                  </div>
                </div>
              </div>

              <div>
                {!fullscreen && (
                  <div className="relative">
                    {renderFlow(620)}
                    <button
                      onClick={() => setFullscreen(true)}
                      className="absolute right-4 top-4 z-10 flex h-8 w-8 cursor-pointer items-center justify-center rounded-lg border border-border bg-card text-muted-foreground transition hover:text-foreground shadow-sm"
                    >
                      <Maximize2 className="h-4 w-4" />
                    </button>
                  </div>
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

              <ConnectedCloudsSidebar
                connected={connectedClouds}
                onConnect={setConnectFor}
                onDisconnect={disconnectCloud}
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <ConnectModal provider={connectFor} onClose={() => setConnectFor(null)} onConnect={connectCloud} />

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
            <div className="min-h-0 flex-1 relative">
              {renderFlow("100%")}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
