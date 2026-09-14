"use client";

import { useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Handle,
  Position,
  MarkerType,
  type Node,
  type Edge,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { motion } from "framer-motion";
import { Share2, Clock, Crosshair, AlertTriangle } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { SeverityBadge } from "@/components/shared/severity";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  CHAIN_1_NODES,
  CHAIN_1_EDGES,
  CHAIN_2_NODES,
  CHAIN_2_EDGES,
  ALERTS,
} from "@/lib/data/alerts";
import type { ThreatChainNode } from "@/lib/types";

interface ChainNodeData {
  node: ThreatChainNode;
  index: number;
  onSelect: (id: string) => void;
  [key: string]: unknown;
}

const NODE_H = 118;

function ChainGraphNode({ data, selected }: NodeProps<Node<ChainNodeData>>) {
  const { node, index, onSelect } = data;
  return (
    <div
      onClick={() => onSelect(node.id)}
      className={`w-[260px] cursor-pointer rounded-2xl border bg-card p-3.5 shadow-soft transition-all hover:-translate-y-0.5 hover:shadow-lift ${
        selected ? "border-primary ring-2 ring-primary/30" : "border-border"
      }`}
    >
      <Handle type="target" position={Position.Top} className="!h-2 !w-2 !border-0 !bg-primary" />
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-bold uppercase tracking-wider text-primary">Step {index + 1}</span>
        <span className="text-[10px] font-semibold text-muted-foreground">{node.tactic}</span>
      </div>
      <div className="mt-1.5 text-[13px] font-semibold leading-snug">{node.label}</div>
      <div className="mt-2 flex items-center justify-between">
        <Badge variant="purple" className="font-mono">
          {node.techniqueId}
        </Badge>
        <SeverityBadge severity={node.severity} />
      </div>
      <Handle type="source" position={Position.Bottom} className="!h-2 !w-2 !border-0 !bg-primary" />
    </div>
  );
}

const nodeTypes = { chainNode: ChainGraphNode };

const SEVERITY_EDGE: Record<string, string> = {
  critical: "#ef4444",
  high: "#f59e0b",
  medium: "#4f7cf7",
};

export default function ThreatCorrelationPage() {
  const [chainId, setChainId] = useState<"1" | "2">("1");
  const [selectedNode, setSelectedNode] = useState<string | null>("c1n1");

  const { nodes, edges } = useMemo(() => {
    const rawNodes = chainId === "1" ? CHAIN_1_NODES : CHAIN_2_NODES;
    const rawEdges = chainId === "1" ? CHAIN_1_EDGES : CHAIN_2_EDGES;

    const n: Node<ChainNodeData>[] = rawNodes.map((node, i) => ({
      id: node.id,
      type: "chainNode",
      position: { x: 40, y: i * (NODE_H + 34) + 10 },
      data: { node, index: i, onSelect: setSelectedNode },
    }));

    const e: Edge[] = rawEdges.map((edge) => {
      const src = rawNodes.find((x) => x.id === edge.source);
      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: true,
        label: edge.evidence,
        labelStyle: { fontSize: 10, fill: "var(--muted-foreground)" },
        labelBgStyle: { fill: "var(--card)", fillOpacity: 0.9 },
        labelBgPadding: [4, 2] as [number, number],
        markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: "#6d5df6" },
        style: { stroke: src ? SEVERITY_EDGE[src.severity] ?? "#6d5df6" : "#6d5df6", strokeWidth: 2 },
      };
    });

    return { nodes: n, edges: e };
  }, [chainId]);

  const activeNode =
    (chainId === "1" ? CHAIN_1_NODES : CHAIN_2_NODES).find((x) => x.id === selectedNode) ?? null;
  const activeAlert = activeNode ? ALERTS.find((a) => a.id === activeNode.alertId) : null;

  const chainTitle =
    chainId === "1"
      ? "Credential compromise → data exfiltration"
      : "Public GKE API → crypto-miner deployment";

  return (
    <div>
      <PageHeader
        title="Threat Correlation"
        description="Aegivion stitches related alerts into full kill chains with evidence at every hop."
      >
        <Button variant="gradient">
          <Crosshair className="h-4 w-4" /> Correlate with AI
        </Button>
      </PageHeader>

      {/* chain switcher */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {[
          { id: "1" as const, label: "CH-2026-08-04-01", sub: "4 alerts · critical", tone: "destructive" },
          { id: "2" as const, label: "CH-2026-08-02-01", sub: "4 alerts · medium", tone: "warning" },
        ].map((c) => (
          <button
            key={c.id}
            onClick={() => {
              setChainId(c.id);
              setSelectedNode(c.id === "1" ? "c1n1" : "c2n1");
            }}
            className={`cursor-pointer rounded-xl border px-3.5 py-2 text-left transition ${
              chainId === c.id
                ? "border-primary/40 bg-primary/10 shadow-soft"
                : "border-border bg-card hover:border-primary/30"
            }`}
          >
            <div className="flex items-center gap-2 text-[12.5px] font-semibold">
              {c.label}
              <Badge variant={c.tone as "destructive" | "warning"}>{c.sub}</Badge>
            </div>
          </button>
        ))}
        <span className="ml-auto hidden text-[11.5px] text-muted-foreground md:block">{chainTitle}</span>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
        {/* graph */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft"
          style={{ height: 600 }}
        >
          <ReactFlow
            key={chainId}
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.4}
            maxZoom={1.8}
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} color="var(--border)" />
            <Controls position="bottom-left" showInteractive={false} />
            <MiniMap
              position="bottom-right"
              nodeColor={(n) => (n.id === selectedNode ? "#6d5df6" : "var(--muted)")}
              maskColor="rgba(109,93,246,0.06)"
              pannable
              zoomable
            />
          </ReactFlow>
        </motion.div>

        {/* detail panel */}
        <motion.div
          initial={{ opacity: 0, x: 12 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-4"
        >
          <div className="rounded-2xl border border-border bg-card p-5 shadow-soft">
            <h3 className="flex items-center gap-2 text-[14px] font-semibold">
              <Share2 className="h-4 w-4 text-primary" /> Kill chain analysis
            </h3>
            {activeNode && activeAlert ? (
              <div className="mt-3 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[12.5px] font-semibold">{activeNode.label}</span>
                  <SeverityBadge severity={activeNode.severity} />
                </div>
                <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
                  <Badge variant="purple" className="font-mono">
                    {activeNode.techniqueId}
                  </Badge>
                  <span>{activeNode.tactic}</span>
                </div>
                <p className="rounded-xl bg-muted/50 p-3 text-[12px] leading-relaxed text-muted-foreground">
                  {activeAlert.description}
                </p>
                <div>
                  <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Evidence
                  </div>
                  <ul className="space-y-1.5">
                    {activeAlert.evidence.slice(0, 3).map((ev, i) => (
                      <li key={i} className="flex gap-1.5 text-[11.5px] leading-snug text-muted-foreground">
                        <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />
                        {ev}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" className="flex-1">
                    View alert
                  </Button>
                  <Button size="sm" variant="gradient" className="flex-1">
                    Jump to node
                  </Button>
                </div>
              </div>
            ) : (
              <p className="mt-3 text-[12.5px] text-muted-foreground">Select a node to inspect its evidence.</p>
            )}
          </div>

          <div className="rounded-2xl border border-border bg-card p-5 shadow-soft">
            <h3 className="flex items-center gap-2 text-[14px] font-semibold">
              <Clock className="h-4 w-4 text-primary" /> Event timeline
            </h3>
            <div className="mt-3 space-y-0">
              {(chainId === "1" ? CHAIN_1_NODES : CHAIN_2_NODES).map((n, i, arr) => (
                <div key={n.id} className="relative flex gap-3 pb-4 last:pb-0">
                  {i < arr.length - 1 && <span className="absolute left-[5px] top-4 h-full w-px bg-border" />}
                  <span
                    className={`relative mt-1 h-[11px] w-[11px] shrink-0 rounded-full border-2 border-card ${
                      selectedNode === n.id ? "bg-primary" : "bg-muted-foreground/50"
                    }`}
                  />
                  <button
                    onClick={() => setSelectedNode(n.id)}
                    className="cursor-pointer text-left"
                  >
                    <div className="text-[11.5px] font-medium text-muted-foreground">
                      {n.tactic} · <span className="font-mono">{n.techniqueId}</span>
                    </div>
                    <div className="text-[12.5px] font-semibold">{n.label}</div>
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-start gap-2.5 rounded-2xl border border-warning/25 bg-warning/5 p-4">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
            <p className="text-[11.5px] leading-relaxed text-muted-foreground">
              <span className="font-semibold text-foreground">Aegivion estimate:</span> this chain has a{" "}
              <span className="font-semibold text-warning">64% probability</span> of reoccurring within 72h if the
              exposed CI keys are not rotated. <span className="text-primary">Open remediation</span> to stage fixes.
            </p>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
