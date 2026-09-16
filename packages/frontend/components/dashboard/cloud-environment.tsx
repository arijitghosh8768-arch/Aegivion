"use client";

import { useCallback, useEffect, useRef, useState, useMemo } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  RefreshCw,
  Rotate3d,
  Maximize2,
  X,
  ShieldCheck,
  Activity,
  ZoomIn,
  ZoomOut,
  ArrowUpRight,
  Boxes,
  ShieldAlert,
  Server,
  KeyRound,
  Lock,
  FileText,
  Globe2,
  CloudCog,
  HardDrive,
  Fingerprint,
  Radio,
  Crosshair,
  Sparkles,
  CheckCircle2,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "@/lib/api-client";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { ScoreRing } from "@/components/shared/score-ring";
import { TopologyNodeMark } from "@/components/topology/node-mark";
import type { TopologyNodeId } from "@/lib/data/topology";

const W = 1200;
const H = 840;
const CX = W / 2;
const CY = H / 2;
const RING = 330;

/* Round coordinates so server & client render identical values (fixes hydration mismatch). */
const r2 = (v: number) => Math.round(v * 100) / 100;

interface EnvNode {
  id: string;
  label: string;
  displayName: string;
  sub: string;
  assets: string;
  angle: number; // degrees, 0 = right, clockwise
  color: string;
  soft: string;
  kind: "cloud" | "database" | "users" | "network";
  status: string;
  link: string;
  _score?: number;
}

const NODES: EnvNode[] = [
  { id: "aws", label: "AWS", displayName: "AWS", sub: "Amazon Web Services", assets: "12 Assets", angle: 270, color: "#c35df5", soft: "rgba(195,93,245,0.16)", kind: "cloud", status: "Secure", link: "/cloud-topology?p=aws" },
  { id: "network", label: "Network", displayName: "Network", sub: "VPC, Subnets", assets: "8 Assets", angle: 321.43, color: "#4f7cf7", soft: "rgba(79,124,247,0.16)", kind: "network", status: "Secure", link: "/cloud-topology" },
  { id: "firewall", label: "Firewall", displayName: "Firewall", sub: "WAF & Security Groups", assets: "6 Assets", angle: 12.86, color: "#FF9900", soft: "rgba(255,153,0,0.16)", kind: "cloud", status: "Secure", link: "/cloud-topology" },
  { id: "endpoints", label: "Endpoints", displayName: "Endpoints", sub: "Devices", assets: "9 Assets", angle: 64.29, color: "#22c55e", soft: "rgba(34,197,94,0.16)", kind: "cloud", status: "Secure", link: "/cloud-topology" },
  { id: "gcp", label: "GCP", displayName: "GCP", sub: "GCP Project", assets: "12 Assets", angle: 115.71, color: "#4285F4", soft: "rgba(66,133,244,0.16)", kind: "cloud", status: "Secure", link: "/cloud-topology?p=gcp" },
  { id: "azure", label: "Azure", displayName: "Azure", sub: "Microsoft Azure", assets: "10 Assets", angle: 167.14, color: "#0078D4", soft: "rgba(0,120,212,0.16)", kind: "cloud", status: "Secure", link: "/cloud-topology?p=azure" },
  { id: "database", label: "Database", displayName: "Database", sub: "Monitored engines", assets: "4 Assets", angle: 218.57, color: "#8b5cf6", soft: "rgba(139,92,246,0.16)", kind: "database", status: "Secure", link: "/assets" },
];

/* Arc sector labels (rotate with the ring) */
const ARCS: any[] = [];

function polar(angleDeg: number, radius: number) {
  const rad = (angleDeg * Math.PI) / 180;
  return { x: r2(CX + radius * Math.cos(rad)), y: r2(CY + radius * Math.sin(rad)) };
}

/* Shared brand marks for every node — consistent with the full topology */
function NodeGlyph({ node }: { node: EnvNode }) {
  return (
    <foreignObject x={-20} y={-20} width={40} height={40} style={{ pointerEvents: 'none' }}>
      <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <TopologyNodeMark nodeId={node.id as TopologyNodeId} size={32} />
      </div>
    </foreignObject>
  );
}

interface ViewState {
  rot: number;
  zoom: number;
  panX: number;
  panY: number;
  dragging: boolean;
  lastX: number;
  lastY: number;
  mode: "rotate" | "pan";
  autoRotate: boolean;
}

type Selection = { kind: "node"; node: EnvNode } | { kind: "core" };

export function CloudEnvironment({ className }: { className?: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const sceneRef = useRef<SVGGElement>(null);
  const labelRefs = useRef<Record<string, SVGGElement | null>>({});

  const { data: telemetry } = useQuery<any>({
    queryKey: ["risk-intelligence"],
    queryFn: () => fetchApi("/v1/risk/intelligence"),
    refetchInterval: 30000,
  });
  const { data: topData } = useQuery<any>({
    queryKey: ["topology-data"],
    queryFn: () => fetchApi("/v1/topology"),
    refetchInterval: 30000,
  });

  const displayNodes: EnvNode[] = useMemo(() => {
    return NODES.map((n) => {
      let count = n.assets;
      let stat = n.status;
      let score = NODE_DETAILS[n.id]?.score ?? 100;

      if (telemetry && !telemetry.error) {
        let realCount = 0;
        if (n.id === "aws") realCount = telemetry.aws_assets || 0;
        else if (n.id === "azure") realCount = telemetry.azure_assets || 0;
        else if (n.id === "gcp") realCount = telemetry.gcp_assets || 0;
        else if (topData && topData.nodes) {
          const nodes = topData.nodes as any[];
          if (n.id === "database") realCount = nodes.filter(x => x.type === "database").length;
          if (n.id === "network") realCount = nodes.filter(x => x.type === "network" || x.type === "vpc").length;
          if (n.id === "firewall") realCount = nodes.filter(x => x.type === "firewall").length;
          if (n.id === "endpoints") realCount = nodes.filter(x => x.type === "compute" || x.type === "endpoint").length;
        }
        
        count = `${realCount} Assets`;
        if (realCount === 0) {
          stat = "Disconnected";
          score = 0;
        } else if (telemetry.critical_risks > 0 && ["aws", "azure", "gcp"].includes(n.id)) {
          stat = "At Risk";
          score = Math.max(10, 100 - (telemetry.critical_risks * 10));
        } else {
          stat = "Secure";
          score = 100;
        }
      }
      return { ...n, assets: count, status: stat, _score: score };
    });
  }, [telemetry, topData]);

  const state = useRef<ViewState>({
    rot: 0,
    zoom: 0.85,
    panX: 0,
    panY: 0,
    dragging: false,
    lastX: 0,
    lastY: 0,
    mode: "rotate",
    autoRotate: true,
  });
  const [selection, setSelection] = useState<Selection | null>(null);
  const selectNode = useCallback((node: EnvNode) => setSelection({ kind: "node", node }), []);
  const selectCore = useCallback(() => setSelection({ kind: "core" }), []);
  const [zoomPct, setZoomPct] = useState(85);
  const [auto, setAuto] = useState(true);
  const [spinning, setSpinning] = useState(false);


  /* pan/zoom/rotate render loop */
  useEffect(() => {
    if (typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      state.current.autoRotate = false;
      return;
    }
    let raf = 0;
    let last = performance.now();
    let lastTransform = "";
    const loop = (now: number) => {
      const dt = Math.min(0.1, (now - last) / 1000);
      last = now;
      const s = state.current;
      if (!s.dragging && s.autoRotate) {
        s.rot = ((s.rot - 14 * dt) % 360 + 360) % 360; // anticlockwise · 14 deg/s → full 360° every ~26s
      }
      const transform = `translate(${r2(s.panX)},${r2(s.panY)}) scale(${r2(s.zoom)}) rotate(${r2(s.rot)} ${CX} ${CY})`;
      if (sceneRef.current && (transform !== lastTransform || s.dragging)) {
        sceneRef.current.setAttribute("transform", transform);
        lastTransform = transform;
      }
      
      // Counter rotate nodes to keep them upright while orbiting
      const counterRot = `rotate(${r2(-s.rot)})`;
      for (const n of NODES) {
        const el = labelRefs.current[n.id];
        if (el) el.setAttribute("transform", counterRot);
      }
      const coreEl = labelRefs.current['core'];
      if (coreEl) coreEl.setAttribute("transform", counterRot);

      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    const onVisibility = () => {
      if (document.hidden) cancelAnimationFrame(raf);
      else {
        last = performance.now();
        raf = requestAnimationFrame(loop);
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      cancelAnimationFrame(raf);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  /* Wheel zoom — only when Ctrl/Cmd is held so scrolling over the scene scrolls the page naturally. */
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey && !e.metaKey) return; // let the page scroll normally
      e.preventDefault();
      const s = state.current;
      const factor = e.deltaY < 0 ? 1.12 : 0.89;
      s.zoom = Math.min(2.6, Math.max(0.5, s.zoom * factor));
      setZoomPct(Math.round(s.zoom * 100));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const setZoom = useCallback((delta: number) => {
    const s = state.current;
    const next = Math.min(2.6, Math.max(0.5, s.zoom + delta));
    if (next !== s.zoom) {
      s.zoom = next;
      setZoomPct(Math.round(s.zoom * 100));
      // Force an immediate transform write so the +/- buttons respond instantly.
      if (sceneRef.current) {
        sceneRef.current.setAttribute(
          "transform",
          `translate(${r2(s.panX)},${r2(s.panY)}) scale(${r2(s.zoom)}) rotate(${r2(s.rot)} ${CX} ${CY})`
        );
      }
    }
  }, []);

  const resetView = useCallback(() => {
    const s = state.current;
    s.rot = 0;
    s.zoom = 1;
    s.panX = 0;
    s.panY = 0;
    setZoomPct(100);
    if (sceneRef.current) {
      sceneRef.current.setAttribute("transform", `translate(0,0) scale(1) rotate(0 ${CX} ${CY})`);
    }
  }, []);

  const refresh = useCallback(() => {
    setSpinning(true);
    const s = state.current;
    s.autoRotate = false;
    setAuto(false);
    s.rot += 720;
    setTimeout(() => {
      s.rot = s.rot % 360;
      s.autoRotate = true;
      setAuto(true);
      setSpinning(false);
    }, 1500);
  }, []);

  const toggleAuto = useCallback(() => {
    state.current.autoRotate = !state.current.autoRotate;
    setAuto(state.current.autoRotate);
  }, []);

  /* drag / rotate / pan */
  const endDrag = useCallback(() => {
    state.current.dragging = false;
  }, []);

  const onPointerDown = (e: React.PointerEvent) => {
    if (e.button !== 0 && e.button !== 2) return;
    const s = state.current;
    s.dragging = true;
    s.lastX = e.clientX;
    s.lastY = e.clientY;
    (s as any).startX = e.clientX;
    (s as any).startY = e.clientY;
    s.mode = e.button === 2 || e.ctrlKey || e.metaKey ? "pan" : "rotate";
  };
  const onPointerMove = (e: React.PointerEvent) => {
    const s = state.current;
    if (!s.dragging || (!(e.buttons & 1) && !(e.buttons & 2))) return;
    const dx = e.clientX - s.lastX;
    const dy = e.clientY - s.lastY;
    s.lastX = e.clientX;
    s.lastY = e.clientY;
    if (s.mode === "rotate") {
      s.rot += dx * 0.35;
    } else {
      s.panX += dx / s.zoom;
      s.panY += dy / s.zoom;
    }
  };
  const onPointerUp = (e: React.PointerEvent) => {
    endDrag();
    try {
      (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    } catch {
      /* noop */
    }
  };

  const linkD = (angleDeg: number) => {
    const p = polar(angleDeg, RING);
    const dx = CX - p.x;
    const dy = CY - p.y;
    const dist = Math.hypot(dx, dy);
    const ux = dx / dist;
    const uy = dy / dist;
    const sx = r2(p.x + ux * 58);
    const sy = r2(p.y + uy * 58);
    const ex = r2(CX - ux * 92);
    const ey = r2(CY - uy * 92);
    const mx = r2((sx + ex) / 2 + -uy * 30);
    const my = r2((sy + ey) / 2 + ux * 30);
    return { d: `M ${sx} ${sy} Q ${mx} ${my} ${ex} ${ey}`, ex, ey };
  };

  if (telemetry && telemetry.asset_count === 0) {
    return (
      <div className={cn("relative flex h-[420px] flex-col overflow-hidden rounded-2xl border border-border bg-card", className)}>
        <div className="flex h-full flex-col items-center justify-center text-center p-8">
           <CloudCog className="h-12 w-12 text-muted-foreground/30 mb-4" />
           <h3 className="text-[16px] font-semibold">No Environments Connected</h3>
           <p className="mt-2 text-[13px] max-w-sm text-muted-foreground">
             Connect your first cloud provider to automatically visualize your topology and scan for risks.
           </p>
           <Link href="/cloud-topology" className="mt-5 inline-flex items-center justify-center h-9 px-4 text-[13px] font-medium text-white bg-brand-gradient rounded-lg shadow-soft transition hover:brightness-110">
             Connect Provider
           </Link>
        </div>
      </div>
    );
  }
  return (
    <div className={cn("flex flex-col overflow-hidden rounded-2xl border border-border bg-card shadow-soft", className)}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/70 px-5 py-3.5">
        <div>
          <h2 className="text-[14.5px] font-bold tracking-tight">CLOUD ENVIRONMENT OVERVIEW</h2>
          <p className="text-sm text-muted-foreground">Real-time 360° security visualization</p>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={refresh}
            disabled={spinning}
            className="flex h-8 w-8 cursor-pointer items-center justify-center rounded-lg border border-border bg-muted/40 text-muted-foreground transition hover:border-primary/40 hover:text-foreground disabled:opacity-60"
            aria-label="Refresh topology"
          >
            <RefreshCw className={cn("h-4 w-4", spinning && "animate-spin")} />
          </button>
          <button
            onClick={toggleAuto}
            className={cn(
              "flex h-8 cursor-pointer items-center gap-1.5 rounded-lg border px-2.5 text-sm font-semibold transition",
              auto
                ? "border-primary/30 bg-primary/10 text-primary"
                : "border-border bg-muted/40 text-muted-foreground hover:text-foreground"
            )}
          >
            <Rotate3d className="h-3.5 w-3.5" /> 360°
          </button>
          <Link
            href="/cloud-topology"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-muted/40 text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
            aria-label="Open full topology"
          >
            <Maximize2 className="h-4 w-4" />
          </Link>
        </div>
      </div>

      {/* Scene */}
      <div
        ref={containerRef}
        className="relative flex-1 select-none overflow-hidden"
        style={{ minHeight: 330, touchAction: "none" }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={endDrag}
        onPointerLeave={endDrag}
        onContextMenu={(e) => e.preventDefault()}
      >
        {/* ambient glow */}
        <div className="pointer-events-none absolute left-1/2 top-1/2 h-[360px] w-[360px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-brand-gradient opacity-[0.08] blur-[80px]" />

        <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full cursor-grab active:cursor-grabbing" style={{ touchAction: "none" }}>
          <defs>
            <linearGradient id="env-core-grad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#6d5df6" />
              <stop offset="55%" stopColor="#4f7cf7" />
              <stop offset="100%" stopColor="#c35df5" />
            </linearGradient>
            <filter id="env-glow" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="7" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <radialGradient id="env-core-fill">
              <stop offset="0%" stopColor="#8b7bff" stopOpacity="0.5" />
              <stop offset="70%" stopColor="#6d5df6" stopOpacity="0.16" />
              <stop offset="100%" stopColor="#4f7cf7" stopOpacity="0" />
            </radialGradient>
            <radialGradient id="env-dot">
              <stop offset="0%" stopColor="#6d5df6" stopOpacity="0.7" />
              <stop offset="100%" stopColor="#4f7cf7" stopOpacity="0" />
            </radialGradient>
            {displayNodes.map((n) => (
              <linearGradient key={`env-link-${n.id}`} id={`env-link-${n.id}`} x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor={n.color} stopOpacity="0.95" />
                <stop offset="100%" stopColor="#6d5df6" stopOpacity="0.25" />
              </linearGradient>
            ))}
          </defs>

          <g ref={sceneRef}>
            {/* platform rings */}
            <g className="pointer-events-none" opacity="0.55">
              {[110, 175, 250, 330].map((r) => (
                <circle key={r} cx={CX} cy={CY} r={r} fill="none" stroke="var(--border)" strokeWidth="1" strokeDasharray="2 8" />
              ))}
              <circle cx={CX} cy={CY} r={420} fill="url(#env-core-fill)" />
              <circle cx={CX} cy={CY} r={330} fill="none" stroke="url(#env-core-grad)" strokeWidth="1.2" strokeDasharray="3 10" opacity="0.7" />
            </g>

            {/* connections + packets */}
            {displayNodes.map((n) => {
              const g = linkD(n.angle);
              return (
                <g key={`conn-${n.id}`}>
                  <path d={g.d} fill="none" stroke={`url(#env-link-${n.id})`} strokeWidth="1.4" opacity="0.85" />
                  <path
                    d={g.d}
                    fill="none"
                    stroke={n.color}
                    strokeWidth="2.2"
                    strokeDasharray="2 10"
                    strokeLinecap="round"
                    opacity="0.55"
                    className="animate-dash"
                  />
                  <circle cx={g.ex} cy={g.ey} r="3.5" fill="#6d5df6" filter="url(#env-glow)" />
                  {/* data packets travelling toward core */}
                  {[0, 1, 2].map((i) => (
                    <circle key={i} r={i === 1 ? 2.6 : 3.2} fill={n.color} filter="url(#env-glow)">
                      <animateMotion dur={`${6 + i * 1.6}s`} begin={`${i * 2.1}s`} repeatCount="indefinite" path={g.d} />
                      <animate attributeName="opacity" values="1;0.4;1" dur="2s" repeatCount="indefinite" />
                    </circle>
                  ))}
                </g>
              );
            })}

            {/* orbiting resource dots around each node */}
            {displayNodes.map((n) => {
              const p = polar(n.angle, RING);
              return (
                <g key={`orbit-${n.id}`} transform={`translate(${p.x},${p.y})`}>
                  <g style={{ animation: "spin 18s linear infinite", transformBox: "fill-box", transformOrigin: "center" }}>
                    {[0, 72, 144, 216, 288].map((a, i) => (
                      <circle
                        key={i}
                        cx={r2(Math.cos((a * Math.PI) / 180) * 68)}
                        cy={r2(Math.sin((a * Math.PI) / 180) * 68)}
                        r={i % 2 === 0 ? 4 : 2.8}
                        fill={n.color}
                        opacity="0.75"
                      />
                    ))}
                  </g>
                </g>
              );
            })}

            {/* nodes */}
            {displayNodes.map((n) => {
              const p = polar(n.angle, RING);
              const selected = selection?.kind === "node" && selection.node.id === n.id;
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x},${p.y})`}
                  className="cursor-pointer focus:outline-none"
                  onPointerUp={(e) => {
                    const s = state.current as any;
                    const dist = Math.hypot(e.clientX - (s.startX || e.clientX), e.clientY - (s.startY || e.clientY));
                    if (dist < 10) selectNode(n);
                  }}
                  onClick={() => selectNode(n)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      selectNode(n);
                    }
                  }}
                  role="button"
                  tabIndex={0}
                  aria-label={`${n.displayName} node`}
                >
                  <g ref={(el) => { labelRefs.current[n.id] = el; }} transform="rotate(0)">
                    {selected && (
                      <circle r="72" fill="none" stroke={n.color} strokeWidth="1.5" strokeDasharray="4 6" className="animate-dash" opacity="0.9" />
                    )}
                    {/* badge */}
                    <circle r="46" fill={n.soft} stroke={n.color} strokeWidth="2.5" filter="url(#env-glow)" opacity="0.95" />
                    <circle r="38" fill="var(--card)" stroke={n.color} strokeWidth="1.5" opacity="0.95" />
                    <g transform="translate(0,-2)">
                      <NodeGlyph node={n} />
                    </g>
                    {/* label block */}
                    <g>
                      <text textAnchor="middle" dy="64" fontSize="11.5" fontWeight="700" fill="var(--foreground)">
                        {n.label}
                      </text>
                      <g transform="translate(0, 74)">
                        <rect x="-30" y="-9.5" width="60" height="19" rx="9.5" fill={n.status === "Secure" ? "rgba(34,197,94,0.1)" : "rgba(245,158,11,0.12)"} />
                        <circle cx="-19" cy="0" r="3" fill={n.status === "Secure" ? "#22c55e" : "#f59e0b"}>
                          <animate attributeName="opacity" values="1;0.4;1" dur="2s" repeatCount="indefinite" />
                        </circle>
                        <text x="2" textAnchor="middle" dy="3.5" fontSize="10" fontWeight="700" fill={n.status === "Secure" ? "#16a34a" : "#d97706"}>
                          {n.status}
                        </text>
                      </g>
                      <text textAnchor="middle" dy="102" fontSize="9.5" fontWeight="500" fill="var(--muted-foreground)">
                        {n.assets}
                      </text>
                    </g>
                  </g>
                </g>
              );
            })}

            {/* arc sector labels — path direction reversed so text always reads top-to-bottom */}
            {ARCS.map((a) => {
              const r1 = (a.from * Math.PI) / 180;
              const r2a = (a.to * Math.PI) / 180;
              const large = Math.abs(a.to - a.from) > 180 ? 1 : 0;
              const mid = (a.from + a.to) / 2;
              const flip = Math.cos((mid * Math.PI) / 180) < 0;
              const x1 = r2(CX + a.r * Math.cos(flip ? r2a : r1));
              const y1 = r2(CY + a.r * Math.sin(flip ? r2a : r1));
              const x2 = r2(CX + a.r * Math.cos(flip ? r1 : r2a));
              const y2 = r2(CY + a.r * Math.sin(flip ? r1 : r2a));
              return (
                <g key={a.text} className="pointer-events-none">
                  <path
                    id={`arc-${a.text.replace(/\s/g, "")}`}
                    d={`M ${x1} ${y1} A ${a.r} ${a.r} 0 ${large} 1 ${x2} ${y2}`}
                    fill="none"
                    stroke="var(--border)"
                    strokeWidth="1"
                    strokeDasharray="2 5"
                    opacity="0.7"
                  />
                  <text textAnchor="middle" fontSize="9.5" fontWeight="700" letterSpacing="3" fill="var(--muted-foreground)" style={{ fontStyle: "normal" }}>
                    <textPath href={`#arc-${a.text.replace(/\s/g, "")}`} startOffset="50%">
                      {a.text}
                    </textPath>
                  </text>
                </g>
              );
            })}

            {/* central core */}
            <g
              transform={`translate(${CX},${CY})`}
              onPointerUp={(e) => {
                const s = state.current as any;
                const dist = Math.hypot(e.clientX - (s.startX || e.clientX), e.clientY - (s.startY || e.clientY));
                if (dist < 10) selectCore();
              }}
              onClick={() => selectCore()}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  selectCore();
                }
              }}
              className="cursor-pointer focus:outline-none"
              role="button"
              tabIndex={0}
              aria-label="Aegivion security core"
            >
              {[0, 1, 2].map((i) => (
                <circle
                  key={i}
                  r="78"
                  fill="none"
                  stroke="#6d5df6"
                  strokeWidth="1.4"
                  className="animate-pulse-ring"
                  style={{ animationDelay: `${i * 1.1}s`, transformBox: "fill-box", transformOrigin: "center", opacity: 0.45 }}
                />
              ))}
              <circle r="118" fill="url(#env-dot)" />
              <circle r="84" fill="rgba(109,93,246,0.10)" stroke="url(#env-core-grad)" strokeWidth="2.5" filter="url(#env-glow)" />
              <circle r="66" fill="var(--card)" stroke="url(#env-core-grad)" strokeWidth="1.5" />
              <g ref={(el) => { labelRefs.current['core'] = el; }} transform="rotate(0)">
                <ShieldCheck width={36} height={36} x={-18} y={-42} className="text-brand-purple" strokeWidth={1.8} />
                <text textAnchor="middle" dy="16" fontSize="18" fontWeight="800" fill="var(--foreground)">
                  Aegivion
                </text>
                <text textAnchor="middle" dy="36" fontSize="12" fontWeight="500" fill="var(--muted-foreground)">
                  Cloud Security
                </text>
                <text textAnchor="middle" dy="52" fontSize="12" fontWeight="500" fill="var(--muted-foreground)">
                  Management
                </text>
              </g>
            </g>
          </g>
        </svg>

        {/* zoom controls */}
        <div className="absolute right-3.5 top-3.5 flex flex-col gap-1.5">
          <button onClick={() => setZoom(0.2)} className="flex h-8 w-8 cursor-pointer items-center justify-center rounded-lg border border-border bg-card/90 text-muted-foreground shadow-soft backdrop-blur transition hover:border-primary/40 hover:text-foreground active:scale-95" aria-label="Zoom in">
            <ZoomIn className="h-4 w-4" />
          </button>
          <button onClick={() => setZoom(-0.2)} className="flex h-8 w-8 cursor-pointer items-center justify-center rounded-lg border border-border bg-card/90 text-muted-foreground shadow-soft backdrop-blur transition hover:border-primary/40 hover:text-foreground active:scale-95" aria-label="Zoom out">
            <ZoomOut className="h-4 w-4" />
          </button>
          <button onClick={resetView} className="flex h-8 w-8 cursor-pointer items-center justify-center rounded-lg border border-border bg-card/90 text-muted-foreground shadow-soft backdrop-blur transition hover:border-primary/40 hover:text-foreground active:scale-95" aria-label="Reset view">
            <Maximize2 className="h-4 w-4" />
          </button>
        </div>

        {/* zoom indicator */}
        <div className="pointer-events-none absolute bottom-3.5 left-3.5 rounded-lg bg-card/85 px-2 py-1 text-[10px] font-semibold tabular-nums text-muted-foreground shadow-soft backdrop-blur">
          {zoomPct}%
        </div>

        {/* status pill */}
        <div className="pointer-events-none absolute bottom-3.5 left-1/2 -translate-x-1/2">
          <div className="flex items-center gap-1.5 rounded-full border border-border bg-card/90 px-3 py-1.5 shadow-soft backdrop-blur">
            <span className="relative flex h-2 w-2">
              <span className="absolute h-full w-full animate-ping rounded-full bg-success opacity-60" />
              <span className="relative h-2 w-2 rounded-full bg-success" />
            </span>
            <span className="text-xs font-semibold text-foreground">All Systems Operational</span>
          </div>
        </div>

        {/* hint */}
        <div className="pointer-events-none absolute bottom-3.5 right-3.5 hidden items-center gap-1 rounded-lg bg-card/85 px-2.5 py-1.5 text-[10px] font-medium text-muted-foreground shadow-soft backdrop-blur md:flex">
          <Activity className="h-3 w-3" /> Drag to rotate · Ctrl+scroll to zoom · Click a node
        </div>

        {/* futuristic full-detail overlay */}
        <AnimatePresence>
          {selection && (
            <DetailOverlay
              selection={
                selection.kind === "node"
                  ? { kind: "node", node: displayNodes.find((d) => d.id === selection.node.id) || selection.node }
                  : selection
              }
              onClose={() => setSelection(null)}
            />
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Futuristic full-detail overlay                                      */
/* ------------------------------------------------------------------ */

type RiskLevel = "ok" | "warn" | "crit";

interface RiskItem {
  icon: React.ComponentType<{ className?: string }>;
  text: string;
  level: RiskLevel;
}

interface LiveEvent {
  text: string;
  time: string;
  tone: "ok" | "info" | "warn" | "crit";
}

interface NodeDetailData {
  score: number;
  stats: { label: string; value: string }[];
  risks: RiskItem[];
  live: LiveEvent[];
  recommendations: string[];
  mitre: string[];
}

const RISK_META: Record<RiskLevel, { label: string; cls: string; bar: string; weight: number }> = {
  ok: { label: "Resolved", cls: "border-success/25 bg-success/10 text-success", bar: "bg-success", weight: 18 },
  warn: { label: "Warning", cls: "border-warning/25 bg-warning/10 text-warning", bar: "bg-warning", weight: 58 },
  crit: { label: "Critical", cls: "border-destructive/25 bg-destructive/10 text-destructive", bar: "bg-destructive", weight: 92 },
};

const LIVE_DOT: Record<LiveEvent["tone"], string> = {
  ok: "bg-success",
  info: "bg-info",
  warn: "bg-warning",
  crit: "bg-destructive",
};

/* Rich per-node detail content */
const NODE_DETAILS: Record<string, NodeDetailData> = {
  aws: {
    score: 78,
    stats: [
      { label: "EC2", value: "14" },
      { label: "S3", value: "9" },
      { label: "Lambda", value: "6" },
      { label: "RDS", value: "3" },
    ],
    risks: [
      { icon: KeyRound, text: "IAM role over-privileged", level: "warn" },
      { icon: Lock, text: "S3 bucket policy publicly readable", level: "crit" },
      { icon: Server, text: "Security group allows SSH from 0.0.0.0/0", level: "warn" },
    ],
    live: [
      { text: "CloudTrail — root login from new region us-east-2", time: "2m ago", tone: "warn" },
      { text: "S3 object write blocked on public bucket", time: "9m ago", tone: "warn" },
      { text: "GuardDuty — IAM policy drift on deploy-bot role", time: "24m ago", tone: "info" },
    ],
    recommendations: [
      "Enable Block Public Access on all S3 buckets",
      "Attach least-privilege IAM policy to deploy-bot",
      "Scope SSH security group to bastion CIDR only",
    ],
    mitre: ["T1078 Valid Accounts", "T1530 Cloud Storage Data"],
  },
  azure: {
    score: 82,
    stats: [
      { label: "VMs", value: "8" },
      { label: "Storage", value: "6" },
      { label: "AAD", value: "12" },
      { label: "Defender", value: "On" },
    ],
    risks: [
      { icon: CloudCog, text: "Storage account allows anonymous access", level: "warn" },
      { icon: KeyRound, text: "Service principal has broad role assignment", level: "warn" },
    ],
    live: [
      { text: "Entra ID — failed MFA challenge for admin user", time: "4m ago", tone: "warn" },
      { text: "Defender — beaconing pattern toward external C2", time: "12m ago", tone: "crit" },
      { text: "NSG flow-log anomaly detected in prod-vnet", time: "31m ago", tone: "info" },
    ],
    recommendations: [
      "Disable anonymous blob access on storage account",
      "Scope SPN role assignment to a single resource group",
      "Enforce Conditional Access MFA for all admins",
    ],
    mitre: ["T1078 Valid Accounts", "T1133 External Remote Services", "T1562 Impair Defenses"],
  },
  gcp: {
    score: 74,
    stats: [
      { label: "Compute", value: "11" },
      { label: "Buckets", value: "7" },
      { label: "SCC", value: "Live" },
      { label: "VPC", value: "4" },
    ],
    risks: [
      { icon: Globe2, text: "Cloud Storage bucket world-readable", level: "warn" },
      { icon: KeyRound, text: "Service account key exposed in repo", level: "crit" },
    ],
    live: [
      { text: "SCC — high-severity finding on compute instance", time: "3m ago", tone: "warn" },
      { text: "IAM — service account key downloaded from GCS", time: "15m ago", tone: "crit" },
      { text: "VPC flow logs — unusual egress to 45.x.x.x", time: "41m ago", tone: "warn" },
    ],
    recommendations: [
      "Rotate exposed SA key and scan repos for secrets",
      "Enforce uniform bucket-level access",
      "Enable VPC flow logs with 90-day retention",
    ],
    mitre: ["T1078 Valid Accounts", "T1530 Cloud Storage Data", "T1041 Exfiltration Over C2"],
  },
  database: {
    score: 88,
    stats: [
      { label: "RDS", value: "3" },
      { label: "Redis", value: "1" },
      { label: "Dynamo", value: "2" },
      { label: "Copies", value: "6" },
    ],
    risks: [
      { icon: HardDrive, text: "1 instance without encryption at rest", level: "warn" },
      { icon: Lock, text: "Database snapshots retained 30 days", level: "ok" },
    ],
    live: [
      { text: "RDS — audit log query-rate spike", time: "5m ago", tone: "info" },
      { text: "Backup job complete — 6 snapshots healthy", time: "18m ago", tone: "ok" },
      { text: "Redis — slowlog entry above 100ms", time: "36m ago", tone: "info" },
    ],
    recommendations: [
      "Enable encryption at rest on rds-prod-01",
      "Enable automated minor version upgrades",
      "Rotate DB master credentials quarterly",
    ],
    mitre: ["T1213 Data from Information Repositories"],
  },
  users: {
    score: 71,
    stats: [
      { label: "Identities", value: "9" },
      { label: "Admins", value: "2" },
      { label: "MFA", value: "7/9" },
      { label: "Keys", value: "4" },
    ],
    risks: [
      { icon: Fingerprint, text: "2 users without MFA enabled", level: "warn" },
      { icon: KeyRound, text: "Root login attempt detected (12m ago)", level: "warn" },
    ],
    live: [
      { text: "IAM — new access key created for ci-bot", time: "7m ago", tone: "info" },
      { text: "Failed console login — 3 attempts on aws-prod", time: "11m ago", tone: "warn" },
      { text: "MFA enrollment reminder sent to 2 users", time: "26m ago", tone: "info" },
    ],
    recommendations: [
      "Enforce MFA for all 9 identities",
      "Rotate access keys older than 90 days",
      "Remove long-term credentials from root user",
    ],
    mitre: ["T1078 Valid Accounts", "T1098 Account Manipulation", "T1110 Brute Force"],
  },
  network: {
    score: 66,
    stats: [
      { label: "VPCs", value: "3" },
      { label: "Subnets", value: "9" },
      { label: "SGs", value: "14" },
      { label: "LBs", value: "2" },
    ],
    risks: [
      { icon: Server, text: "Open SSH port on production security group", level: "crit" },
      { icon: Lock, text: "Unrestricted egress from public subnet", level: "warn" },
    ],
    live: [
      { text: "Flow logs — 41 blocked inbound attempts on :22", time: "1m ago", tone: "warn" },
      { text: "ALB — 5xx spike from edge nodes", time: "13m ago", tone: "info" },
      { text: "New SG rule added — review pending", time: "28m ago", tone: "warn" },
    ],
    recommendations: [
      "Remove 0.0.0.0/0 SSH rule from prod-sg",
      "Add egress allowlist for public subnets",
      "Enable flow-log analytics pipeline",
    ],
    mitre: ["T1046 Network Service Scanning", "T1021 Remote Services"],
  },
};

/* Core engine detail data */
const CORE_DETAIL: {
  score: number;
  stats: { label: string; value: string }[];
  live: LiveEvent[];
  recommendations: string[];
  mitre: string[];
} = {
  score: 96,
  stats: [
    { label: "Clouds", value: "3" },
    { label: "Assets", value: "32" },
    { label: "Findings", value: "12" },
    { label: "Uptime", value: "99.99%" },
  ],
  live: [
    { text: "Correlation engine — 214 rules active", time: "Live", tone: "ok" },
    { text: "MITRE ATT&CK mapping refreshed", time: "1m ago", tone: "info" },
    { text: "Anomaly queue — 3 events awaiting review", time: "5m ago", tone: "warn" },
  ],
  recommendations: [
    "Prioritize the 2 critical findings before the next risk re-scoring",
    "Review the 3 queued anomalies in the detection engine",
    "Extend threat-correlation window from 30 to 45 days",
  ],
  mitre: ["T1027 Obfuscated Files", "T1059 Command & Scripting", "T1190 Exploit Public-Facing"],
};

function SectionTitle({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-muted-foreground">
      <span className="text-primary">{icon}</span>
      {children}
    </div>
  );
}

function DetailAction({
  href,
  onClick,
  children,
  primary,
}: {
  href: string;
  onClick?: () => void;
  children: React.ReactNode;
  primary?: boolean;
}) {
  return (
    <Link
      href={href}
      onClick={onClick}
      className={cn(
        "flex h-9 items-center justify-center gap-1.5 rounded-xl px-3.5 text-sm font-semibold transition",
        primary
          ? "bg-brand-gradient text-white shadow-soft hover:brightness-110"
          : "border border-border bg-card/70 text-muted-foreground hover:border-primary/40 hover:text-foreground"
      )}
    >
      {children}
    </Link>
  );
}

function StatTiles({ stats, delay = 0.1 }: { stats: { label: string; value: string }[]; delay?: number }) {
  return (
    <div className="grid grid-cols-2 gap-2.5">
      {stats.map((s, i) => (
        <motion.div
          key={s.label}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: delay + i * 0.06 }}
          className="group relative overflow-hidden rounded-xl border border-border/70 bg-muted/30 p-3 transition hover:border-primary/30"
        >
          <div className="absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r from-transparent via-primary/60 to-transparent opacity-0 transition group-hover:opacity-100" />
          <div className="text-[16px] font-bold tabular-nums">{s.value}</div>
          <div className="text-[10px] text-muted-foreground">{s.label}</div>
        </motion.div>
      ))}
    </div>
  );
}

function LiveList({ items, delay = 0.2 }: { items: LiveEvent[]; delay?: number }) {
  return (
    <div className="mt-2 space-y-1">
      {items.map((ev, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, x: 14 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: delay + i * 0.06 }}
          className="flex items-center gap-2.5 rounded-lg px-1.5 py-1.5 transition hover:bg-muted/40"
        >
          <span className="relative flex h-2 w-2 shrink-0">
            <span className={cn("absolute h-full w-full animate-ping rounded-full opacity-60", LIVE_DOT[ev.tone])} />
            <span className={cn("relative h-2 w-2 rounded-full", LIVE_DOT[ev.tone])} />
          </span>
          <span className="min-w-0 flex-1 truncate text-sm text-foreground/85">{ev.text}</span>
          <span className="shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground">{ev.time}</span>
        </motion.div>
      ))}
    </div>
  );
}

function RecommendationList({ items, delay = 0.2 }: { items: string[]; delay?: number }) {
  return (
    <div className="mt-2 space-y-1.5">
      {items.map((rec, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, x: 14 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: delay + i * 0.06 }}
          className="flex items-start gap-2 rounded-xl border border-primary/10 bg-primary/5 px-2.5 py-2"
        >
          <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" />
          <span className="text-sm leading-snug text-foreground/85">{rec}</span>
        </motion.div>
      ))}
    </div>
  );
}

function MitreChips({ items }: { items: string[] }) {
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {items.map((t) => (
        <span key={t} className="rounded-full border border-brand-purple/25 bg-brand-purple/10 px-2.5 py-1 font-mono text-[10px] font-semibold text-brand-purple">
          {t}
        </span>
      ))}
    </div>
  );
}

function DetailOverlay({ selection, onClose }: { selection: Selection; onClose: () => void }) {
  /* Esc to close + lock page scroll while the overlay is open */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [onClose]);

  if (typeof document === "undefined") return null;

  return createPortal(
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.22 }}
      className="fixed inset-0 z-[80] flex overflow-y-auto p-4 md:p-8"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      {/* holographic backdrop */}
      <div className="pointer-events-none fixed inset-0 bg-foreground/50 backdrop-blur-md" />
      <div className="pointer-events-none fixed inset-0 dot-grid opacity-50" />
      <motion.div
        className="pointer-events-none fixed -top-28 left-1/4 h-80 w-80 rounded-full bg-brand-purple/30 blur-[110px]"
        animate={{ opacity: [0.45, 0.9, 0.45], scale: [1, 1.15, 1] }}
        transition={{ repeat: Infinity, duration: 7, ease: "easeInOut" }}
      />
      <motion.div
        className="pointer-events-none fixed -bottom-28 right-1/5 h-80 w-80 rounded-full bg-brand-blue/30 blur-[110px]"
        animate={{ opacity: [0.45, 0.9, 0.45], scale: [1, 1.1, 1] }}
        transition={{ repeat: Infinity, duration: 8, ease: "easeInOut", delay: 1.4 }}
      />

      {/* HUD panel */}
      <motion.div
        initial={{ opacity: 0, scale: 0.94, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.96, y: 12 }}
        transition={{ type: "spring", stiffness: 320, damping: 28 }}
        onClick={(e) => e.stopPropagation()}
        className="relative m-auto w-full max-w-3xl overflow-hidden rounded-3xl border border-primary/25 bg-card/95 shadow-[0_0_100px_-18px_rgba(109,93,246,0.55)] backdrop-blur-2xl"
      >
        <div className="absolute inset-x-0 top-0 z-10 h-[3px] bg-gradient-to-r from-brand-purple via-brand-blue to-brand-pink" />
        {[
          "left-2 top-2 border-l-2 border-t-2",
          "right-2 top-2 border-r-2 border-t-2",
          "bottom-2 left-2 border-b-2 border-l-2",
          "bottom-2 right-2 border-b-2 border-r-2",
        ].map((c) => (
          <span key={c} className={`pointer-events-none absolute z-10 h-5 w-5 rounded-sm border-primary/40 ${c}`} />
        ))}
        {/* scanline sweep */}
        <motion.div
          aria-hidden
          className="pointer-events-none absolute inset-x-0 z-[6] h-[2px] bg-gradient-to-r from-transparent via-primary/40 to-transparent"
          initial={{ top: "-2%" }}
          animate={{ top: "100%" }}
          transition={{ repeat: Infinity, duration: 3.4, ease: "linear" }}
        />

        {selection.kind === "core" ? <CoreDetailBody onClose={onClose} /> : <NodeDetailBody node={selection.node} onClose={onClose} />}
      </motion.div>
    </motion.div>,
    document.body
  );
}

function NodeDetailBody({ node, onClose }: { node: EnvNode; onClose: () => void }) {
  const detail = NODE_DETAILS[node.id] ?? NODE_DETAILS.aws;
  return (
    <div className="relative">
      {/* header */}
      <div className="relative overflow-hidden border-b border-border/70 bg-muted/20 px-6 py-5">
        <div className="pointer-events-none absolute inset-0 bg-grid opacity-50 [mask-image:radial-gradient(ellipse_at_top_left,black,transparent_70%)]" />
        <div className="relative flex items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="relative shrink-0">
              <span className="absolute inset-0 animate-pulse-ring rounded-2xl" style={{ border: `1.5px solid ${node.color}` }} />
              <span
                className="flex h-14 w-14 items-center justify-center rounded-2xl border bg-card/80"
                style={{ borderColor: `${node.color}55`, boxShadow: `0 0 26px -6px ${node.color}88` }}
              >
                <NodeGlyph node={node} />
              </span>
            </div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-[17px] font-bold tracking-tight">{node.displayName}</h3>
                <span className="rounded-full border border-success/25 bg-success/10 px-2 py-0.5 text-[10px] font-bold text-success">
                  <span className="mr-1 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-success align-middle" />
                  {node.status === "Secure" ? "Connected & Secure" : node.status}
                </span>
              </div>
              <p className="text-sm text-muted-foreground">{node.sub}</p>
              <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] font-medium text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <RefreshCw className="h-3 w-3" />
                  Last sync: 2 mins ago
                </span>
                <span className="flex items-center gap-1.5">
                  <ShieldAlert className="h-3 w-3" />
                  Last scan: Just now
                </span>
              </div>
              <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.14em]" style={{ color: node.color }}>
                {node.label} · {node.assets} · {detail.mitre.length} techniques mapped
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close details"
            className="flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-xl border border-border bg-card/80 text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* body */}
      <div className="grid gap-5 p-6 md:grid-cols-5">
        <div className="space-y-4 md:col-span-2">
          <div className="flex items-center justify-center rounded-2xl border border-border/70 bg-muted/30 p-5">
            <ScoreRing value={node._score ?? detail.score} size={150} label="Health" color={node.color} sublabel={node.assets} />
          </div>
          <StatTiles stats={detail.stats} delay={0.12} />
        </div>

        <div className="space-y-4 md:col-span-3">
          <section>
            <SectionTitle icon={<ShieldAlert className="h-3.5 w-3.5" />}>Threat analysis</SectionTitle>
            <div className="mt-2 space-y-2">
              {detail.risks.map((r, i) => {
                const Icon = r.icon;
                const meta = RISK_META[r.level];
                return (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: 14 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.14 + i * 0.07 }}
                    className="rounded-xl border border-border/70 bg-muted/20 p-3"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex min-w-0 items-center gap-2.5">
                        <span className={cn("flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border", meta.cls)}>
                          <Icon className="h-3.5 w-3.5" />
                        </span>
                        <span className="truncate text-[12px] font-medium leading-snug">{r.text}</span>
                      </div>
                      <span className={cn("shrink-0 rounded-full border px-2 py-0.5 text-[9.5px] font-bold uppercase tracking-wide", meta.cls)}>
                        {meta.label}
                      </span>
                    </div>
                    <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-muted">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${meta.weight}%` }}
                        transition={{ delay: 0.35 + i * 0.07, duration: 0.7, ease: "easeOut" }}
                        className={cn("h-full rounded-full", meta.bar)}
                      />
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </section>

          <section>
            <SectionTitle icon={<Radio className="h-3.5 w-3.5" />}>Live telemetry</SectionTitle>
            <LiveList items={detail.live} delay={0.3} />
          </section>

          <section>
            <SectionTitle icon={<Sparkles className="h-3.5 w-3.5" />}>AI recommendations</SectionTitle>
            <RecommendationList items={detail.recommendations} delay={0.38} />
          </section>

          <section>
            <SectionTitle icon={<Crosshair className="h-3.5 w-3.5" />}>MITRE ATT&CK mapping</SectionTitle>
            <MitreChips items={detail.mitre} />
          </section>
        </div>
      </div>

      {/* footer actions */}
      <div className="flex flex-wrap items-center gap-2 border-t border-border/70 bg-muted/20 px-6 py-4">
        <DetailAction href={node.link} onClick={onClose} primary>
          View in topology <ArrowUpRight className="h-3.5 w-3.5" />
        </DetailAction>
        <DetailAction href="/assets" onClick={onClose}>
          <Boxes className="h-3.5 w-3.5" /> Assets
        </DetailAction>
        <DetailAction href="/threats" onClick={onClose}>
          <ShieldAlert className="h-3.5 w-3.5" /> Threats
        </DetailAction>
        <DetailAction href={node.kind === "users" ? "/identities" : node.kind === "cloud" ? "/cloud-accounts" : "/compliance"} onClick={onClose}>
          <FileText className="h-3.5 w-3.5" /> Details
        </DetailAction>
      </div>
    </div>
  );
}

function CoreDetailBody({ onClose }: { onClose: () => void }) {
  return (
    <div className="relative">
      {/* header */}
      <div className="relative overflow-hidden border-b border-border/70 bg-muted/20 px-6 py-5">
        <div className="pointer-events-none absolute inset-0 bg-grid opacity-50 [mask-image:radial-gradient(ellipse_at_top_left,black,transparent_70%)]" />
        <div className="relative flex items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="relative shrink-0">
              <span className="absolute inset-0 animate-pulse-ring rounded-2xl border-[1.5px] border-brand-purple" />
              <span className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-gradient shadow-[0_0_28px_-4px_rgba(109,93,246,0.7)]">
                <ShieldCheck className="h-7 w-7 text-white" strokeWidth={1.8} />
              </span>
            </div>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-[17px] font-bold tracking-tight">Aegivion Security Core</h3>
                <span className="rounded-full border border-success/25 bg-success/10 px-2 py-0.5 text-[10px] font-bold text-success">
                  <span className="mr-1 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-success align-middle" />
                  Operational
                </span>
              </div>
              <p className="text-sm text-muted-foreground">Decision Intelligence Engine</p>
              <p className="mt-0.5 font-mono text-[10px] uppercase tracking-[0.14em] text-brand-purple">
                Correlating 3 clouds · 214 rules · live MITRE mapping
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close details"
            className="flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-xl border border-border bg-card/80 text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* body */}
      <div className="grid gap-5 p-6 md:grid-cols-5">
        <div className="space-y-4 md:col-span-2">
          <div className="flex items-center justify-center rounded-2xl border border-border/70 bg-muted/30 p-5">
            <ScoreRing value={CORE_DETAIL.score} size={150} label="Engine health" />
          </div>
          <StatTiles stats={CORE_DETAIL.stats} delay={0.12} />
        </div>

        <div className="space-y-4 md:col-span-3">
          <section>
            <SectionTitle icon={<Radio className="h-3.5 w-3.5" />}>Live telemetry</SectionTitle>
            <LiveList items={CORE_DETAIL.live} delay={0.2} />
          </section>

          <section>
            <SectionTitle icon={<Sparkles className="h-3.5 w-3.5" />}>AI recommendations</SectionTitle>
            <RecommendationList items={CORE_DETAIL.recommendations} delay={0.32} />
          </section>

          <section>
            <SectionTitle icon={<Crosshair className="h-3.5 w-3.5" />}>MITRE ATT&CK mapping</SectionTitle>
            <MitreChips items={CORE_DETAIL.mitre} />
          </section>
        </div>
      </div>

      {/* footer actions */}
      <div className="flex flex-wrap items-center gap-2 border-t border-border/70 bg-muted/20 px-6 py-4">
        <DetailAction href="/cloud-topology" onClick={onClose} primary>
          Open full topology <ArrowUpRight className="h-3.5 w-3.5" />
        </DetailAction>
        <DetailAction href="/detection-engine" onClick={onClose}>
          <ShieldAlert className="h-3.5 w-3.5" /> Detection engine
        </DetailAction>
        <DetailAction href="/threat-correlation" onClick={onClose}>
          <Crosshair className="h-3.5 w-3.5" /> Threat correlation
        </DetailAction>
      </div>
    </div>
  );
}
