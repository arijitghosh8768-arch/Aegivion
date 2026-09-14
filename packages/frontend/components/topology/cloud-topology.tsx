"use client";

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";
import gsap from "gsap";
import {
  Activity,
  Loader2,
  Maximize2,
  Minimize2,
  Radar,
  SearchX,
  Shield,
  Siren,
  TriangleAlert,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import {
  TOPOLOGY_W,
  TOPOLOGY_H,
  TOPOLOGY_CENTER,
  TOPOLOGY_NODES,
  TOPOLOGY_ARCS,
  ATTACK_PATHS,
  type NodeStatus,
  type TopologyNodeId,
} from "@/lib/data/topology";
import { TopologyNodeMark } from "@/components/topology/node-mark";
import { ScoreRing } from "@/components/shared/score-ring";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import type { ProviderId } from "@/lib/types";

const CX = TOPOLOGY_CENTER.x;
const CY = TOPOLOGY_CENTER.y;

const STATUS_META: Record<NodeStatus, { label: string; color: string }> = {
  healthy: { label: "Healthy", color: "#22c55e" },
  warning: { label: "Warning", color: "#f59e0b" },
  critical: { label: "Critical", color: "#ef4444" },
  disconnected: { label: "Disconnected", color: "#94a3b8" },
};

const SEVERITY_META = [
  { key: "critical", label: "Critical", color: "#ef4444" },
  { key: "high", label: "High", color: "#f97316" },
  { key: "medium", label: "Medium", color: "#eab308" },
  { key: "low", label: "Low", color: "#60a5fa" },
] as const;

function riskColor(risk: number) {
  if (risk >= 75) return "#ef4444";
  if (risk >= 55) return "#f59e0b";
  return "#22c55e";
}

const wrapAngle = (a: number) => ((a % 360) + 360) % 360;

function polarPoint(angleDeg: number, radius: number) {
  const rad = (angleDeg * Math.PI) / 180;
  return { x: CX + radius * Math.sin(rad), y: CY - radius * Math.cos(rad) };
}

interface LinkGeom {
  d: string;
  sx: number;
  sy: number;
  mx: number;
  my: number;
  ex: number;
  ey: number;
}

function linkD(nx: number, ny: number): LinkGeom {
  const dx = CX - nx;
  const dy = CY - ny;
  const dist = Math.hypot(dx, dy);
  const ux = dx / dist;
  const uy = dy / dist;
  const sx = nx + ux * 58;
  const sy = ny + uy * 58;
  const ex = CX - ux * 92;
  const ey = CY - uy * 92;
  const mx = (sx + ex) / 2 + -uy * 46;
  const my = (sy + ey) / 2 + ux * 46;
  return {
    d: `M ${sx.toFixed(1)} ${sy.toFixed(1)} Q ${mx.toFixed(1)} ${my.toFixed(1)} ${ex.toFixed(1)} ${ey.toFixed(1)}`,
    sx,
    sy,
    mx,
    my,
    ex,
    ey,
  };
}

function quadPoint(g: LinkGeom, t: number) {
  const u = 1 - t;
  return {
    x: u * u * g.sx + 2 * u * t * g.mx + t * t * g.ex,
    y: u * u * g.sy + 2 * u * t * g.my + t * t * g.ey,
  };
}

function attackD(ax: number, ay: number, bx: number, by: number) {
  const mx = (ax + bx) / 2 + -(by - ay) * 0.22;
  const my = (ay + by) / 2 + (bx - ax) * 0.22;
  return {
    d: `M ${ax.toFixed(1)} ${ay.toFixed(1)} Q ${mx.toFixed(1)} ${my.toFixed(1)} ${bx.toFixed(1)} ${by.toFixed(1)}`,
    mx,
    my,
  };
}

const isProvider = (id: TopologyNodeId): id is ProviderId =>
  id === "aws" || id === "azure" || id === "gcp";

interface ViewState {
  zoom: number;
  panX: number;
  panY: number;
  dragging: boolean;
  lastX: number;
  lastY: number;
  mode: "pan" | "rotate";
}

interface Selection {
  nodeId: TopologyNodeId | "__core__";
  resourceType?: string;
}

export interface CloudTopologyProps {
  className?: string;
  height?: number | string;
  compact?: boolean;
  showMiniMap?: boolean;
  showControls?: boolean;
  showAttackPaths?: boolean;
  filteredProviders?: string[];
  filteredTypes?: string[];
  drawer?: boolean;
  fullscreen?: boolean;
  onToggleFullscreen?: () => void;
  query?: string;
}

export function CloudTopology({
  className,
  height = 520,
  compact = false,
  showMiniMap = false,
  showControls = true,
  showAttackPaths = false,
  filteredProviders,
  filteredTypes,
  drawer = false,
  fullscreen = false,
  onToggleFullscreen,
  query = "",
}: CloudTopologyProps) {
  const router = useRouter();
  const disconnectCloud = useAppStore((s) => s.disconnectCloud);

  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const sceneRef = useRef<SVGGElement>(null);
  const glowRef = useRef<HTMLDivElement>(null);
  const tooltipRef = useRef<HTMLDivElement>(null);
  const mmSvgRef = useRef<SVGSVGElement>(null);
  const mmViewportRef = useRef<SVGRectElement>(null);
  const arcRefs = useRef<(SVGPathElement | null)[]>([]);
  const coreTextRef = useRef<SVGGElement>(null);
  const nodeRefs = useRef<Record<string, SVGGElement | null>>({});
  const labelRefs = useRef<Record<string, SVGGElement | null>>({});
  const linkRefs = useRef<Record<string, (SVGPathElement | null)[]>>({});
  const packetRefs = useRef<Record<string, (SVGCircleElement | null)[]>>({});
  const mmNodeRefs = useRef<Record<string, SVGCircleElement | null>>({});
  const attackPathRefs = useRef<Record<string, SVGPathElement | null>>({});
  const attackLabelRefs = useRef<Record<string, SVGGElement | null>>({});

  const state = useRef<ViewState>({ zoom: 1, panX: 0, panY: 0, dragging: false, lastX: 0, lastY: 0, mode: "pan" });
  const rotObj = useRef({ v: 0 });
  const tweenRef = useRef<gsap.core.Tween | null>(null);
  const rotatePaused = useRef(false);
  const freezeAt = useRef<Record<string, number | null>>({});
  const baseAngle = useRef<Record<string, number>>({});
  const scaleRef = useRef<Record<string, number>>({});
  const hoverScaleRef = useRef<Record<string, number>>({});
  const hoveredIdRef = useRef<string | null>(null);

  const [selection, setSelection] = useState<Selection | null>(null);
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [zoomPct, setZoomPct] = useState(100);
  const [attackOn, setAttackOn] = useState(showAttackPaths);

  const visibleNodes = useMemo(() => {
    const ids = new Set(filteredProviders ?? TOPOLOGY_NODES.map((n) => n.id));
    return TOPOLOGY_NODES.filter((n) => ids.has(n.id));
  }, [filteredProviders]);

  const hiddenTypes = useMemo(() => new Set(filteredTypes ?? []), [filteredTypes]);

  const hoveredNode = useMemo(
    () => TOPOLOGY_NODES.find((n) => n.id === hoveredId) ?? null,
    [hoveredId]
  );

  const focusSet = useMemo(() => {
    if (!selection || selection.nodeId === "__core__") return null;
    const n = TOPOLOGY_NODES.find((x) => x.id === selection.nodeId);
    if (!n) return null;
    return new Set<string>([n.id, ...n.focus]);
  }, [selection]);

  /* ------------------------- per-frame render ------------------------- */

  const applyView = useCallback(() => {
    const svg = svgRef.current;
    const scene = sceneRef.current;
    if (!svg || !scene) return;
    const rect = svg.getBoundingClientRect();
    const fit = Math.min(rect.width / TOPOLOGY_W, rect.height / TOPOLOGY_H) || 1;
    const offX = (rect.width - TOPOLOGY_W * fit) / 2;
    const offY = (rect.height - TOPOLOGY_H * fit) / 2;

    const s = state.current;
    const r = rotObj.current.v;
    const now = performance.now() / 1000;

    scene.setAttribute("transform", `translate(${s.panX},${s.panY}) scale(${s.zoom})`);

    const pos: Record<string, { x: number; y: number }> = {};

    for (const n of visibleNodes) {
      const world = wrapAngle(baseAngle.current[n.id] ?? (n.angle + r));
      const rad = (world * Math.PI) / 180;
      const x = CX + n.radius * Math.sin(rad);
      const y = CY - n.radius * Math.cos(rad);
      pos[n.id] = { x, y };

      const el = nodeRefs.current[n.id];
      if (el) {
        const target = hoverScaleRef.current[n.id] ?? 1;
        const sc = (scaleRef.current[n.id] ?? 1) + (target - (scaleRef.current[n.id] ?? 1)) * 0.16;
        scaleRef.current[n.id] = sc;
        el.setAttribute(
          "transform",
          `translate(${x.toFixed(2)},${y.toFixed(2)}) scale(${sc.toFixed(3)})`
        );
      }
      const lbl = labelRefs.current[n.id];
      if (lbl) lbl.setAttribute("transform", `rotate(${world.toFixed(1)})`);

      const g = linkD(x, y);
      const links = linkRefs.current[n.id];
      if (links) {
        for (const l of links) if (l) l.setAttribute("d", g.d);
      }

      const pkts = packetRefs.current[n.id];
      if (pkts) {
        pkts.forEach((pkt, i) => {
          if (!pkt) return;
          const conf = n.packets[i] ?? n.packets[0];
          if (!conf) return;
          const t = (now / conf.dur + conf.offset) % 1;
          const pt = quadPoint(g, t);
          pkt.setAttribute("cx", pt.x.toFixed(2));
          pkt.setAttribute("cy", pt.y.toFixed(2));
          const a = Math.min(1, t * 7, (1 - t) * 7);
          pkt.setAttribute("opacity", (0.2 + a * 0.8).toFixed(2));
        });
      }

      const mmEl = mmNodeRefs.current[n.id];
      if (mmEl) {
        mmEl.setAttribute("cx", x.toFixed(1));
        mmEl.setAttribute("cy", y.toFixed(1));
      }
    }

    /* tooltip follows the hovered node */
    if (hoveredIdRef.current) {
      const hp = pos[hoveredIdRef.current];
      if (hp && tooltipRef.current) {
        const sx = offX + (s.panX + hp.x) * fit * s.zoom;
        const sy = offY + (s.panY + hp.y) * fit * s.zoom;
        tooltipRef.current.style.left = `${sx}px`;
        tooltipRef.current.style.top = `${sy}px`;
        /* flip below the node when it sits near the top edge */
        tooltipRef.current.style.transform =
          sy < 140 ? "translate(-50%, 20px)" : "translate(-50%, calc(-100% - 18px))";
      }
    }

    /* arc sector labels rotate with the ring, staying readable */
    TOPOLOGY_ARCS.forEach((arc, i) => {
      const el = arcRefs.current[i];
      if (!el) return;
      const mid = wrapAngle((arc.from + arc.to) / 2 + r);
      const flip = mid > 180;
      const a1 = wrapAngle(arc.from + r);
      const a2 = wrapAngle(arc.to + r);
      const p1 = polarPoint(flip ? a2 : a1, arc.r);
      const p2 = polarPoint(flip ? a1 : a2, arc.r);
      el.setAttribute(
        "d",
        `M ${p1.x.toFixed(1)} ${p1.y.toFixed(1)} A ${arc.r} ${arc.r} 0 0 ${flip ? 0 : 1} ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`
      );
    });

    /* core text rotates with the ring */
    if (coreTextRef.current) {
      coreTextRef.current.setAttribute("transform", `rotate(${r.toFixed(1)})`);
    }

    /* attack paths follow the moving nodes */
    for (const ap of ATTACK_PATHS) {
      const pathEl = attackPathRefs.current[ap.id];
      if (!pathEl) continue;
      const a = pos[ap.from];
      const b = pos[ap.to];
      if (!a || !b) {
        pathEl.setAttribute("opacity", "0");
        continue;
      }
      const g2 = attackD(a.x, a.y, b.x, b.y);
      pathEl.setAttribute("d", g2.d);
      pathEl.setAttribute("opacity", "0.75");
      const lbl = attackLabelRefs.current[ap.id];
      if (lbl) lbl.setAttribute("transform", `translate(${g2.mx.toFixed(1)},${g2.my.toFixed(1)})`);
    }

    /* mini-map viewport indicator */
    const mmSvg = mmSvgRef.current;
    const mmRect = mmViewportRef.current;
    if (mmSvg && mmRect && rect.width > 0) {
      const mrect = mmSvg.getBoundingClientRect();
      if (mrect.width > 0) {
        const cxV = (rect.width / 2 - offX) / (fit * s.zoom) - s.panX;
        const cyV = (rect.height / 2 - offY) / (fit * s.zoom) - s.panY;
        const vw = rect.width / (fit * s.zoom);
        const vh = rect.height / (fit * s.zoom);
        mmRect.setAttribute("x", (cxV - vw / 2).toFixed(1));
        mmRect.setAttribute("y", (cyV - vh / 2).toFixed(1));
        mmRect.setAttribute("width", vw.toFixed(1));
        mmRect.setAttribute("height", vh.toFixed(1));
      }
    }
  }, [visibleNodes]);

  /* ------------------------- orbital animation ------------------------- */

  useEffect(() => {
    for (const n of TOPOLOGY_NODES) {
      if (baseAngle.current[n.id] == null) baseAngle.current[n.id] = n.angle;
      scaleRef.current[n.id] = 1;
      hoverScaleRef.current[n.id] = 1;
    }
  }, []);

  useEffect(() => {
    const reduced =
      typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!reduced) {
      tweenRef.current = gsap.to(rotObj.current, {
        v: 360,
        duration: 34, // one full orbit every 34s
        ease: "none",
        repeat: -1,
      });
    }
    return () => {
      tweenRef.current?.kill();
      tweenRef.current = null;
    };
  }, []);

  useEffect(() => {
    let raf = 0;
    const loop = () => {
      applyView();
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [applyView]);

  useLayoutEffect(() => {
    applyView();
  }, [applyView]);

  /* ------------------------- zoom / pan / center ------------------------- */

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const s = state.current;
      const factor = e.deltaY < 0 ? 1.09 : 0.92;
      s.zoom = Math.min(2.6, Math.max(0.5, s.zoom * factor));
      setZoomPct(Math.round(s.zoom * 100));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const setZoom = useCallback((delta: number) => {
    const s = state.current;
    s.zoom = Math.min(2.6, Math.max(0.5, s.zoom + delta));
    setZoomPct(Math.round(s.zoom * 100));
  }, []);

  const centerView = useCallback(() => {
    gsap.to(state.current, { panX: 0, panY: 0, duration: 0.6, ease: "power3.out", overwrite: "auto" });
  }, []);

  const resetView = useCallback(() => {
    gsap.to(state.current, { panX: 0, panY: 0, zoom: 1, duration: 0.55, ease: "power3.out", overwrite: "auto" });
    setZoomPct(100);
  }, []);

  const onDoubleClick = (e: React.MouseEvent) => {
    const t = e.target as Element;
    if (t.closest(".topo-node") || t.closest(".topo-core")) return;
    centerView();
  };

  /* ------------------------- pointer drag ------------------------- */

  const endDrag = useCallback(() => {
    state.current.dragging = false;
    if (rotatePaused.current) {
      rotatePaused.current = false;
      tweenRef.current?.resume();
    }
  }, []);

  const onPointerDown = (e: React.PointerEvent) => {
    if (e.button !== 0 && e.button !== 2) return;
    e.preventDefault();
    const s = state.current;
    s.dragging = true;
    s.lastX = e.clientX;
    s.lastY = e.clientY;
    s.mode = e.button === 2 || e.ctrlKey || e.metaKey ? "rotate" : "pan";
    if (s.mode === "rotate" && !rotatePaused.current) {
      rotatePaused.current = true;
      tweenRef.current?.pause();
    }
    try {
      (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    } catch {
      /* pointer capture unavailable — drag still works via move events */
    }
  };

  const onPointerMove = (e: React.PointerEvent) => {
    const s = state.current;
    if (!s.dragging || (!(e.buttons & 1) && !(e.buttons & 2))) return;
    const dx = e.clientX - s.lastX;
    const dy = e.clientY - s.lastY;
    s.lastX = e.clientX;
    s.lastY = e.clientY;
    if (s.mode === "rotate") {
      rotObj.current.v += dx * 0.35;
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
      /* ignore */
    }
  };

  /* ------------------------- hover / freeze ------------------------- */

  const handleHover = useCallback((id: string) => {
    hoveredIdRef.current = id;
    if (freezeAt.current[id] == null) freezeAt.current[id] = rotObj.current.v;
    hoverScaleRef.current[id] = 1.07;
    setHoveredId(id);
  }, []);

  const handleUnhover = useCallback((id: string) => {
    if (hoveredIdRef.current !== id) return;
    hoveredIdRef.current = null;
    const f = freezeAt.current[id];
    if (f != null) {
      baseAngle.current[id] = wrapAngle(baseAngle.current[id] + (f - rotObj.current.v));
      freezeAt.current[id] = null;
    }
    hoverScaleRef.current[id] = 1;
    setHoveredId(null);
  }, []);

  /* ------------------------- mini-map jump ------------------------- */

  const onMmPointer = (e: React.PointerEvent) => {
    e.stopPropagation();
    const svg = mmSvgRef.current;
    const main = svgRef.current;
    if (!svg || !main) return;
    const mr = svg.getBoundingClientRect();
    const mfit = Math.min(mr.width / TOPOLOGY_W, mr.height / TOPOLOGY_H);
    const vx = (e.clientX - mr.left - (mr.width - TOPOLOGY_W * mfit) / 2) / mfit;
    const vy = (e.clientY - mr.top - (mr.height - TOPOLOGY_H * mfit) / 2) / mfit;
    const rect = main.getBoundingClientRect();
    const fit = Math.min(rect.width / TOPOLOGY_W, rect.height / TOPOLOGY_H);
    const offX = (rect.width - TOPOLOGY_W * fit) / 2;
    const offY = (rect.height - TOPOLOGY_H * fit) / 2;
    const s = state.current;
    gsap.to(state.current, {
      panX: (rect.width / 2 - offX) / (fit * s.zoom) - vx,
      panY: (rect.height / 2 - offY) / (fit * s.zoom) - vy,
      duration: 0.55,
      ease: "power3.out",
      overwrite: "auto",
    });
  };

  /* ------------------------- search highlight ------------------------- */

  const search = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return { active: false, matches: new Set<string>() };
    const m = new Set<string>();
    for (const n of TOPOLOGY_NODES) {
      const hay = [
        n.name,
        n.short,
        n.tagline,
        n.region,
        ...n.resources.map((r) => r.type),
        ...n.sections.flatMap((s) => s.values),
      ]
        .join(" ")
        .toLowerCase();
      if (hay.includes(q)) m.add(n.id);
    }
    return { active: true, matches: m };
  }, [query]);

  /* ------------------------- ambient glow ------------------------- */

  useEffect(() => {
    if (!containerRef.current || !glowRef.current) return;
    const ctx = gsap.context(() => {
      gsap.fromTo(
        containerRef.current,
        { opacity: 0, y: 8 },
        { opacity: 1, y: 0, duration: 1.1, ease: "power2.out" }
      );
      gsap.to(glowRef.current, {
        rotation: 360,
        transformOrigin: "center",
        duration: 70,
        repeat: -1,
        ease: "none",
      });
    });
    return () => ctx.revert();
  }, []);

  const closeSelection = useCallback(() => setSelection(null), []);
  const handleDisconnect = useCallback(
    (id: TopologyNodeId) => {
      if (isProvider(id)) disconnectCloud(id);
      setSelection(null);
    },
    [disconnectCloud]
  );

  /* ------------------------- render ------------------------- */

  return (
    <div
      ref={containerRef}
      className={cn("group relative select-none overflow-hidden rounded-2xl border border-border bg-card/60", className)}
      style={{ height, minHeight: typeof height === "number" ? undefined : 480, touchAction: "none" }}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={endDrag}
      onPointerLeave={endDrag}
      onDoubleClick={onDoubleClick}
      onContextMenu={(e) => e.preventDefault()}
    >
      {/* ambient glow */}
      <div className="pointer-events-none absolute inset-0 bg-brand-purple/[0.05]" />
      <div
        ref={glowRef}
        className="pointer-events-none absolute left-1/2 top-1/2 h-[70%] w-[70%] -translate-x-1/2 -translate-y-1/2 rounded-full bg-brand-gradient opacity-[0.06] blur-[80px]"
      />

      <svg
        ref={svgRef}
        viewBox={`0 0 ${TOPOLOGY_W} ${TOPOLOGY_H}`}
        className="h-full w-full cursor-grab active:cursor-grabbing"
        style={{ touchAction: "none" }}
      >
        <defs>
          <linearGradient id="core-grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#6d5df6" />
            <stop offset="55%" stopColor="#4f7cf7" />
            <stop offset="100%" stopColor="#c35df5" />
          </linearGradient>
          {TOPOLOGY_NODES.map((n) => (
            <linearGradient key={n.id} id={`link-${n.id}`} x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={n.color} stopOpacity="0.9" />
              <stop offset="100%" stopColor="#6d5df6" stopOpacity="0.25" />
            </linearGradient>
          ))}
          <filter id="soft-glow" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="6" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <radialGradient id="core-fill">
            <stop offset="0%" stopColor="#8b7bff" stopOpacity="0.55" />
            <stop offset="70%" stopColor="#6d5df6" stopOpacity="0.18" />
            <stop offset="100%" stopColor="#4f7cf7" stopOpacity="0" />
          </radialGradient>
          <path id="core-text-top" d="M -75 0 A 75 75 0 0 1 75 0" />
          <path id="core-text-bottom" d="M -75 0 A 75 75 0 0 0 75 0" />
        </defs>

        {/* radar background rings */}
        <g className="pointer-events-none" opacity="0.5">
          {[150, 260, 380].map((r) => (
            <circle key={r} cx={CX} cy={CY} r={r} fill="none" stroke="var(--border)" strokeWidth="1" strokeDasharray="2 7" />
          ))}
          <circle cx={CX} cy={CY} r={600} fill="url(#core-fill)" />
        </g>

        {/* attack paths */}
        {attackOn &&
          ATTACK_PATHS.map((ap) => (
            <g key={ap.id} className="pointer-events-none">
              <path
                ref={(el) => {
                  attackPathRefs.current[ap.id] = el;
                }}
                fill="none"
                stroke={ap.severity === "critical" ? "#ef4444" : ap.severity === "high" ? "#f59e0b" : "#3b82f6"}
                strokeWidth="2"
                strokeDasharray="6 6"
                className="animate-dash"
                opacity="0.75"
              />
              <path fill="none" stroke={ap.severity === "critical" ? "#ef4444" : "#f59e0b"} strokeWidth="5" opacity="0.12" />
              <g
                ref={(el) => {
                  attackLabelRefs.current[ap.id] = el;
                }}
              >
                <rect x="-72" y="-16" width="144" height="23" rx="11.5" fill="var(--card)" stroke="var(--border)" />
                <text
                  textAnchor="middle"
                  dy="5.5"
                  fontSize="10.5"
                  fontWeight="600"
                  fill={ap.severity === "critical" ? "#ef4444" : ap.severity === "high" ? "#f59e0b" : "#3b82f6"}
                >
                  {ap.label}
                </text>
              </g>
            </g>
          ))}

        <g ref={sceneRef}>
          {/* arc sector labels */}
          <g className="pointer-events-none" opacity="0.8">
            {TOPOLOGY_ARCS.map((arc, i) => (
              <g key={arc.text}>
                <path
                  ref={(el) => {
                    arcRefs.current[i] = el;
                  }}
                  id={`topo-arc-${i}`}
                  fill="none"
                  stroke="var(--border)"
                  strokeWidth="1"
                  strokeDasharray="2 5"
                />
                <text
                  textAnchor="middle"
                  fontSize="9.5"
                  fontWeight="700"
                  letterSpacing="3"
                  fill="var(--muted-foreground)"
                  style={{ fontStyle: "normal" }}
                >
                  <textPath href={`#topo-arc-${i}`} startOffset="50%">
                    {arc.text}
                  </textPath>
                </text>
              </g>
            ))}
          </g>

          {/* connections + packets */}
          {visibleNodes.map((n) => {
            const bright = hoveredId === n.id || (focusSet?.has(n.id) ?? false);
            const dim = search.active
              ? !search.matches.has(n.id)
              : focusSet
                ? !focusSet.has(n.id)
                : false;
            return (
              <g key={`link-${n.id}`}>
                <path
                  ref={(el) => {
                    linkRefs.current[n.id] = [el, linkRefs.current[n.id]?.[1] ?? null];
                  }}
                  fill="none"
                  stroke={`url(#link-${n.id})`}
                  strokeWidth={bright ? 2.4 : 1.5}
                  opacity={dim ? 0.12 : bright ? 1 : 0.8}
                  style={{ transition: "opacity 0.35s ease, stroke-width 0.3s ease" }}
                />
                <path
                  ref={(el) => {
                    linkRefs.current[n.id] = [linkRefs.current[n.id]?.[0] ?? null, el];
                  }}
                  fill="none"
                  stroke={n.color}
                  strokeWidth={bright ? 2.2 : 1.6}
                  strokeDasharray="2 10"
                  strokeLinecap="round"
                  opacity={dim ? 0 : bright ? 0.85 : 0.5}
                  className={bright ? "animate-dash-fast" : "animate-dash"}
                  style={{ transition: "opacity 0.35s ease" }}
                />
                {!dim &&
                  n.packets.map((pk, i) => (
                    <circle
                      key={i}
                      ref={(el) => {
                        const arr = packetRefs.current[n.id] ?? (packetRefs.current[n.id] = []);
                        arr[i] = el;
                      }}
                      r={pk.size}
                      fill={n.color}
                      filter="url(#soft-glow)"
                    />
                  ))}
              </g>
            );
          })}

          {/* nodes */}
          {visibleNodes.map((n, ni) => {
            const selected = selection?.nodeId === n.id;
            const hovered = hoveredId === n.id;
            const searchHit = search.active && search.matches.has(n.id);
            const dim = search.active
              ? !searchHit
              : focusSet
                ? !focusSet.has(n.id)
                : false;
            const status = STATUS_META[n.status];
            const visibleResources = n.resources.filter((r) => !hiddenTypes.has(r.type));
            return (
              <g
                key={n.id}
                ref={(el) => {
                  nodeRefs.current[n.id] = el;
                }}
                className="topo-node cursor-pointer focus:outline-none"
                style={{ opacity: dim ? 0.3 : 1, transition: "opacity 0.35s ease" }}
                onClick={(e) => {
                  e.stopPropagation();
                  router.push(`/providers/${n.id}`);
                }}
                onPointerEnter={(e) => {
                  e.stopPropagation();
                  handleHover(n.id);
                }}
                onPointerLeave={() => handleUnhover(n.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    router.push(`/providers/${n.id}`);
                  }
                }}
                role="button"
                tabIndex={0}
                aria-label={`${n.name} node`}
              >
                {selected && (
                  <circle r="70" fill="none" stroke={n.color} strokeWidth="1.5" strokeDasharray="4 6" className="animate-dash" opacity="0.9" />
                )}
                {searchHit && (
                  <circle
                    r="58"
                    fill="none"
                    stroke={n.color}
                    strokeWidth="2"
                    className="animate-pulse-ring"
                    style={{ transformBox: "fill-box", transformOrigin: "center", opacity: 0.7 }}
                  />
                )}
                {/* hover glow */}
                <circle r="56" fill={n.soft} opacity={hovered ? 0.9 : 0} style={{ transition: "opacity 0.3s ease" }} />
                {/* steady node pulse */}
                <circle
                  r="58"
                  fill="none"
                  stroke={n.color}
                  strokeWidth="1.2"
                  className="animate-pulse-ring"
                  style={{ animationDelay: `${ni * 1.15}s`, transformBox: "fill-box", transformOrigin: "center", opacity: 0.35 }}
                />
                {/* orbit resource dots */}
                <g style={{ animation: `spin ${n.orbitSpeed}s linear infinite`, transformBox: "fill-box", transformOrigin: "center" }}>
                  {visibleResources.map((r, i) => (
                    <circle
                      key={i}
                      cx={Math.cos((r.angle * Math.PI) / 180) * n.orbitRadius}
                      cy={Math.sin((r.angle * Math.PI) / 180) * n.orbitRadius}
                      r="5"
                      fill={riskColor(r.risk)}
                      opacity="0.9"
                      className="cursor-pointer transition-opacity hover:opacity-100"
                      onClick={(e) => {
                        e.stopPropagation();
                        router.push(`/providers/${n.id}`);
                      }}
                    >
                      <title>{`${r.type} · risk ${r.risk}/100`}</title>
                    </circle>
                  ))}
                </g>
                <g
                  style={{ animation: `spin ${n.orbitSpeed2}s linear infinite reverse`, transformBox: "fill-box", transformOrigin: "center" }}
                  opacity="0.55"
                >
                  {visibleResources.map((r, i) => (
                    <circle
                      key={`b-${i}`}
                      cx={Math.cos(((r.angle + 36) * Math.PI) / 180) * (n.orbitRadius + 34)}
                      cy={Math.sin(((r.angle + 36) * Math.PI) / 180) * (n.orbitRadius + 34)}
                      r="3"
                      fill={n.color}
                    />
                  ))}
                </g>
                {/* node body */}
                <circle r="52" fill={n.soft} stroke={n.color} strokeWidth="2.5" filter="url(#soft-glow)" opacity="0.95" />
                <circle r="44" fill="var(--card)" stroke={n.color} strokeWidth="1.5" opacity="0.95" />
                {/* floating logo mark — always upright */}
                <g style={{ animation: `float-y 7s ease-in-out ${ni * 0.7}s infinite`, transformBox: "fill-box", transformOrigin: "center" }}>
                  <TopologyNodeMark nodeId={n.id} size={46} />
                </g>
                {/* label block — rotates naturally with the orbit */}
                <g
                  ref={(el) => {
                    labelRefs.current[n.id] = el;
                  }}
                >
                  <text textAnchor="middle" dy="64" fontSize="12.5" fontWeight="700" fill="var(--foreground)">
                    {n.name}
                  </text>
                  <g transform="translate(0, 74)">
                    <rect x="-34" y="-10" width="68" height="20" rx="10" fill="var(--card)" stroke="var(--border)" />
                    <circle cx="-24" cy="0" r="3" fill={status.color}>
                      <animate attributeName="opacity" values="1;0.3;1" dur="2s" repeatCount="indefinite" />
                    </circle>
                    <text x="14" textAnchor="middle" dy="3.5" fontSize="10" fontWeight="600" fill={status.color}>
                      {status.label}
                    </text>
                  </g>
                  <text textAnchor="middle" dy="104" fontSize="10" fontWeight="500" fill="var(--muted-foreground)">
                    {n.resourceCount} {n.assetLabel}
                  </text>
                </g>
              </g>
            );
          })}

          {/* central security core */}
          <g
            transform={`translate(${CX},${CY})`}
            onClick={() => router.push("/cloud-topology")}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                router.push("/cloud-topology");
              }
            }}
            className="topo-core cursor-pointer focus:outline-none"
            role="button"
            tabIndex={0}
            aria-label="Aegivion security core"
          >
            {[0, 1, 2].map((i) => (
              <circle
                key={i}
                r="70"
                fill="none"
                stroke="#6d5df6"
                strokeWidth="1.5"
                className="animate-pulse-ring"
                style={{ animationDelay: `${i * 1.1}s`, transformBox: "fill-box", transformOrigin: "center", opacity: 0.4 }}
              />
            ))}
            <circle r="92" fill="url(#core-fill)" />
            <circle
              r="66"
              fill="rgba(109,93,246,0.10)"
              stroke="url(#core-grad)"
              strokeWidth="2.5"
              filter="url(#soft-glow)"
              style={{ animation: "breathe 6s ease-in-out infinite", transformBox: "fill-box", transformOrigin: "center" }}
            />
            <circle r="54" fill="var(--card)" stroke="url(#core-grad)" strokeWidth="1.5" />
            
            {/* The shield stays completely static, not rotated */}
            <Shield width={44} height={44} x={-22} y={-26} className="text-brand-purple" strokeWidth={1.8} />
            
            {/* The text rotates around the central static core */}
            <g ref={coreTextRef} className="pointer-events-none">
              <text fontSize="11" fontWeight="700" letterSpacing="0.05em" fill="var(--foreground)">
                <textPath href="#core-text-top" startOffset="50%" textAnchor="middle">
                  Aegivion Security Core
                </textPath>
              </text>
              <text fontSize="9.5" fontWeight="500" letterSpacing="0.05em" fill="var(--muted-foreground)">
                <textPath href="#core-text-bottom" startOffset="50%" textAnchor="middle">
                  Decision Intelligence Engine
                </textPath>
              </text>
            </g>
          </g>
        </g>
      </svg>

      {/* mini-map */}
      {showMiniMap && (
        <div className="absolute bottom-4 right-4 z-10 overflow-hidden rounded-xl border border-border bg-card/90 p-1.5 shadow-soft backdrop-blur">
          <svg
            ref={mmSvgRef}
            width="150"
            height="98"
            viewBox={`0 0 ${TOPOLOGY_W} ${TOPOLOGY_H}`}
            onPointerDown={onMmPointer}
            className="cursor-pointer"
          >
            <rect width={TOPOLOGY_W} height={TOPOLOGY_H} fill="var(--muted)" rx="6" />
            <circle cx={CX} cy={CY} r="20" fill="rgba(109,93,246,0.15)" stroke="#6d5df6" strokeWidth="1.5" />
            {visibleNodes.map((n) => (
              <circle
                key={n.id}
                ref={(el) => {
                  mmNodeRefs.current[n.id] = el;
                }}
                r="5"
                fill={n.color}
                stroke="var(--card)"
                strokeWidth="1.5"
              />
            ))}
            <rect
              ref={(el) => {
                mmViewportRef.current = el;
              }}
              fill="rgba(109,93,246,0.08)"
              stroke="#6d5df6"
              strokeWidth="2"
              rx="5"
            />
          </svg>
        </div>
      )}

      {/* controls */}
      {showControls && (
        <div className="absolute right-4 top-4 z-10 flex flex-col gap-1.5">
          <button
            onClick={() => setZoom(0.15)}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card/90 text-muted-foreground shadow-soft backdrop-blur transition hover:text-foreground active:scale-95"
            aria-label="Zoom in"
          >
            <ZoomIn className="h-4 w-4" />
          </button>
          <button
            onClick={() => setZoom(-0.15)}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card/90 text-muted-foreground shadow-soft backdrop-blur transition hover:text-foreground active:scale-95"
            aria-label="Zoom out"
          >
            <ZoomOut className="h-4 w-4" />
          </button>
          <button
            onClick={resetView}
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card/90 text-muted-foreground shadow-soft backdrop-blur transition hover:text-foreground active:scale-95"
            aria-label="Reset / auto-fit view"
          >
            <Maximize2 className="h-4 w-4" />
          </button>
          {onToggleFullscreen && (
            <button
              onClick={onToggleFullscreen}
              className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card/90 text-muted-foreground shadow-soft backdrop-blur transition hover:text-foreground active:scale-95"
              aria-label={fullscreen ? "Exit fullscreen" : "Enter fullscreen"}
            >
              {fullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
            </button>
          )}
        </div>
      )}

      {/* attack path toggle */}
      {!compact && (
        <button
          onClick={() => setAttackOn((v) => !v)}
          className={cn(
            "absolute left-4 top-4 z-10 flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-[11px] font-semibold shadow-soft backdrop-blur transition active:scale-95",
            attackOn
              ? "border-destructive/30 bg-destructive/10 text-destructive"
              : "border-border bg-card/90 text-muted-foreground hover:text-foreground"
          )}
        >
          <Siren className="h-3.5 w-3.5" />
          Attack paths
        </button>
      )}

      {/* search status */}
      {search.active && (
        <div className="absolute left-4 top-12 z-10 flex items-center gap-1.5 rounded-lg border border-primary/25 bg-primary/10 px-2.5 py-1.5 text-[11px] font-semibold text-primary shadow-soft backdrop-blur">
          <SearchX className="h-3.5 w-3.5" />
          {search.matches.size > 0
            ? `${search.matches.size} node${search.matches.size > 1 ? "s" : ""} highlighted for “${query.trim()}”`
            : `No matches for “${query.trim()}”`}
        </div>
      )}

      {/* hint */}
      {!compact && (
        <div className="pointer-events-none absolute bottom-4 left-1/2 z-10 hidden -translate-x-1/2 rounded-lg bg-card/80 px-2.5 py-1.5 text-[10px] font-medium text-muted-foreground shadow-soft backdrop-blur md:block">
          <Activity className="mr-1 inline h-3 w-3" />
          Drag to pan · Scroll to zoom · Double-click to center · Right-drag to rotate
        </div>
      )}

      {/* zoom indicator */}
      {showControls && (
        <div className="pointer-events-none absolute bottom-4 left-4 z-10 rounded-lg bg-card/80 px-2 py-1 text-[10px] font-semibold tabular-nums text-muted-foreground shadow-soft backdrop-blur">
          {zoomPct}%
        </div>
      )}

      {/* hover tooltip */}
      <AnimatePresence>
        {hoveredId &&
          !selection &&
          hoveredNode &&
          visibleNodes.some((n) => n.id === hoveredId) && (
          <motion.div
            key="node-tooltip"
            ref={tooltipRef}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="pointer-events-none absolute z-30 w-56 rounded-xl border border-border bg-card/95 p-3 shadow-lift backdrop-blur-xl"
            style={{ transform: "translate(-50%, calc(-100% - 18px))" }}
          >
            <div className="flex items-center gap-2.5">
              <TopologyNodeMark nodeId={hoveredNode.id} size={34} />
              <div className="min-w-0">
                <div className="truncate text-[13px] font-bold leading-tight">{hoveredNode.name}</div>
                <div
                  className="flex items-center gap-1 text-[10px] font-semibold"
                  style={{ color: STATUS_META[hoveredNode.status].color }}
                >
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: STATUS_META[hoveredNode.status].color }} />
                  {STATUS_META[hoveredNode.status].label}
                </div>
              </div>
            </div>
            <div className="mt-2.5 space-y-1.5 border-t border-border/70 pt-2.5">
              {(
                [
                  ["Connected Resources", `${hoveredNode.resourceCount} ${hoveredNode.assetLabel}`],
                  ["Critical Findings", String(hoveredNode.findings.critical)],
                  ["Security Score", `${hoveredNode.securityScore}/100`],
                  ["Last Scan", hoveredNode.lastScan],
                ] as const
              ).map(([k, v]) => (
                <div key={k} className="flex items-center justify-between gap-3 text-[11px]">
                  <span className="text-muted-foreground">{k}</span>
                  <span className="font-semibold tabular-nums">{v}</span>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* selection detail drawer / panel */}
      <AnimatePresence>
        {selection && drawer && (
          <motion.div
            key="detail-drawer"
            initial={{ x: 360, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 360, opacity: 0 }}
            transition={{ type: "spring", stiffness: 320, damping: 30 }}
            onPointerDown={(e) => e.stopPropagation()}
            onPointerMove={(e) => e.stopPropagation()}
            onWheel={(e) => e.stopPropagation()}
            className="absolute inset-y-2 right-2 z-20 w-[340px] overflow-hidden rounded-2xl border border-border bg-card/95 shadow-lift backdrop-blur-xl"
          >
            <div className="flex h-full flex-col">
              <div className="flex-1 overflow-y-auto">
                {selection.nodeId === "__core__" ? (
                  <CoreDetail onClose={closeSelection} />
                ) : (
                  <NodeDetailPanel
                    nodeId={selection.nodeId}
                    resourceType={selection.resourceType}
                    onClose={closeSelection}
                    onDisconnect={handleDisconnect}
                  />
                )}
              </div>
            </div>
          </motion.div>
        )}
        {selection && !drawer && (
          <motion.div
            key="detail-popover"
            initial={{ x: 40, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 40, opacity: 0 }}
            transition={{ type: "spring", stiffness: 320, damping: 30 }}
            className="absolute right-4 top-16 z-20 max-h-[70%] w-[340px] overflow-hidden rounded-2xl border border-border bg-card/95 shadow-lift backdrop-blur-xl"
          >
            <div className="max-h-full overflow-y-auto">
              {selection.nodeId === "__core__" ? (
                <CoreDetail onClose={closeSelection} />
              ) : (
                <NodeDetailPanel
                  nodeId={selection.nodeId}
                  resourceType={selection.resourceType}
                  onClose={closeSelection}
                  onDisconnect={handleDisconnect}
                />
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ----------------------------- detail panel ----------------------------- */

function NodeDetailPanel({
  nodeId,
  resourceType,
  onClose,
  onDisconnect,
}: {
  nodeId: TopologyNodeId;
  resourceType?: string;
  onClose: () => void;
  onDisconnect: (id: TopologyNodeId) => void;
}) {
  const node = TOPOLOGY_NODES.find((n) => n.id === nodeId) ?? TOPOLOGY_NODES[0];
  const status = STATUS_META[node.status];
  const resource = node.resources.find((r) => r.type === resourceType);
  const [scanning, setScanning] = useState(false);
  const provider = node.kind === "provider";

  const runScan = () => {
    setScanning(true);
    setTimeout(() => setScanning(false), 1600);
  };

  const totalFindings =
    node.findings.critical + node.findings.high + node.findings.medium + node.findings.low;

  const resourcesHref = provider
    ? `/assets?provider=${node.id}`
    : node.kind === "users"
      ? "/identities"
      : "/assets";

  return (
    <div>
      {/* header */}
      <div className="flex items-start justify-between border-b border-border p-4 pb-3">
        <div className="flex items-center gap-2.5">
          <span
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border"
            style={{ borderColor: `${node.color}44`, background: node.soft, boxShadow: `0 0 22px -8px ${node.color}66` }}
          >
            <TopologyNodeMark nodeId={node.id} size={38} />
          </span>
          <div className="min-w-0">
            <div className="text-sm font-bold leading-tight">{node.name}</div>
            <div className="truncate text-[11px] text-muted-foreground">{node.tagline}</div>
            <div className="mt-1 flex items-center gap-1 text-[10px] font-bold" style={{ color: status.color }}>
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: status.color }} />
              {status.label}
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          className="rounded-lg p-1 text-muted-foreground transition hover:bg-muted hover:text-foreground"
          aria-label="Close details"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="space-y-3.5 p-4">
        {/* meta tiles */}
        <div className="grid grid-cols-2 gap-2">
          {(
            [
              ["Region", node.region],
              ["Connected Since", node.connectedSince],
              ["Asset Count", `${node.resourceCount} ${node.assetLabel}`],
              ["Last Scan", node.lastScan],
            ] as const
          ).map(([label, value]) => (
            <div key={label} className="rounded-xl bg-muted/60 px-2.5 py-2">
              <div className="truncate text-[12px] font-bold tabular-nums">{value}</div>
              <div className="text-[10px] text-muted-foreground">{label}</div>
            </div>
          ))}
        </div>

        {/* security score + severity */}
        <div className="flex items-center gap-4 rounded-xl border border-border/70 bg-muted/30 p-3">
          <ScoreRing value={node.securityScore} size={88} stroke={8} label="Security" color={node.color} />
          <div className="min-w-0 flex-1 space-y-2">
            {SEVERITY_META.map((sev) => {
              const count = node.findings[sev.key];
              const pct = totalFindings ? (count / totalFindings) * 100 : 0;
              return (
                <div key={sev.key}>
                  <div className="mb-0.5 flex items-center justify-between text-[10px]">
                    <span className="font-semibold" style={{ color: sev.color }}>
                      {count} {sev.label}
                    </span>
                    <span className="text-muted-foreground">{Math.round(pct)}%</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, background: sev.color }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {resource && (
          <div className="rounded-xl border border-primary/20 bg-primary/5 p-3">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-primary">Selected resource</div>
            <div className="mt-0.5 flex items-center justify-between">
              <span className="text-[13px] font-semibold">{resource.type}</span>
              <span className="flex items-center gap-1 text-[11px] font-bold" style={{ color: riskColor(resource.risk) }}>
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: riskColor(resource.risk) }} />
                {resource.risk}/100
              </span>
            </div>
          </div>
        )}

        {/* sections */}
        {node.sections.map((section) => (
          <div key={section.title}>
            <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              {section.title}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {section.values.map((v) => (
                <span
                  key={v}
                  className="rounded-lg border border-border/70 bg-muted/50 px-2 py-1 text-[10.5px] font-medium text-foreground/85"
                >
                  {v}
                </span>
              ))}
            </div>
          </div>
        ))}

        {/* summary */}
        <div className="rounded-xl bg-muted/40 p-3">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Security Summary</div>
          <p className="mt-1 text-[11.5px] leading-snug text-foreground/85">{node.summary}</p>
          <div className="mt-2 flex items-center justify-between border-t border-border/60 pt-2 text-[10.5px]">
            <span className="text-muted-foreground">Compliance Score</span>
            <span className="font-bold tabular-nums" style={{ color: node.complianceScore >= 80 ? "#22c55e" : "#f59e0b" }}>
              {node.complianceScore}%
            </span>
          </div>
        </div>

        {/* risks */}
        <div>
          <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Top Risks</div>
          <div className="space-y-1.5">
            {node.risks.map((r) => (
              <div key={r.text} className="flex items-start gap-2 rounded-lg bg-muted/50 px-2.5 py-2">
                <span
                  className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: r.level === "crit" ? "#ef4444" : r.level === "warn" ? "#f59e0b" : "#22c55e" }}
                />
                <span className="text-[11.5px] leading-snug">{r.text}</span>
              </div>
            ))}
          </div>
        </div>

        {/* recommendations */}
        <div>
          <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Recommendations</div>
          <div className="space-y-1.5">
            {node.recommendations.map((rec) => (
              <div key={rec} className="flex items-start gap-2 rounded-xl border border-primary/10 bg-primary/5 px-2.5 py-2">
                <span className="mt-0.5 flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full bg-success/20 text-[9px] font-bold text-success">
                  ✓
                </span>
                <span className="text-[11.5px] leading-snug">{rec}</span>
              </div>
            ))}
          </div>
        </div>

        {/* actions */}
        <div className="grid grid-cols-2 gap-2">
          <Link
            href={resourcesHref}
            onClick={onClose}
            className="flex h-8 items-center justify-center gap-1 rounded-lg bg-brand-gradient text-[11px] font-semibold text-white shadow-soft transition hover:brightness-110"
          >
            View Resources
          </Link>
          <button
            onClick={runScan}
            disabled={scanning}
            className="flex h-8 cursor-pointer items-center justify-center gap-1 rounded-lg bg-muted text-[11px] font-semibold text-muted-foreground transition hover:text-foreground disabled:opacity-60"
          >
            {scanning ? <Loader2 className="h-3 w-3 animate-spin" /> : <Radar className="h-3 w-3" />}
            {scanning ? "Scanning…" : "Run Scan"}
          </button>
          <Link
            href="/"
            onClick={onClose}
            className="flex h-8 items-center justify-center gap-1 rounded-lg bg-muted text-[11px] font-semibold text-muted-foreground transition hover:text-foreground"
          >
            Open Dashboard
          </Link>
          {provider ? (
            <button
              onClick={() => onDisconnect(node.id)}
              className="flex h-8 cursor-pointer items-center justify-center gap-1 rounded-lg bg-destructive/10 text-[11px] font-semibold text-destructive transition hover:bg-destructive/20"
            >
              Disconnect Cloud
            </button>
          ) : (
            <div className="flex h-8 items-center justify-center gap-1 rounded-lg border border-dashed border-border text-[11px] font-medium text-muted-foreground">
              Always monitored
            </div>
          )}
        </div>

        {totalFindings > 0 && (
          <div className="flex items-start gap-1.5 rounded-xl border border-warning/25 bg-warning/10 p-3">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" />
            <p className="text-[11px] leading-snug text-muted-foreground">
              <span className="font-semibold text-warning">{totalFindings} active findings</span> —{" "}
              {node.risks[0]?.text ?? "review before remediation."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

/* ----------------------------- core panel ----------------------------- */

function CoreDetail({ onClose }: { onClose: () => void }) {
  return (
    <div>
      <div className="flex items-start justify-between border-b border-border p-4 pb-3">
        <div className="flex items-center gap-2.5">
          <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-brand-gradient">
            <Shield className="h-[20px] w-[20px] text-white" strokeWidth={2} />
          </span>
          <div>
            <div className="text-sm font-semibold leading-tight">Aegivion Security Core</div>
            <div className="text-[11px] text-muted-foreground">Decision Intelligence Engine</div>
          </div>
        </div>
        <button onClick={onClose} className="rounded-lg p-1 text-muted-foreground transition hover:bg-muted hover:text-foreground">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="space-y-3 p-4">
        <div className="grid grid-cols-3 gap-2">
          {[
            { label: "Clouds", value: "3" },
            { label: "Assets", value: "51" },
            { label: "Findings", value: "1,240" },
          ].map((s) => (
            <div key={s.label} className="rounded-xl bg-muted/60 px-2 py-2 text-center">
              <div className="text-sm font-bold tabular-nums">{s.value}</div>
              <div className="text-[10px] text-muted-foreground">{s.label}</div>
            </div>
          ))}
        </div>
        <div className="rounded-xl border border-success/25 bg-success/10 p-3">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold text-success">
            <span className="relative flex h-2 w-2">
              <span className="absolute h-full w-full animate-ping rounded-full bg-success opacity-60" />
              <span className="relative h-2 w-2 rounded-full bg-success" />
            </span>
            Engine operational · 99.99% uptime
          </div>
          <p className="mt-1.5 text-[11px] leading-snug text-muted-foreground">
            Correlating 1.2M telemetry events/min across 7 accounts with a 214-rule detection corpus and live MITRE mapping.
          </p>
        </div>
        <div className="space-y-1.5 text-[11.5px]">
          {[
            ["Active threat chains", "1"],
            ["Predictions for next 72h", "4 events"],
            ["Auto-remediation queue", "5 plans"],
          ].map(([k, v]) => (
            <div key={k} className="flex items-center justify-between">
              <span className="text-muted-foreground">{k}</span>
              <span className="font-semibold">{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
