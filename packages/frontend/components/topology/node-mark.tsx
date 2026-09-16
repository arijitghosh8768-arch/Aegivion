import { Database, Globe, Users, BrickWall, MonitorSmartphone, Network } from "lucide-react";
import { cn } from "@/lib/utils";
import type { TopologyNodeId } from "@/lib/data/topology";

/* ------------------------------------------------------------------ */
/* Brand-style marks for every topology node                           */
/* ------------------------------------------------------------------ */

function AwsMark({ size }: { size: number }) {
  return (
    <svg width={size * 0.78} height={size * 0.48} viewBox="0 0 72 44" fill="none" aria-label="AWS">
      <text x="36" y="19" textAnchor="middle" fontSize="18" fontWeight="800" fill="#FF9900" fontFamily="system-ui, sans-serif" letterSpacing="0.5">
        aws
      </text>
      <path d="M6 28 C 20 40, 52 40, 66 28" stroke="#FF9900" strokeWidth="4" strokeLinecap="round" fill="none" />
      <path d="M59 31.5 L66.5 27.5 L63.5 36.5" stroke="#FF9900" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" fill="none" />
    </svg>
  );
}

function AzureMark({ size }: { size: number }) {
  const s = Math.round(size * 0.8);
  return (
    <svg width={s} height={s} viewBox="0 0 48 48" aria-label="Microsoft Azure">
      <rect x="1.5" y="1.5" width="45" height="45" rx="10" fill="#0078D4" />
      <path d="M24 7.5 L12.5 37.5 H19.5 L24 24.5 L28.5 37.5 H35.5 Z" fill="#fff" />
      <rect x="18.5" y="19.5" width="11" height="4.6" rx="1" fill="#fff" />
    </svg>
  );
}

function GcpMark({ size }: { size: number }) {
  const s = Math.round(size * 0.82);
  return (
    <svg width={s} height={s} viewBox="0 0 48 48" aria-label="Google Cloud">
      <rect x="4.5" y="4.5" width="17.5" height="17.5" rx="4.5" fill="#4285F4" />
      <rect x="26" y="4.5" width="17.5" height="17.5" rx="4.5" fill="#EA4335" />
      <rect x="4.5" y="26" width="17.5" height="17.5" rx="4.5" fill="#FBBC05" />
      <rect x="26" y="26" width="17.5" height="17.5" rx="4.5" fill="#34A853" />
    </svg>
  );
}

const ICON_COLOR: Record<string, string> = {
  network: "#4f7cf7",
  database: "#8b5cf6",
  users: "#c35df5",
  firewall: "#FF9900",
  endpoints: "#22c55e",
};

export function TopologyNodeMark({
  nodeId,
  size = 44,
  className,
}: {
  nodeId: TopologyNodeId;
  size?: number;
  className?: string;
}) {
  if (nodeId === "aws") return <AwsMark size={size} />;
  if (nodeId === "azure") return <AzureMark size={size} />;
  if (nodeId === "gcp") return <GcpMark size={size} />;

  const Icon = nodeId === "network" ? Globe : nodeId === "database" ? Database : nodeId === "firewall" ? BrickWall : nodeId === "endpoints" ? MonitorSmartphone : Users;
  return (
    <span
      className={cn("inline-flex shrink-0 items-center justify-center", className)}
      style={{ width: size, height: size }}
      aria-label={nodeId}
    >
      <Icon size={size * 0.6} strokeWidth={1.7} style={{ color: ICON_COLOR[nodeId] }} />
    </span>
  );
}
