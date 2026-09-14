"use client";

import { useMemo, useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Search, X, ShieldAlert, Globe2, ChevronLeft, ChevronRight, Boxes } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { UnifiedTable } from "@/components/inventory/unified-table";
import { ProviderMark } from "@/components/shared/provider-mark";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { ASSETS } from "@/lib/data/assets";
import { ASSET_TYPES } from "@/lib/data/assets";
import { cn } from "@/lib/utils";
import type { Asset } from "@/lib/types";

const PAGE = 8;

export default function AssetsPage() {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [provider, setProvider] = useState<string>("all");
  const [type, setType] = useState<string>("all");

  useEffect(() => {
    const search = new URLSearchParams(window.location.search);
    const p = search.get("provider");
    const t = search.get("type");
    if (p) setProvider(p);
    if (t) setType(t);
  }, []);
  const [risk, setRisk] = useState<string>("all");
  const [exposedOnly] = useState(() => typeof window !== "undefined" && window.location.search.includes("filter=exposed"));
  const [selected, setSelected] = useState<Asset | null>(null);
  const [page, setPage] = useState(0);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return ASSETS.filter((a) => {
      if (q && !`${a.name} ${a.type} ${a.owner} ${a.tags.join(" ")}`.toLowerCase().includes(q)) return false;
      if (provider !== "all" && a.provider !== provider) return false;
      if (type !== "all" && a.type !== type) return false;
      if (risk !== "all") {
        if (risk === "critical" && a.riskScore < 75) return false;
        if (risk === "high" && (a.riskScore < 50 || a.riskScore >= 75)) return false;
        if (risk === "low" && a.riskScore >= 50) return false;
      }
      if (exposedOnly && !a.publicExposed) return false;
      return true;
    });
  }, [query, provider, type, risk, exposedOnly]);

  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const safePage = Math.min(page, pages - 1);
  const rows = filtered.slice(safePage * PAGE, safePage * PAGE + PAGE);

  const totalRisk = filtered.reduce((s, a) => s + a.riskScore, 0);
  const avgRisk = filtered.length ? Math.round(totalRisk / filtered.length) : 0;
  const exposed = filtered.filter((a) => a.publicExposed).length;
  const critical = filtered.filter((a) => a.critical).length;

  return (
    <div>
      <PageHeader
        title="Assets"
        description="Every discovered resource across your cloud estate — 9,182 total."
      >
        <Button variant="outline" onClick={() => setExposedOnlyView()}>
          <Globe2 className="h-4 w-4" /> Exposed only
        </Button>
        <Button variant="gradient">
          <Boxes className="h-4 w-4" /> Inventory report
        </Button>
      </PageHeader>

      {/* stats */}
      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Matching assets", value: filtered.length.toLocaleString() },
          { label: "Avg risk", value: `${avgRisk}/100` },
          { label: "Publicly exposed", value: exposed, tint: "text-destructive" },
          { label: "Critical assets", value: critical, tint: "text-destructive" },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="rounded-2xl border border-border bg-card p-4 shadow-soft"
          >
            <div className="text-[11px] font-medium text-muted-foreground">{s.label}</div>
            <div className={cn("mt-1 text-2xl font-bold tracking-tight tabular-nums", s.tint)}>{s.value}</div>
          </motion.div>
        ))}
      </div>

      <div className="mb-8">
        <UnifiedTable />
      </div>

      {/* filters */}
      <div className="mb-4 flex flex-wrap items-center gap-2.5">
        <div className="relative min-w-[220px] flex-1 sm:max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search name, type, owner, tag…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setPage(0);
            }}
            className="pl-9"
          />
        </div>
        <Select value={provider} onValueChange={(v) => { setProvider(v); setPage(0); }}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="Provider" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All providers</SelectItem>
            <SelectItem value="aws">AWS</SelectItem>
            <SelectItem value="azure">Azure</SelectItem>
            <SelectItem value="gcp">GCP</SelectItem>
          </SelectContent>
        </Select>
        <Select value={type} onValueChange={(v) => { setType(v); setPage(0); }}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {ASSET_TYPES.map((t) => (
              <SelectItem key={t} value={t}>
                {t}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={risk} onValueChange={(v) => { setRisk(v); setPage(0); }}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="Risk" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All risk</SelectItem>
            <SelectItem value="critical">Critical (≥75)</SelectItem>
            <SelectItem value="high">High (50–74)</SelectItem>
            <SelectItem value="low">Low (&lt;50)</SelectItem>
          </SelectContent>
        </Select>
        {(query || provider !== "all" || type !== "all" || risk !== "all" || exposedOnly) && (
          <button
            onClick={() => {
              setQuery("");
              setProvider("all");
              setType("all");
              setRisk("all");
              setPage(0);
            }}
            className="flex cursor-pointer items-center gap-1 rounded-lg px-2 py-1.5 text-[12px] font-semibold text-muted-foreground transition hover:text-foreground"
          >
            <X className="h-3.5 w-3.5" /> Clear
          </button>
        )}
      </div>

      {/* table */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40">
                {["Asset", "Provider", "Type", "Region", "Risk", "Status", "Last seen", "Owner"].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => setSelected(a)}
                  className="cursor-pointer border-b border-border/60 transition hover:bg-muted/50"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-muted font-mono text-[10px] font-bold text-muted-foreground">
                        {a.type.slice(0, 2).toUpperCase()}
                      </span>
                      <div>
                        <div className="text-[13px] font-semibold">{a.name}</div>
                        <div className="text-[10.5px] text-muted-foreground">{a.id}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <ProviderMark provider={a.provider} size={26} />
                  </td>
                  <td className="px-4 py-3 text-[12.5px]">{a.type}</td>
                  <td className="px-4 py-3 text-[12px] text-muted-foreground">{a.region}</td>
                  <td className="px-4 py-3">
                    <RiskBar score={a.riskScore} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {a.publicExposed && (
                        <Badge variant="destructive" className="gap-1">
                          <Globe2 className="h-3 w-3" /> public
                        </Badge>
                      )}
                      {a.critical && (
                        <Badge variant="warning" className="gap-1">
                          <ShieldAlert className="h-3 w-3" /> critical
                        </Badge>
                      )}
                      {!a.publicExposed && !a.critical && <Badge variant="success">secure</Badge>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-[12px] text-muted-foreground">{a.lastSeen}</td>
                  <td className="px-4 py-3 text-[12px] text-muted-foreground">{a.owner}</td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-14 text-center text-sm text-muted-foreground">
                    No assets match your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between border-t border-border px-4 py-3">
          <span className="text-[11.5px] text-muted-foreground">
            Showing <b>{rows.length}</b> of <b>{filtered.length}</b> assets
          </span>
          <div className="flex items-center gap-1.5">
            <Button variant="outline" size="iconSm" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <span className="px-2 text-[11.5px] font-medium tabular-nums text-muted-foreground">
              {safePage + 1} / {pages}
            </span>
            <Button variant="outline" size="iconSm" disabled={safePage >= pages - 1} onClick={() => setPage(safePage + 1)}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </motion.div>

      {/* detail dialog */}
      <Dialog open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <DialogContent className="sm:max-w-lg">
          {selected && <AssetDetail asset={selected} />}
        </DialogContent>
      </Dialog>
    </div>
  );

  function setExposedOnlyView() {
    router.push("/assets?filter=exposed");
  }
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 75 ? "#ef4444" : score >= 50 ? "#f59e0b" : "#22c55e";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-14 overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full" style={{ width: `${score}%`, background: color }} />
      </div>
      <span className="text-[11.5px] font-bold tabular-nums" style={{ color }}>
        {score}
      </span>
    </div>
  );
}

function AssetDetail({ asset }: { asset: Asset }) {
  return (
    <div>
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2.5">
          <ProviderMark provider={asset.provider} size={32} />
          {asset.name}
        </DialogTitle>
        <DialogDescription>
          {asset.type} · {asset.region} · Account {asset.account}
        </DialogDescription>
      </DialogHeader>
      <div className="mt-4 grid grid-cols-2 gap-3">
        <div className="rounded-xl bg-muted/50 p-3">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Risk score</div>
          <RiskBar score={asset.riskScore} />
        </div>
        <div className="rounded-xl bg-muted/50 p-3">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Exposure</div>
          <div className="mt-1 flex items-center gap-1.5 text-[13px] font-semibold">
            <Globe2 className={cn("h-4 w-4", asset.publicExposed ? "text-destructive" : "text-success")} />
            {asset.publicExposed ? "Publicly reachable" : "Private"}
          </div>
        </div>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-3 text-[12.5px]">
        <Meta label="Owner" value={asset.owner} />
        <Meta label="Last seen" value={asset.lastSeen} />
        <Meta label="Account" value={asset.account} />
        <Meta label="Monitored by" value={asset.services.join(", ")} />
      </div>
      <div className="mt-4">
        <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Tags</div>
        <div className="flex flex-wrap gap-1.5">
          {asset.tags.map((t) => (
            <Badge key={t} variant="secondary">
              {t}
            </Badge>
          ))}
        </div>
      </div>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border/60 px-3 py-2">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-0.5 truncate font-medium">{value}</div>
    </div>
  );
}
