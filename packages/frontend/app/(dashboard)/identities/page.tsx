"use client";

import { useMemo, useState, useEffect } from "react";
import { motion } from "framer-motion";
import Link from "next/link";
import { Search, UserRound, KeyRound, ShieldAlert, Fingerprint, ArrowRight } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { fetchApi } from "@/lib/api-client";
import { PageHeader } from "@/components/shared/page-header";
import { ProviderMark } from "@/components/shared/provider-mark";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

type IdentityKind = "user" | "role" | "service-account";
type IdentityStatus = "active" | "suspicious" | "dormant" | "monitored";
type IdentityAccess = "admin" | "high" | "medium" | "least";

interface Identity {
  id: string;
  name: string;
  account: string;
  provider: string;
  kind: IdentityKind;
  privileges: string[];
  access: IdentityAccess;
  mfa: boolean;
  keys: number;
  risk: number;
  lastUsed: string;
  status: IdentityStatus;
}

const IDENTITY_TYPES = ["iam_user", "iam_role", "service_account"];

function mapAssetToIdentity(a: any): Identity {
  const rawType: string = (a.type ?? "").toLowerCase();
  const kind: IdentityKind = rawType.includes("role")
    ? "role"
    : rawType.includes("service")
    ? "service-account"
    : "user";

  const risk: number =
    a.risk_score ??
    (a.business_criticality === "HIGH" ? 80 : a.business_criticality === "MEDIUM" ? 50 : 20);

  const status: IdentityStatus =
    risk >= 75 ? "suspicious" : risk >= 50 ? "monitored" : a.last_seen ? "active" : "dormant";

  const access: IdentityAccess =
    risk >= 80 ? "admin" : risk >= 60 ? "high" : risk >= 40 ? "medium" : "least";

  return {
    id: a.resource_id ?? a.id ?? a.name ?? "unknown",
    name: a.name ?? "Unknown",
    account: a.account ?? a.account_id ?? "—",
    provider: (a.provider ?? "aws").toLowerCase(),
    kind,
    privileges: Array.isArray(a.privileges)
      ? a.privileges
      : [a.application, a.department].filter(Boolean),
    access,
    mfa: a.mfa_enabled ?? a.mfa ?? false,
    keys: a.access_keys ?? a.keys ?? 0,
    risk,
    lastUsed: a.last_used ?? a.last_seen ?? a.updated_at ?? "—",
    status,
  };
}

const KIND_UI: Record<IdentityKind, string> = {
  user: "User",
  role: "Role",
  "service-account": "Service Account",
};

const STATUS_UI: Record<IdentityStatus, { label: string; dot: string }> = {
  active: { label: "Active", dot: "bg-success" },
  suspicious: { label: "Suspicious", dot: "bg-destructive" },
  dormant: { label: "Dormant", dot: "bg-muted-foreground" },
  monitored: { label: "Monitored", dot: "bg-warning" },
};

export default function IdentitiesPage() {
  const [query, setQuery] = useState("");
  const [provider, setProvider] = useState<string>("all");
  const [kind, setKind] = useState("all");
  const [access, setAccess] = useState("all");

  useEffect(() => {
    const p = new URLSearchParams(window.location.search).get("provider");
    if (p) setProvider(p);
  }, []);

  const { data: rawData, isLoading } = useQuery({
    queryKey: ["assets"],
    queryFn: () => fetchApi<any>("/v1/assets"),
  });

  const IDENTITIES = useMemo<Identity[]>(() => {
    if (!rawData?.assets) return [];
    return rawData.assets
      .filter((a: any) => {
        const t = (a.type ?? "").toLowerCase();
        return IDENTITY_TYPES.some((it) => t.includes(it));
      })
      .map(mapAssetToIdentity);
  }, [rawData]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return IDENTITIES.filter((id) => {
      if (q && !`${id.name} ${id.privileges.join(" ")} ${id.account}`.toLowerCase().includes(q)) return false;
      if (provider !== "all" && id.provider !== provider) return false;
      if (kind !== "all" && id.kind !== kind) return false;
      if (access !== "all" && id.access !== access) return false;
      return true;
    });
  }, [query, provider, kind, access, IDENTITIES]);

  const noMfa = filtered.filter((i) => !i.mfa).length;
  const admin = filtered.filter((i) => i.access === "admin").length;
  const suspicious = filtered.filter((i) => i.status === "suspicious").length;
  const avgRisk = filtered.length
    ? Math.round(filtered.reduce((s, i) => s + i.risk, 0) / filtered.length)
    : 0;

  return (
    <div>
      <PageHeader
        title="Identities"
        description="Users, roles and service accounts across all cloud providers — privileges, MFA and credential posture."
      >
        <Badge variant="soft" className="gap-1.5">
          <Fingerprint className="h-3.5 w-3.5 text-primary" /> {IDENTITIES.length} identities
        </Badge>
      </PageHeader>

      {/* stats */}
      <div className="mb-5 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "Matching identities", value: filtered.length },
          { label: "No MFA", value: noMfa, tint: "text-destructive" },
          { label: "Admin access", value: admin, tint: "text-warning" },
          { label: "Suspicious", value: suspicious, tint: "text-destructive" },
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

      {/* filters */}
      <div className="mb-4 flex flex-wrap items-center gap-2.5">
        <div className="relative min-w-[220px] flex-1 sm:max-w-xs">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input placeholder="Search identity, privilege, account…" value={query} onChange={(e) => setQuery(e.target.value)} className="pl-9" />
        </div>
        <Select value={provider} onValueChange={setProvider}>
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
        <Select value={kind} onValueChange={setKind}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Kind" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All kinds</SelectItem>
            <SelectItem value="user">User</SelectItem>
            <SelectItem value="role">Role</SelectItem>
            <SelectItem value="service-account">Service Account</SelectItem>
          </SelectContent>
        </Select>
        <Select value={access} onValueChange={setAccess}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="Access" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All access</SelectItem>
            <SelectItem value="admin">Admin</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="least">Least privilege</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* table */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40">
                {["Identity", "Kind", "Provider", "Privileges", "MFA", "Keys", "Risk", "Last used", "Status"].map((h) => (
                  <th key={h} className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="px-4 py-14 text-center text-sm text-muted-foreground">
                    Loading identities…
                  </td>
                </tr>
              ) : IDENTITIES.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-14 text-center text-sm text-muted-foreground">
                    No identities discovered yet. Connect a cloud account and run a scan.
                  </td>
                </tr>
              ) : (
                <>
                  {filtered.map((id) => {
                    const st = STATUS_UI[id.status];
                    return (
                      <tr key={id.id} className="border-b border-border/60 transition hover:bg-muted/50">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2.5">
                            <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-muted text-muted-foreground">
                              {id.kind === "service-account" ? <KeyRound className="h-3.5 w-3.5" /> : <UserRound className="h-3.5 w-3.5" />}
                            </span>
                            <div>
                              <div className="text-[13px] font-semibold">{id.name}</div>
                              <div className="text-[10.5px] text-muted-foreground">{id.account}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-[12.5px]">{KIND_UI[id.kind]}</td>
                        <td className="px-4 py-3">
                          <ProviderMark provider={id.provider as any} size={26} />
                        </td>
                        <td className="max-w-[220px] px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {id.privileges.slice(0, 2).map((p) => (
                              <Badge key={p} variant={id.access === "admin" ? "destructive" : "soft"}>
                                {p}
                              </Badge>
                            ))}
                            {id.privileges.length > 2 && <Badge variant="soft">+{id.privileges.length - 2}</Badge>}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {id.mfa ? (
                            <span className="flex items-center gap-1 text-[11.5px] font-semibold text-success">
                              <Fingerprint className="h-3.5 w-3.5" /> Enabled
                            </span>
                          ) : (
                            <span className="flex items-center gap-1 text-[11.5px] font-semibold text-destructive">
                              <ShieldAlert className="h-3.5 w-3.5" /> Missing
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-[12.5px] tabular-nums text-muted-foreground">{id.keys}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-12 overflow-hidden rounded-full bg-muted">
                              <div
                                className="h-full rounded-full"
                                style={{ width: `${id.risk}%`, background: id.risk >= 75 ? "#ef4444" : id.risk >= 50 ? "#f59e0b" : "#22c55e" }}
                              />
                            </div>
                            <span className={cn("text-[11.5px] font-bold tabular-nums", id.risk >= 75 ? "text-destructive" : id.risk >= 50 ? "text-warning" : "text-success")}>
                              {id.risk}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-[12px] text-muted-foreground">{id.lastUsed}</td>
                        <td className="px-4 py-3">
                          <span className={cn("inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/60 px-2 py-0.5 text-[11px] font-medium capitalize", st.dot === "bg-destructive" && "text-destructive", st.dot === "bg-warning" && "text-warning")}>
                            <span className={cn("h-1.5 w-1.5 rounded-full", st.dot)} />
                            {st.label}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={9} className="px-4 py-14 text-center text-sm text-muted-foreground">
                        No identities match your filters.
                      </td>
                    </tr>
                  )}
                </>
              )}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between border-t border-border px-4 py-3">
          <span className="text-[11.5px] text-muted-foreground">
            Showing <b>{filtered.length}</b> identities · avg risk <b>{avgRisk}</b>/100
          </span>
          <Link href="/settings" className="flex items-center gap-1 text-[11px] font-semibold text-primary hover:underline">
            Identity provider settings <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
      </motion.div>
    </div>
  );
}
