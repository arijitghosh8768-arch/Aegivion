"use client";

import { motion } from "framer-motion";
import Link from "next/link";
import { ArrowLeft, Server, AlertTriangle, AlertOctagon, CheckCircle2, ShieldAlert } from "lucide-react";
import { ProviderMark } from "@/components/shared/provider-mark";
import { ScoreRing } from "@/components/shared/score-ring";
import { TOPOLOGY_PROVIDERS, TOPOLOGY_NODES } from "@/lib/data/topology";
import { notFound, useParams } from "next/navigation";

// Combine both lists so we can render any provider/domain node
const ALL_NODES = [...TOPOLOGY_PROVIDERS, ...TOPOLOGY_NODES];

export default function ProviderDetailPage() {
  const params = useParams();
  const providerId = params.providerId as string;
  const provider = ALL_NODES.find((p) => p.id === providerId);

  if (!provider) {
    notFound();
  }

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="space-y-6"
    >
      <Link href="/cloud-topology" className="inline-flex items-center text-sm font-medium text-muted-foreground transition-colors hover:text-foreground">
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to Dashboard
      </Link>

      <div className="flex items-center gap-4">
        <motion.div 
          layoutId={`node-icon-${provider.id}`}
          className="flex h-16 w-16 items-center justify-center rounded-2xl border shadow-soft"
          style={{ borderColor: provider.soft, backgroundColor: provider.soft, boxShadow: `0 0 30px -5px ${provider.soft}` }}
        >
          {provider.kind === "provider" ? (
            <ProviderMark provider={provider.id as any} className="h-8 w-8" />
          ) : (
            <ShieldAlert className="h-8 w-8" style={{ color: provider.color }} />
          )}
        </motion.div>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">{provider.name} Security Overview</h1>
          <p className="text-muted-foreground">{provider.tagline}</p>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-border bg-card p-6 shadow-soft">
          <div className="flex items-center gap-4">
            <ScoreRing value={provider.securityScore} size={80} stroke={6} color={provider.color} label="Security" />
            <div>
              <div className="text-sm font-medium text-muted-foreground">Status</div>
              <div className="text-lg font-bold capitalize" style={{ color: provider.status === 'healthy' ? '#22c55e' : provider.status === 'warning' ? '#f59e0b' : '#ef4444' }}>
                {provider.status}
              </div>
            </div>
          </div>
        </div>
        
        <div className="rounded-xl border border-border bg-card p-6 shadow-soft">
          <div className="flex items-center gap-4">
            <ScoreRing value={provider.complianceScore} size={80} stroke={6} color="#22c55e" label="Compliance" />
            <div>
              <div className="text-sm font-medium text-muted-foreground">Framework</div>
              <div className="text-lg font-bold text-success">Passing</div>
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card p-6 shadow-soft">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-muted-foreground">Critical Findings</div>
              <div className="text-3xl font-bold">{provider.findings.critical}</div>
            </div>
            <div className="rounded-full bg-destructive/10 p-3">
              <AlertOctagon className="h-6 w-6 text-destructive" />
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-border bg-card p-6 shadow-soft">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-muted-foreground">Vulnerabilities</div>
              <div className="text-3xl font-bold">{provider.findings.high + provider.findings.medium}</div>
            </div>
            <div className="rounded-full bg-warning/10 p-3">
              <AlertTriangle className="h-6 w-6 text-warning" />
            </div>
          </div>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">Infrastructure Assets</h2>
          <div className="grid gap-3 sm:grid-cols-2">
            {provider.resources.map((res) => (
              <div key={res.type} className="flex items-center gap-4 rounded-xl border border-border bg-card p-4 shadow-soft">
                <div className="rounded-lg bg-muted p-2">
                  <Server className="h-5 w-5 text-muted-foreground" />
                </div>
                <div>
                  <div className="text-2xl font-bold">{res.risk}</div>
                  <div className="text-xs font-medium text-muted-foreground">{res.type} Risk Level</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <h2 className="text-xl font-semibold">Top Security Risks</h2>
          <div className="space-y-3">
            {provider.risks.map((risk, i) => (
              <div key={i} className="flex items-center justify-between rounded-xl border border-border bg-card p-4 shadow-soft">
                <div className="flex items-center gap-3">
                  <div className={`h-2 w-2 rounded-full ${
                    risk.level === "crit" ? "bg-destructive animate-pulse" : "bg-warning"
                  }`} />
                  <span className="text-sm font-medium">{risk.text}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  );
}
