"use client";

import { motion } from "framer-motion";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { ShieldAlert, TrendingDown } from "lucide-react";
import { ProviderMark } from "@/components/shared/provider-mark";
import dynamic from "next/dynamic";

// Optimization: Lazy load heavy visualization components
const HeavyAttackGraph = dynamic(
  () => import("@/components/topology/heavy-attack-graph"),
  { 
    loading: () => <div className="p-5 h-32 rounded-xl border border-border bg-muted animate-pulse flex items-center justify-center">Loading attack graph...</div>,
    ssr: false 
  }
);

export default function RiskPage() {
  return (
    <div>
      <PageHeader
        title="Multi-Cloud Risk Intelligence"
        description="Predictive risk scoring and cross-cloud attack path analysis."
      >
        <Badge variant="soft" className="gap-1.5 bg-destructive/10 text-destructive">
          <ShieldAlert className="h-3.5 w-3.5" /> 3 Critical Paths
        </Badge>
      </PageHeader>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="p-5 rounded-2xl border border-border bg-card shadow-soft">
          <div className="flex items-center justify-between mb-2">
            <div className="text-sm font-semibold text-muted-foreground">AWS Risk Score</div>
            <ProviderMark provider="aws" size={24} />
          </div>
          <div className="text-3xl font-bold">42/100</div>
          <div className="mt-2 text-xs text-success flex items-center gap-1"><TrendingDown className="h-3 w-3" /> -5% this week</div>
        </motion.div>
        
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="p-5 rounded-2xl border border-border bg-card shadow-soft">
          <div className="flex items-center justify-between mb-2">
            <div className="text-sm font-semibold text-muted-foreground">Azure Risk Score</div>
            <ProviderMark provider="azure" size={24} />
          </div>
          <div className="text-3xl font-bold">28/100</div>
          <div className="mt-2 text-xs text-success flex items-center gap-1"><TrendingDown className="h-3 w-3" /> -2% this week</div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="p-5 rounded-2xl border border-destructive/50 bg-destructive/5 shadow-soft">
          <div className="flex items-center justify-between mb-2">
            <div className="text-sm font-semibold text-destructive">GCP Risk Score</div>
            <ProviderMark provider="gcp" size={24} />
          </div>
          <div className="text-3xl font-bold text-destructive">85/100</div>
          <div className="mt-2 text-xs text-destructive flex items-center gap-1 font-semibold">Action Required</div>
        </motion.div>
      </div>

      <h2 className="text-xl font-bold tracking-tight mb-4">Critical Attack Paths</h2>
      <div className="space-y-4">
        <HeavyAttackGraph />
      </div>
    </div>
  );
}
