"use client";

import { motion } from "framer-motion";
import { Server, Database, Shield, Globe, HardDrive } from "lucide-react";
import { ProviderMark } from "@/components/shared/provider-mark";
import { Badge } from "@/components/ui/badge";

type AssetType = "Compute" | "Database" | "Storage" | "Network" | "IAM";

interface UnifiedAsset {
  id: string;
  provider: "aws" | "azure" | "gcp";
  name: string;
  type: AssetType;
  region: string;
  risk: "Critical" | "High" | "Medium" | "Low";
}

const MOCK_INVENTORY: UnifiedAsset[] = [
  { id: "i-0abc123", provider: "aws", name: "prod-web-01", type: "Compute", region: "us-east-1", risk: "Medium" },
  { id: "vm-win-02", provider: "azure", name: "sql-primary-db", type: "Database", region: "eastus", risk: "Low" },
  { id: "gcp-18823", provider: "gcp", name: "data-lake-raw", type: "Storage", region: "us-central1", risk: "High" },
  { id: "vpc-091a", provider: "aws", name: "vpc-core-net", type: "Network", region: "eu-west-1", risk: "Low" },
  { id: "gcp-99121", provider: "gcp", name: "analytics-cluster", type: "Compute", region: "europe-west3", risk: "Critical" },
  { id: "az-id-001", provider: "azure", name: "admin-svc-principal", type: "IAM", region: "global", risk: "High" },
];

const TYPE_ICONS: Record<AssetType, any> = {
  Compute: Server,
  Database: Database,
  Storage: HardDrive,
  Network: Globe,
  IAM: Shield,
};

const RISK_COLORS = {
  Critical: "bg-destructive/15 text-destructive border-destructive/30",
  High: "bg-warning/15 text-warning border-warning/30",
  Medium: "bg-orange-500/15 text-orange-500 border-orange-500/30",
  Low: "bg-success/15 text-success border-success/30",
};

export function UnifiedTable() {
  return (
    <div className="w-full">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-xl font-bold tracking-tight">Unified Multi-Cloud Inventory</h2>
        <div className="text-sm text-muted-foreground">Showing {MOCK_INVENTORY.length} assets</div>
      </div>
      <div className="rounded-xl border border-border bg-card overflow-hidden shadow-soft">
        <div className="grid grid-cols-12 gap-4 border-b border-border/50 bg-muted/40 p-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          <div className="col-span-3">Asset Name</div>
          <div className="col-span-2">Provider</div>
          <div className="col-span-3">Type</div>
          <div className="col-span-2">Region</div>
          <div className="col-span-2">Risk Level</div>
        </div>
        <div className="divide-y divide-border/50">
          {MOCK_INVENTORY.map((asset, i) => {
            const Icon = TYPE_ICONS[asset.type];
            return (
              <motion.div 
                key={asset.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
                className="grid grid-cols-12 items-center gap-4 p-4 hover:bg-muted/30 transition-colors"
              >
                <div className="col-span-3 flex flex-col">
                  <span className="font-semibold">{asset.name}</span>
                  <span className="text-[11px] text-muted-foreground font-mono mt-0.5">{asset.id}</span>
                </div>
                <div className="col-span-2 flex items-center">
                  <ProviderMark provider={asset.provider} size={28} />
                </div>
                <div className="col-span-3 flex items-center gap-2">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-muted">
                    <Icon className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <span className="text-sm font-medium">{asset.type}</span>
                </div>
                <div className="col-span-2 text-sm text-muted-foreground">
                  {asset.region}
                </div>
                <div className="col-span-2">
                  <Badge variant="outline" className={`border ${RISK_COLORS[asset.risk]}`}>
                    {asset.risk}
                  </Badge>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
