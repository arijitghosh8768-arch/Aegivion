"use client";

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { CreditCard, Check, Zap, Shield, ArrowUpRight, Loader2, Sparkles, AlertCircle } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { fetchApi } from "@/lib/api-client";

interface UsageData {
  success: boolean;
  subscription_plan: string;
  plan_details: {
    name: string;
    price: string;
    max_cloud_accounts: number;
    max_assets: number;
    max_users: number;
  };
  usage: {
    cloud_accounts: {
      current: number;
      limit: number;
      percentage: number;
    };
    assets: {
      current: number;
      limit: number;
      percentage: number;
    };
    findings: {
      current: number;
    };
  };
}

const TIERS = [
  {
    id: "free",
    name: "Free Community",
    price: "$0",
    period: "forever",
    description: "Essential cloud security monitoring for single teams.",
    features: [
      "1 Connected Cloud Account (AWS/Azure/GCP)",
      "Up to 100 Tracked Assets",
      "Core CSPM Misconfiguration Scans",
      "Standard Finding Dashboard",
      "Manual Remediation Guidance"
    ]
  },
  {
    id: "pro",
    name: "Pro Tier",
    price: "$299",
    period: "per month",
    popular: true,
    description: "Complete automated posture management for growing organizations.",
    features: [
      "Up to 5 Connected Cloud Accounts",
      "Up to 1,000 Tracked Assets",
      "AI Root-Cause & MITRE Explanations",
      "Safe Remediation Engine with Rollback",
      "Automated Pre-State Snapshots",
      "Compliance Framework Sync (SOC2, CIS, ISO)"
    ]
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: "$999",
    period: "per month",
    description: "Zero-Trust enterprise governance, multi-cloud scale & custom RAG.",
    features: [
      "Unlimited Connected Cloud Accounts",
      "Unlimited Tracked Assets",
      "Dedicated PgVector Security Knowledge RAG",
      "Custom Allowlist Enforcement",
      "Continuous Drift Detection & Auto-Rollback",
      "24/7 Dedicated Security SLA & Support"
    ]
  }
];

export default function BillingPage() {
  const [data, setData] = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [upgrading, setUpgrading] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const loadUsage = async () => {
    try {
      setLoading(true);
      const res = await fetchApi<UsageData>("/v1/billing/usage");
      setData(res);
    } catch (err: any) {
      console.error("Failed to load billing usage", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsage();
  }, []);

  const handleUpgrade = async (tier: string) => {
    setUpgrading(tier);
    setNotice(null);
    try {
      const res: any = await fetchApi("/v1/billing/upgrade", {
        method: "POST",
        body: JSON.stringify({ tier }),
      });
      setNotice(res.message || `Switched to ${tier.toUpperCase()}`);
      await loadUsage();
    } catch (err: any) {
      alert("Upgrade failed: " + err.message);
    } finally {
      setUpgrading(null);
    }
  };

  const currentPlan = data?.subscription_plan || "free";

  return (
    <div>
      <PageHeader
        title="Billing & Subscription Limits"
        description="Monitor tenant quotas, connected environments, and manage your Aegivion plan."
      />

      {notice && (
        <div className="mb-6 flex items-center gap-2 rounded-2xl border border-success/30 bg-success/10 p-4 text-xs font-medium text-success">
          <Check className="h-4 w-4" />
          <span>{notice}</span>
        </div>
      )}

      {/* Quota Overview Cards */}
      <div className="mb-8 grid gap-4 sm:grid-cols-3">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl border border-border bg-card p-5 shadow-soft"
        >
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Cloud Accounts</span>
            <Badge variant="soft" className="uppercase font-mono text-[10px]">
              {data?.usage.cloud_accounts.current} / {data?.usage.cloud_accounts.limit}
            </Badge>
          </div>
          <div className="mt-3 text-2xl font-bold tracking-tight">
            {data?.usage.cloud_accounts.current || 0}
            <span className="text-sm font-normal text-muted-foreground ml-1">
              / {data?.usage.cloud_accounts.limit || 1}
            </span>
          </div>
          <div className="mt-3">
            <Progress value={data?.usage.cloud_accounts.percentage || 0} className="h-2" />
          </div>
          <p className="mt-2 text-[11px] text-muted-foreground">
            {data?.usage.cloud_accounts.percentage}% of quota utilized
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="rounded-2xl border border-border bg-card p-5 shadow-soft"
        >
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Tracked Assets</span>
            <Badge variant="soft" className="uppercase font-mono text-[10px]">
              {data?.usage.assets.current} / {data?.usage.assets.limit}
            </Badge>
          </div>
          <div className="mt-3 text-2xl font-bold tracking-tight">
            {data?.usage.assets.current || 0}
            <span className="text-sm font-normal text-muted-foreground ml-1">
              / {data?.usage.assets.limit || 100}
            </span>
          </div>
          <div className="mt-3">
            <Progress value={data?.usage.assets.percentage || 0} className="h-2" />
          </div>
          <p className="mt-2 text-[11px] text-muted-foreground">
            Monitored instances, buckets, subnets & roles
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="rounded-2xl border border-border bg-card p-5 shadow-soft"
        >
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Current Tier</span>
            <Badge variant="gradient" className="uppercase font-mono text-[10px]">
              ACTIVE
            </Badge>
          </div>
          <div className="mt-3 text-2xl font-bold capitalize tracking-tight text-primary">
            {currentPlan}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {data?.plan_details.price || "$0/mo"} · Renews monthly
          </p>
          <div className="mt-3 text-[11px] text-muted-foreground">
            {data?.usage.findings.current || 0} total findings tracked
          </div>
        </motion.div>
      </div>

      {/* Plan Comparison Cards */}
      <div className="mb-6">
        <h2 className="text-lg font-bold tracking-tight mb-1">Available Subscriptions</h2>
        <p className="text-xs text-muted-foreground mb-4">
          Upgrade your plan anytime to unlock additional cloud accounts and automated remediation.
        </p>

        <div className="grid gap-4 md:grid-cols-3">
          {TIERS.map((tier) => {
            const isCurrent = currentPlan.toLowerCase() === tier.id;
            const isUpgrading = upgrading === tier.id;

            return (
              <div
                key={tier.id}
                className={`relative flex flex-col justify-between rounded-3xl border p-6 transition shadow-soft ${
                  tier.popular
                    ? "border-primary/50 bg-gradient-to-b from-primary/5 to-card"
                    : "border-border bg-card"
                }`}
              >
                {tier.popular && (
                  <Badge variant="gradient" className="absolute -top-3 right-6 flex items-center gap-1">
                    <Sparkles className="h-3 w-3" /> Most Popular
                  </Badge>
                )}

                <div>
                  <div className="flex items-center justify-between">
                    <h3 className="text-base font-bold">{tier.name}</h3>
                    {isCurrent && (
                      <Badge variant="outline" className="text-xs">
                        Current
                      </Badge>
                    )}
                  </div>

                  <div className="mt-4 flex items-baseline gap-1">
                    <span className="text-3xl font-extrabold tracking-tight">{tier.price}</span>
                    <span className="text-xs text-muted-foreground">/{tier.period}</span>
                  </div>

                  <p className="mt-2 text-xs text-muted-foreground leading-relaxed">
                    {tier.description}
                  </p>

                  <ul className="mt-6 space-y-2 text-xs text-muted-foreground">
                    {tier.features.map((feat) => (
                      <li key={feat} className="flex items-start gap-2">
                        <Check className="h-3.5 w-3.5 text-success shrink-0 mt-0.5" />
                        <span>{feat}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="mt-8 pt-4 border-t border-border/60">
                  <Button
                    variant={isCurrent ? "outline" : tier.popular ? "gradient" : "default"}
                    className="w-full"
                    disabled={isCurrent || isUpgrading}
                    onClick={() => handleUpgrade(tier.id)}
                  >
                    {isUpgrading ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" /> Processing…
                      </>
                    ) : isCurrent ? (
                      "Current Plan"
                    ) : (
                      `Switch to ${tier.name}`
                    )}
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

