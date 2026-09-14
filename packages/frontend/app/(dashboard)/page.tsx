"use client";

import { motion } from "framer-motion";
import { MetricCards } from "@/components/dashboard/metric-cards";
import { CloudEnvironment } from "@/components/dashboard/cloud-environment";
import { AiSecurityInsights, LiveThreatFeed, AskAegivionAI } from "@/components/dashboard/right-panels";
import { RiskTrend, TopRiskyAssets } from "@/components/dashboard/risk-assets";

export default function DashboardPage() {
  return (
    <div className="space-y-4">
      {/* Top stats row */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
        <MetricCards />
      </motion.div>

      {/* Hero: cloud environment overview + live threat feed side by side in the same row */}
      <div className="grid gap-4 md:grid-cols-3">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1, duration: 0.5 }}
          className="md:col-span-2"
        >
          <CloudEnvironment className="h-[420px]" />
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.18, duration: 0.5 }}
        >
          <LiveThreatFeed className="h-full" />
        </motion.div>
      </div>

      {/* AI assistant row */}
      <div className="grid gap-4 lg:grid-cols-3">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.5 }}
        >
          <AiSecurityInsights className="h-full" />
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.24, duration: 0.5 }}
          className="lg:col-span-2"
        >
          <AskAegivionAI />
        </motion.div>
      </div>

      {/* Bottom: risk trend + top risky assets */}
      <div className="grid gap-4 lg:grid-cols-2">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.28, duration: 0.5 }}
        >
          <RiskTrend className="h-full" />
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.32, duration: 0.5 }}
        >
          <TopRiskyAssets className="h-full" />
        </motion.div>
      </div>
    </div>
  );
}
