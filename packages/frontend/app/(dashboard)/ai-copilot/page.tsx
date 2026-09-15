"use client";

import { motion } from "framer-motion";
import { Bot, Sparkles, ShieldAlert, Globe2, Wrench, FileText, BrainCircuit, Gauge } from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Badge } from "@/components/ui/badge";
import { AiPanel } from "@/components/dashboard/ai-panel";

const CAPABILITIES = [
  { icon: ShieldAlert, title: "Explain findings", desc: "Why is this EC2 risky? Get evidence-grounded reasoning.", accent: "text-destructive bg-destructive/10" },
  { icon: Globe2, title: "Attack surface", desc: "Enumerate public buckets, open ports and exposed identities.", accent: "text-warning bg-warning/10" },
  { icon: Wrench, title: "Generate remediation", desc: "Terraform + CLI fixes with rollback plans, ready for approval.", accent: "text-success bg-success/10" },
  { icon: BrainCircuit, title: "Correlate threats", desc: "Stitch alerts into kill chains with MITRE ATT&CK mapping.", accent: "text-brand-purple bg-brand-purple/10" },
  { icon: Gauge, title: "Forecast risk", desc: "14-day attack probability with confidence bands.", accent: "text-info bg-info/10" },
  { icon: FileText, title: "Generate reports", desc: "Executive, posture, compliance and threat-intel packs.", accent: "text-brand-blue bg-brand-blue/10" },
];

export default function AiCopilotPage() {
  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="AI Copilot"
        description="Your explainable security analyst — every answer cites its sources and shows its reasoning."
      >
        <Badge variant="soft" className="gap-1.5">
          <Sparkles className="h-3.5 w-3.5 text-primary" /> GPT-class reasoning · decision-grade
        </Badge>
      </PageHeader>

      <div className="grid gap-5 xl:grid-cols-[1fr_340px]">
        <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }}>
          <AiPanel expanded className="h-[560px]" />
        </motion.div>

        <div className="space-y-4">
          <motion.div
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.08 }}
            className="rounded-2xl border border-border bg-card p-4 shadow-soft"
          >
            <h3 className="flex items-center gap-2 text-[13.5px] font-semibold">
              <Bot className="h-4 w-4 text-primary" /> What I can do
            </h3>
            <div className="mt-3 grid grid-cols-2 gap-2">
              {CAPABILITIES.map((c) => (
                <div
                  key={c.title}
                  className="rounded-xl border border-border/70 bg-muted/30 p-2.5 transition hover:border-primary/30 hover:bg-primary/5"
                >
                  <span className={`flex h-7 w-7 items-center justify-center rounded-lg ${c.accent}`}>
                    <c.icon className="h-3.5 w-3.5" />
                  </span>
                  <div className="mt-1.5 text-[11.5px] font-semibold leading-tight">{c.title}</div>
                  <div className="mt-1 text-[10px] leading-snug text-muted-foreground">{c.desc}</div>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.14 }}
            className="rounded-2xl border border-border bg-card p-4 shadow-soft"
          >
            <h3 className="text-[13.5px] font-semibold">Context window</h3>
            <div className="mt-2.5 space-y-2 text-[11.5px] text-muted-foreground">
              {[
                ["Live telemetry", "Connected to API"],
                ["Environment", "Production"],
                ["Time range", "Last 30 days"],
                ["Guardrails", "Read-only · explainable"],
              ].map(([k, v]) => (
                <div key={k} className="flex items-center justify-between">
                  <span>{k}</span>
                  <span className="font-semibold text-foreground">{v}</span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
