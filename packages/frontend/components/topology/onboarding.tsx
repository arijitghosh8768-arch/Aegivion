"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { Check, ArrowRight, BookOpen, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { ProviderId } from "@/lib/types";

interface ProviderCardDef {
  id: ProviderId;
  name: string;
  desc: string;
  features: string[];
  accent: string;
  soft: string;
  logo: React.ReactNode;
  cta: string;
}

/* --- Simplified official-style brand marks (original SVG glyphs) --- */

function AwsMark() {
  return (
    <svg width="44" height="44" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="11" fill="#fff" stroke="#FF9900" strokeWidth="1" />
      <path d="M6.5 14.5c0-1.6 1.2-2.6 3-2.6.9 0 1.7.2 2.2.5v.9c-.7-.5-1.5-.7-2.3-.7-1.2 0-1.9.6-1.9 1.5 0 1 .7 1.5 1.9 1.5.8 0 1.7-.2 2.4-.7v.9c-.6.3-1.4.5-2.3.5-1.9 0-3-1-3-1.8Z" fill="#FF9900" />
      <path d="M17 14.2c0-.4-.3-.6-.9-.6h-1.6v2.9h-.9v-3.6h2.7c.9 0 1.6.4 1.6 1.3 0 .8-.6 1.2-1.3 1.2l1.3 2.2v.1h-1l-1.2-2.2h-1.2v2.2h-.9v-3.7h2.5c.8 0 1.4.4 1.4 1.2 0 .7-.5 1.1-1 1.1.5 0 .5.2.5.5 0 .1 0 .3-.1.5v.1c-.1.2 0 .4.2.5.2 0 .4-.1.6-.3.3-.3.4-.7.4-1.2Z" fill="#FF9900" />
      <path d="M12 15.2l.7-.7 1.3 1.3-1.3 1.3-.7-.7-.6.6-.8-.8.9-.9.5-.1Z" fill="#252F3E" opacity="0.25" />
      <path d="M4.5 8.5h15" stroke="#FF9900" strokeWidth="1" strokeLinecap="round" />
    </svg>
  );
}

function AzureMark() {
  return (
    <svg width="44" height="44" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="11" fill="#fff" stroke="#0078D4" strokeWidth="1" />
      <path d="M9.5 5.5h4.6l-4.1 8.4H6.6l2.9-8.4Z" fill="#0078D4" />
      <path d="M13.1 8.2h4.8l-4.4 8.9h-4.7l4.3-8.9Z" fill="#50B8E8" />
      <path d="M7.8 16.2h9.2L15.2 18H6l1.8-1.8Z" fill="#0078D4" opacity="0.85" />
    </svg>
  );
}

function GcpMark() {
  return (
    <svg width="44" height="44" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="11" fill="#fff" stroke="#4285F4" strokeWidth="1" />
      <path d="M17.1 15.2c.7-.4 1.1-1 1.1-1.8 0-1.1-.9-2-2-2l.9-2.6c2.2.6 3.7 2.6 3.7 4.9 0 1.5-.6 2.8-1.6 3.7l-1.8-2.2h-5.2l-1.4 2.6-1.6-2.7c.9-1 2.3-1.5 3.8-1.5h2.1v.6Z" fill="#4285F4" />
      <path d="M12.4 6.6c.8 0 1.6.2 2.3.6l2.2-2.2c-1.3-.9-2.9-1.4-4.5-1.4-2.4 0-4.5.9-6.1 2.4l1.9 2.7c.9-.6 2.1-.9 3.5-.9Z" fill="#EA4335" />
      <path d="M6.6 9.4c-.5.8-.8 1.7-.8 2.7 0 1.4.5 2.7 1.4 3.7l-1.9 2.6C4 17 3 14.9 3 12.6c0-1.6.5-3.1 1.3-4.4l2.3 1.2Z" fill="#FBBC05" />
    </svg>
  );
}

const CARDS: ProviderCardDef[] = [
  {
    id: "aws",
    name: "AWS",
    desc: "Connect your AWS account securely using IAM Role or AWS Access Keys.",
    features: ["EC2", "S3", "IAM", "VPC", "Lambda", "RDS", "CloudTrail", "CloudWatch"],
    accent: "text-[#FF9900]",
    soft: "bg-[#FF9900]/10",
    logo: <AwsMark />,
    cta: "Connect AWS",
  },
  {
    id: "azure",
    name: "Microsoft Azure",
    desc: "Connect Azure subscriptions securely using Microsoft Entra ID and Azure SDK.",
    features: ["Virtual Machines", "Storage Accounts", "Azure AD", "Defender for Cloud", "Resource Graph", "Activity Logs"],
    accent: "text-[#0078D4]",
    soft: "bg-[#0078D4]/10",
    logo: <AzureMark />,
    cta: "Connect Azure",
  },
  {
    id: "gcp",
    name: "Google Cloud Platform",
    desc: "Connect Google Cloud projects securely using Service Accounts.",
    features: ["Compute Engine", "Cloud Storage", "IAM", "Cloud Logging", "SCC", "VPC"],
    accent: "text-[#4285F4]",
    soft: "bg-[#4285F4]/10",
    logo: <GcpMark />,
    cta: "Connect GCP",
  },
];

export function Onboarding({ onConnect }: { onConnect: (p: ProviderId) => void }) {
  return (
    <div className="space-y-6">
      {/* hero strip */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-start gap-3 rounded-2xl border border-primary/15 bg-primary/5 p-4"
      >
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-brand-gradient">
          <ShieldCheck className="h-4.5 w-4.5 text-white" />
        </span>
        <div>
          <div className="text-[13.5px] font-semibold">Connect your first cloud environment</div>
          <p className="mt-0.5 text-[12px] leading-relaxed text-muted-foreground">
            Aegivion uses <span className="font-semibold text-foreground">read-only</span> roles to discover assets,
            analyze configurations, and detect security risks. No agents required — connect in under 5 minutes.
          </p>
        </div>
      </motion.div>

      {/* provider cards */}
      <div className="grid gap-5 lg:grid-cols-3">
        {CARDS.map((card, i) => (
          <motion.div
            key={card.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
            className="group relative"
          >
            {/* gradient border */}
            <div className="absolute -inset-px rounded-3xl bg-gradient-to-br from-transparent via-transparent to-brand-purple/0 opacity-0 transition-opacity duration-500 group-hover:opacity-100 group-hover:to-brand-purple/25" />
            <div className="card-hover relative flex h-full flex-col rounded-3xl border border-border bg-card p-6 shadow-soft">
              <div className="flex items-start justify-between">
                <motion.div
                  className="relative"
                  whileHover={{ scale: 1.08, rotate: -3 }}
                  transition={{ type: "spring", stiffness: 300, damping: 18 }}
                >
                  {card.logo}
                  <span className={cn("absolute -bottom-1 -right-1 h-3.5 w-3.5 rounded-full border-2 border-card bg-success")} />
                </motion.div>
                <BookOpen className="h-4 w-4 text-muted-foreground/60" />
              </div>

              <h3 className="mt-4 text-[17px] font-bold tracking-tight">{card.name}</h3>
              <p className="mt-1.5 text-[12.5px] leading-relaxed text-muted-foreground">{card.desc}</p>

              <div className="mt-4 flex-1">
                <div className="mb-2 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
                  Monitored services
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                  {card.features.map((f) => (
                    <span key={f} className="flex items-center gap-1.5 text-[11.5px] font-medium text-foreground/85">
                      <span className={cn("flex h-3.5 w-3.5 items-center justify-center rounded-full", card.soft)}>
                        <Check className={cn("h-2.5 w-2.5", card.accent)} strokeWidth={3} />
                      </span>
                      {f}
                    </span>
                  ))}
                </div>
              </div>

              <div className="mt-5 flex gap-2">
                <Button
                  variant="gradient"
                  className="flex-1"
                  onClick={() => onConnect(card.id)}
                >
                  {card.cta} <ArrowRight className="h-4 w-4" />
                </Button>
                <Button variant="outline" asChild>
                  <Link href="/cloud-accounts" aria-label={`Learn more about ${card.name}`}>
                    <BookOpen className="h-4 w-4" /> Learn More
                  </Link>
                </Button>
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="text-center text-[11.5px] text-muted-foreground"
      >
        <ShieldCheck className="mr-1 inline h-3.5 w-3.5 text-success" />
        SOC 2 Type II · ISO 27001 · Encrypted credentials · No write permissions granted
      </motion.p>
    </div>
  );
}
