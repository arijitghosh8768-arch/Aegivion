"use client";

import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { ProviderMark } from "@/components/shared/provider-mark";
import { ArrowRight } from "lucide-react";

export default function HeavyAttackGraph() {
  return (
    <div className="space-y-4">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }} className="p-5 rounded-xl border border-border bg-card shadow-soft">
        <div className="flex items-center gap-3 mb-3">
            <Badge variant="destructive">CRITICAL</Badge>
            <h3 className="font-semibold">Public Compute Instance with Primitive Role</h3>
            <ProviderMark provider="gcp" size={20} className="ml-auto" />
        </div>
        <p className="text-sm text-muted-foreground mb-4">An attacker compromising this public compute instance immediately gains project-wide Owner/Editor access via its attached service account.</p>
        
        <div className="flex flex-col gap-3 mt-6">
            <div className="flex items-center gap-2 text-sm font-medium">
                <div className="px-3 py-2 rounded-md bg-muted border border-border flex flex-col gap-1 w-full">
                  <div className="flex items-center justify-between">
                    <span>1. Initial Access via Public IP</span>
                    <Badge variant="outline" className="text-xs font-mono bg-background">T1190</Badge>
                  </div>
                  <span className="text-xs text-muted-foreground font-normal">Exploit Public-Facing Application</span>
                </div>
            </div>
            
            <div className="flex justify-center">
              <ArrowRight className="h-5 w-5 text-muted-foreground rotate-90 sm:rotate-0" />
            </div>
            
            <div className="flex items-center gap-2 text-sm font-medium">
                <div className="px-3 py-2 rounded-md bg-destructive/10 text-destructive border border-destructive/20 flex flex-col gap-1 w-full">
                  <div className="flex items-center justify-between">
                    <span>2. Lateral Movement & Privilege Escalation</span>
                    <Badge variant="destructive" className="text-xs font-mono">T1078</Badge>
                  </div>
                  <span className="text-xs opacity-80 font-normal">Valid Accounts (roles/owner)</span>
                </div>
            </div>
        </div>
      </motion.div>
    </div>
  );
}
