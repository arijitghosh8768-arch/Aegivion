"use client";

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { fetchApi } from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { ShieldAlert, Cpu, Activity, Zap, Info } from "lucide-react";
import { cn } from "@/lib/utils";

export function ResponseSimulation({ ruleId, ruleName }: { ruleId: string; ruleName: string }) {
  const [open, setOpen] = useState(false);
  
  const simulationMutation = useMutation({
    mutationFn: () => fetchApi(`/v1/automation/rules/${ruleId}/simulate`, { method: "POST" }),
  });

  const handleSimulate = () => {
    if (!simulationMutation.data && !simulationMutation.isPending) {
      simulationMutation.mutate();
    }
  };

  const result = simulationMutation.data as any;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" onClick={handleSimulate}>
          <Activity className="mr-1.5 h-3.5 w-3.5" /> Simulate Response
        </Button>
      </DialogTrigger>
      
      <DialogContent className="sm:max-w-[600px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Cpu className="h-5 w-5 text-brand-blue" />
            Response Simulation
          </DialogTitle>
          <DialogDescription>
            Calculated minimum-impact response for rule: <span className="font-semibold text-foreground">{ruleName}</span>. No cloud changes will be made.
          </DialogDescription>
        </DialogHeader>

        <div className="py-4">
          {simulationMutation.isPending && (
            <div className="flex flex-col items-center justify-center py-8 text-muted-foreground animate-pulse">
              <Zap className="h-8 w-8 mb-4 text-brand-blue" />
              <p>Analyzing attack path and scoring response candidates...</p>
            </div>
          )}
          
          {simulationMutation.isSuccess && result && result.status === "SIMULATION_COMPLETE" && (
            <div className="space-y-6">
              <div className="rounded-xl border border-border bg-muted/20 p-4">
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h4 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">Optimal Response</h4>
                    <p className="text-lg font-bold text-foreground mt-1">{result.selected_action}</p>
                  </div>
                  <div className="text-right">
                    <span className={cn(
                      "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase",
                      result.policy_result === "AUTOMATIC" ? "bg-success/20 text-success" : "bg-amber-500/20 text-amber-500"
                    )}>
                      {result.policy_result.replace("_", " ")}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 md:grid-cols-4 pt-4 border-t border-border">
                  <div>
                    <div className="text-[10px] uppercase text-muted-foreground">Path Reduction</div>
                    <div className="font-semibold text-success">{result.attack_path_reduction}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase text-muted-foreground">Confidence</div>
                    <div className="font-semibold">{result.confidence}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase text-muted-foreground">Business Impact</div>
                    <div className={cn("font-semibold", result.business_impact === "LOW" ? "text-success" : "text-amber-500")}>
                      {result.business_impact}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase text-muted-foreground">Reversible</div>
                    <div className="font-semibold">{result.reversibility ? "YES" : "NO"}</div>
                  </div>
                </div>
              </div>
              
              <div className="rounded-xl border border-brand-blue/30 bg-brand-blue/5 p-4 flex gap-3">
                <Info className="h-5 w-5 text-brand-blue shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-sm font-semibold text-brand-blue mb-1">AI Recommendation Context</h4>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {result.ai_explanation}
                  </p>
                </div>
              </div>
            </div>
          )}

          {simulationMutation.isSuccess && result && result.status === "NO_SAFE_ACTION" && (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <ShieldAlert className="h-10 w-10 text-destructive mb-3" />
              <h3 className="font-semibold text-lg text-foreground">No Safe Automatic Action Found</h3>
              <p className="text-sm text-muted-foreground mt-1 max-w-sm">
                The minimum-impact optimizer determined that all available response candidates pose too high of a business risk or blast radius. Manual investigation required.
              </p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
