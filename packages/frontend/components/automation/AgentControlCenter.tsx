"use client";

import { ShieldCheck, Play, Pause, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function AgentControlCenter({ agent, isAdmin }: { agent: any; isAdmin: boolean }) {
  if (!agent) return null;

  return (
    <div className="mb-6 rounded-2xl border border-border bg-card p-4 shadow-soft">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-success/10 text-success">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold flex items-center gap-2">
              Autonomous Security Agent
              <span className={cn(
                "px-2 py-0.5 rounded-full text-[9px] uppercase tracking-wider font-bold",
                agent.status === "ONLINE" ? "bg-success/20 text-success" : "bg-muted text-muted-foreground"
              )}>
                {agent.status}
              </span>
            </h3>
            <p className="text-xs text-muted-foreground">
              Last heartbeat: {agent.last_heartbeat} — {agent.current_activity}
            </p>
          </div>
        </div>
        
        <div className="flex flex-wrap items-center gap-4 lg:gap-8">
           {Object.entries(agent.workers || {}).map(([key, status]) => (
              <div key={key} className="text-center">
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{key}</div>
                <div className={cn(
                  "text-xs font-semibold flex items-center justify-center gap-1",
                  (status as string) === "RUNNING" ? "text-success" : "text-muted-foreground"
                )}>
                  {(status as string) === "RUNNING" && <Activity className="h-3 w-3 animate-pulse" />}
                  {status as string}
                </div>
              </div>
           ))}
        </div>

        {isAdmin && (
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" className="h-8">
              <Play className="mr-1.5 h-3.5 w-3.5" /> Scan Now
            </Button>
            <Button variant="outline" size="sm" className="h-8 text-destructive hover:text-destructive">
              <Pause className="mr-1.5 h-3.5 w-3.5" /> Pause
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
