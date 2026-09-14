"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Bot, ShieldAlert, ShieldCheck, Radar, ScanSearch, Boxes, type LucideIcon } from "lucide-react";
import { ACTIVITY_FEED } from "@/lib/data/notifications";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const KIND_ICON: Record<string, { icon: LucideIcon; tint: string }> = {
  ai: { icon: Bot, tint: "bg-brand-purple/10 text-brand-purple" },
  action: { icon: ShieldCheck, tint: "bg-success/10 text-success" },
  detection: { icon: Radar, tint: "bg-warning/10 text-warning" },
  scan: { icon: ScanSearch, tint: "bg-info/10 text-info" },
  discovery: { icon: Boxes, tint: "bg-brand-blue/10 text-brand-blue" },
  alert: { icon: ShieldAlert, tint: "bg-destructive/10 text-destructive" },
};

export function ActivityFeed({ className }: { className?: string }) {
  const [visible, setVisible] = useState(ACTIVITY_FEED.length);

  // simulate live events arriving
  useEffect(() => {
    const id = setInterval(() => {
      setVisible((v) => Math.min(ACTIVITY_FEED.length + 2, v + 1));
    }, 12000);
    return () => clearInterval(id);
  }, []);

  const items = ACTIVITY_FEED.slice(0, visible);

  return (
    <Card className={cn("card-hover", className)}>
      <CardHeader className="flex-row items-center justify-between">
        <div>
          <CardTitle>Live Activity</CardTitle>
          <CardDescription>Automation and detection events</CardDescription>
        </div>
        <span className="relative flex h-2 w-2">
          <span className="absolute h-full w-full animate-ping rounded-full bg-success opacity-60" />
          <span className="relative h-2 w-2 rounded-full bg-success" />
        </span>
      </CardHeader>
      <CardContent className="space-y-1.5">
        {items.map((a, i) => {
          const cfg = KIND_ICON[a.kind] ?? KIND_ICON.ai;
          const Icon = cfg.icon;
          return (
            <motion.div
              key={`${a.id}-${i}`}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-center gap-3 rounded-xl px-2.5 py-2 transition hover:bg-muted/50"
            >
              <span className={cn("flex h-7 w-7 shrink-0 items-center justify-center rounded-lg", cfg.tint)}>
                <Icon className="h-3.5 w-3.5" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="truncate text-[12.5px] font-medium">{a.text}</div>
              </div>
              <span className="shrink-0 text-[10.5px] text-muted-foreground">{a.time}</span>
            </motion.div>
          );
        })}
      </CardContent>
    </Card>
  );
}
