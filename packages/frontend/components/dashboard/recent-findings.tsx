"use client";

import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { FINDINGS } from "@/lib/data/findings";
import { SeverityBadge } from "@/components/shared/severity";
import { ProviderMark } from "@/components/shared/provider-mark";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function RecentFindings({ className }: { className?: string }) {
  const items = FINDINGS.filter((f) => f.status === "open" || f.status === "remediating").slice(0, 5);
  return (
    <Card className={cn("card-hover", className)}>
      <CardHeader className="flex-row items-center justify-between">
        <div>
          <CardTitle>Priority Findings</CardTitle>
          <CardDescription>Highest risk, ordered by severity</CardDescription>
        </div>
        <Link href="/detection-engine" className="flex items-center gap-1 text-xs font-semibold text-primary hover:underline">
          View all <ArrowRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent className="space-y-1.5">
        {items.map((f) => (
          <Link
            key={f.id}
            href="/remediation"
            className="flex items-center gap-3 rounded-xl border border-transparent px-2.5 py-2.5 transition hover:border-border hover:bg-muted/50"
          >
            <ProviderMark provider={f.provider} size={28} />
            <div className="min-w-0 flex-1">
              <div className="truncate text-[12.5px] font-semibold">{f.title}</div>
              <div className="text-xs text-muted-foreground">
                {f.service} · {f.framework ?? f.category}
              </div>
            </div>
            <SeverityBadge severity={f.severity} />
          </Link>
        ))}
      </CardContent>
    </Card>
  );
}
