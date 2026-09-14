import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Info, ShieldAlert, Eye, EyeOff, Search } from "lucide-react";
import { cn } from "@/lib/utils";

interface GroundedMessageProps {
  content: string;
  observed?: string[];
  inferred?: string[];
  unknown?: string[];
  declined?: boolean;
}

export function GroundedMessage({ content, observed = [], inferred = [], unknown = [], declined = false }: GroundedMessageProps) {
  if (declined) {
    return (
      <Card className="p-4 border-dashed border-muted-foreground/30 bg-muted/20">
        <div className="flex gap-3">
          <ShieldAlert className="h-5 w-5 text-muted-foreground shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="font-semibold text-sm">Insufficient Evidence</h4>
            <p className="text-sm text-muted-foreground leading-relaxed">{content}</p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {content && (
        <div className="text-sm leading-relaxed whitespace-pre-wrap">
          {content}
        </div>
      )}
      
      {(observed.length > 0 || inferred.length > 0 || unknown.length > 0) && (
        <Card className="overflow-hidden border-border bg-card shadow-soft">
          <div className="divide-y divide-border">
            {/* Observed */}
            {observed.length > 0 && (
              <div className="p-3 bg-muted/10">
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant="outline" className="text-[10px] font-mono tracking-wide text-foreground gap-1 border-foreground/20">
                    <Eye className="h-3 w-3" /> OBSERVED
                  </Badge>
                  <span className="text-[10px] text-muted-foreground">Factual evidence</span>
                </div>
                <ul className="space-y-1.5 pl-5 list-disc text-xs text-foreground/90">
                  {observed.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
            
            {/* Inferred */}
            {inferred.length > 0 && (
              <div className="p-3 bg-warning/5">
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant="outline" className="text-[10px] font-mono tracking-wide text-warning gap-1 border-warning/30 bg-warning/10">
                    <Search className="h-3 w-3" /> INFERRED
                  </Badge>
                  <span className="text-[10px] text-muted-foreground">Derived implications</span>
                </div>
                <ul className="space-y-1.5 pl-5 list-disc text-xs text-warning/90">
                  {inferred.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
            
            {/* Unknown */}
            {unknown.length > 0 && (
              <div className="p-3 bg-muted/50">
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant="outline" className="text-[10px] font-mono tracking-wide text-muted-foreground gap-1 border-muted-foreground/30">
                    <EyeOff className="h-3 w-3" /> UNKNOWN
                  </Badge>
                  <span className="text-[10px] text-muted-foreground">Outside current context</span>
                </div>
                <ul className="space-y-1.5 pl-5 list-disc text-xs text-muted-foreground">
                  {unknown.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}
