import { Badge } from "@/components/ui/badge";
import { ExternalLink } from "lucide-react";

interface MitreTechniqueTagProps {
  techniqueId: string;
  techniqueName?: string;
}

export function MitreTechniqueTag({ techniqueId, techniqueName }: MitreTechniqueTagProps) {
  const url = `https://attack.mitre.org/techniques/${techniqueId}`;
  
  return (
    <a href={url} target="_blank" rel="noreferrer noopener" className="inline-block transition-opacity hover:opacity-80">
      <Badge variant="outline" className="border-indigo-200 bg-indigo-50 text-indigo-800 dark:border-indigo-800 dark:bg-indigo-950 dark:text-indigo-300 font-mono text-xs gap-1">
        {techniqueId} {techniqueName && `- ${techniqueName}`}
        <ExternalLink className="h-3 w-3" />
      </Badge>
    </a>
  );
}
