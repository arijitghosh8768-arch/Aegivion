import { MitreTechniqueTag } from "./mitre-technique-tag";
import { VulnerabilityBadge } from "./vulnerability-badge";
import { RiskFactorBreakdown } from "./risk-factor-breakdown";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { ShieldAlert, BookOpen, AlertTriangle } from "lucide-react";

interface ThreatContextProps {
  finding: any;
  riskScore: number;
  riskFactors: any[];
  aiExplanation?: {
    summary: string;
    mitre_technique?: string;
    mitre_tactic?: string;
    cve_id?: string;
    cvss_score?: number;
    in_cisa_kev?: boolean;
    root_cause?: string;
  };
}

export function ThreatContextPanel({ finding, riskScore, riskFactors, aiExplanation }: ThreatContextProps) {
  return (
    <Card className="shadow-soft border-border">
      <CardHeader className="bg-muted/30 pb-4 border-b">
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-primary" />
          <CardTitle className="text-lg">Threat Context & Intelligence</CardTitle>
        </div>
        <CardDescription>Correlated threat data and AI risk breakdown</CardDescription>
      </CardHeader>
      
      <CardContent className="p-0">
        <div className="grid lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x border-border">
          {/* Left Column: Intelligence Metadata */}
          <div className="p-6 space-y-6">
            
            {/* MITRE ATT&CK */}
            <div className="space-y-3">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <BookOpen className="h-4 w-4 text-muted-foreground" />
                MITRE ATT&CK Mapping
              </h4>
              {aiExplanation?.mitre_technique || finding?.mitre_technique ? (
                <MitreTechniqueTag 
                  techniqueId={aiExplanation?.mitre_technique || finding?.mitre_technique} 
                  techniqueName={aiExplanation?.mitre_tactic || finding?.mitre_tactic} 
                />
              ) : (
                <p className="text-sm text-muted-foreground">No specific MITRE technique mapped.</p>
              )}
            </div>

            {/* Vulnerability & KEV */}
            <div className="space-y-3">
              <h4 className="text-sm font-semibold flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                Vulnerability Data
              </h4>
              {aiExplanation?.cve_id || finding?.cve_id ? (
                <VulnerabilityBadge 
                  cveId={aiExplanation?.cve_id || finding?.cve_id} 
                  cvssScore={aiExplanation?.cvss_score || finding?.cvss_score} 
                  inCisaKev={aiExplanation?.in_cisa_kev || finding?.in_cisa_kev} 
                />
              ) : (
                <p className="text-sm text-muted-foreground">No specific CVE associated with this finding.</p>
              )}
            </div>
            
            {/* AI Summary */}
            <div className="space-y-2 pt-2">
              <h4 className="text-sm font-semibold">AI Threat Context</h4>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {aiExplanation?.summary || finding?.description || "No explanation available."}
              </p>
            </div>
          </div>
          
          {/* Right Column: Risk Factors */}
          <div className="p-6 bg-muted/10">
            <RiskFactorBreakdown factors={riskFactors} totalScore={riskScore} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

import { ChatPanel } from "../ai/chat-panel";

export function FindingDetailView({ finding, riskScore, riskFactors, aiExplanation }: ThreatContextProps) {
  return (
    <div className="space-y-6">
      <ThreatContextPanel 
        finding={finding} 
        riskScore={riskScore} 
        riskFactors={riskFactors} 
        aiExplanation={aiExplanation} 
      />
      
      <div className="grid lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          {/* Main finding details would go here */}
          <Card className="h-full min-h-[500px] border-border shadow-soft">
            <CardHeader className="border-b bg-muted/20">
              <CardTitle>Finding Details</CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <p className="text-muted-foreground text-sm">Detailed evidence and technical breakdown.</p>
            </CardContent>
          </Card>
        </div>
        
        <div className="lg:col-span-1">
          <ChatPanel findingId={finding?.id} assetId={finding?.asset_id} />
        </div>
      </div>
    </div>
  );
}
