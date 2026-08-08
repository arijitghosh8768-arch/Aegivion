import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Brain, RotateCw, AlertTriangle, CheckCircle, Cpu, RefreshCw } from 'lucide-react';
import { api } from '@/lib/api';

interface AIExplanationPanelProps {
  findingId: string;
  onGenerate?: () => void;
}

export function AIExplanationPanel({ findingId, onGenerate }: AIExplanationPanelProps) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [hasGenerated, setHasGenerated] = useState(false);
  
  // Fetch AI analysis
  const { data: analysis, refetch, error } = useQuery({
    queryKey: ['ai-analysis', findingId],
    queryFn: async () => {
      const response = await api.post(`/v1/ai/explain/${findingId}`, { finding_id: findingId });
      return response.data;
    },
    enabled: false // Only fetch on demand
  });
  
  const handleGenerate = async () => {
    setIsGenerating(true);
    setHasGenerated(true);
    try {
      await refetch();
    } finally {
      setIsGenerating(false);
    }
    if (onGenerate) onGenerate();
  };
  
  // Generating state
  if (isGenerating) {
    return (
      <div className="bg-[#0e1428] border border-blue-900/30 rounded-xl p-6 text-center py-20">
        <RotateCw className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-4" />
        <p className="text-xs text-gray-400">Aegivion AI is calculating security intelligence and remediation guides...</p>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="bg-[#0e1428] border border-red-900/30 rounded-xl p-6 flex gap-3.5 items-start">
        <AlertTriangle className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
        <div>
          <h3 className="font-semibold text-red-400 text-sm">AI Analysis Unavailable</h3>
          <p className="text-xs text-gray-400 mt-1">
            Failed to generate AI analysis. Please verify your AI provider configuration.
          </p>
          <button 
            onClick={handleGenerate}
            className="mt-3 px-3 py-1.5 bg-red-950/20 hover:bg-red-900/20 text-red-400 rounded border border-red-500/20 text-xs transition"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }
  
  // If AI analysis exists
  if (analysis && hasGenerated) {
    return (
      <div className="space-y-6">
        {/* Explanation Card */}
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-gray-800/60 pb-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Brain className="w-5 h-5 text-blue-500" />
              AI Security Intelligence
            </h3>
            <button 
              onClick={handleGenerate}
              className="p-1 text-gray-450 hover:text-white transition flex items-center gap-1 text-[10px]"
            >
              <RefreshCw size={11} />
              Regenerate
            </button>
          </div>
          
          <div className="space-y-4">
            {/* Root Cause */}
            <div>
              <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Root Cause Analysis</h4>
              <p className="mt-1.5 text-xs text-gray-300 leading-relaxed bg-[#0b0f19] border border-gray-850 p-4 rounded-xl">
                {analysis.root_cause || 'Analysis unavailable'}
              </p>
            </div>
            
            {/* Technical Impact */}
            <div>
              <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Technical Fallout</h4>
              <p className="mt-1.5 text-xs text-gray-300 leading-relaxed bg-[#0b0f19] border border-gray-850 p-4 rounded-xl">
                {analysis.technical_impact || 'Analysis unavailable'}
              </p>
            </div>
            
            {/* Business Impact */}
            <div>
              <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Business Fallout</h4>
              <p className="mt-1.5 text-xs text-gray-300 leading-relaxed bg-[#0b0f19] border border-gray-850 p-4 rounded-xl">
                {analysis.business_impact || 'Analysis unavailable'}
              </p>
            </div>

            {/* Recommendations */}
            {analysis.recommendations && analysis.recommendations.length > 0 && (
              <div>
                <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Recommendations</h4>
                <ul className="mt-1.5 list-disc pl-5 text-xs text-gray-300 space-y-1 bg-[#0b0f19] border border-gray-850 p-4 rounded-xl">
                  {analysis.recommendations.map((rec: string, idx: number) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ul>
              </div>
            )}
            
            {/* Confidence info */}
            <div className="flex items-center gap-3 pt-2 border-t border-gray-800 text-[10px] text-gray-500">
              {analysis.confidence && (
                <span className="px-2 py-0.5 border border-blue-900/30 text-blue-400 bg-blue-950/20 font-bold rounded">
                  Confidence: {(analysis.confidence * 100).toFixed(0)}%
                </span>
              )}
              {analysis.processing_time_ms && (
                <span>Generated in {analysis.processing_time_ms}ms</span>
              )}
            </div>
          </div>
        </div>

        {/* Remediation Card */}
        {analysis.remediation && (
          <div className="bg-[#0e1428] border border-green-950/40 rounded-xl p-6 space-y-5">
            <div className="flex items-center justify-between border-b border-green-950/30 pb-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-green-500" />
                Recommended Remediation
              </h3>
              {analysis.remediation.is_safe && (
                <span className="px-2 py-0.5 border border-green-900/30 text-green-400 bg-green-950/20 text-[10px] font-bold rounded">
                  Safety Verified
                </span>
              )}
            </div>

            <div className="space-y-4">
              {analysis.remediation.immediate_action && (
                <div>
                  <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Immediate Action</h4>
                  <p className="mt-1.5 text-xs text-green-300 bg-green-950/10 border border-green-900/20 p-4 rounded-xl leading-relaxed">
                    {analysis.remediation.immediate_action}
                  </p>
                </div>
              )}

              {analysis.remediation.console_guidance && analysis.remediation.console_guidance.length > 0 && (
                <div>
                  <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">AWS Console Steps</h4>
                  <ul className="mt-1.5 list-decimal pl-5 text-xs text-gray-300 space-y-1 bg-[#0b0f19] border border-gray-850 p-4 rounded-xl">
                    {analysis.remediation.console_guidance.map((step: string, idx: number) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>
              )}

              {analysis.remediation.cli_guidance && analysis.remediation.cli_guidance.length > 0 && (
                <div>
                  <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">CLI Commands</h4>
                  <pre className="mt-1.5 p-4 bg-[#0b0f19] border border-gray-850 rounded-xl text-[11px] font-mono text-gray-305 overflow-x-auto text-green-400">
                    {analysis.remediation.cli_guidance.join('\n')}
                  </pre>
                </div>
              )}

              {analysis.remediation.iac_guidance && analysis.remediation.iac_guidance.length > 0 && (
                <div>
                  <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">IaC Configuration (Terraform)</h4>
                  <pre className="mt-1.5 p-4 bg-[#0b0f19] border border-gray-850 rounded-xl text-[11px] font-mono text-gray-305 overflow-x-auto text-blue-400">
                    {analysis.remediation.iac_guidance.join('\n')}
                  </pre>
                </div>
              )}

              {analysis.remediation.validation_steps && analysis.remediation.validation_steps.length > 0 && (
                <div>
                  <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Validation Steps</h4>
                  <ul className="mt-1.5 list-disc pl-5 text-xs text-gray-300 space-y-1 bg-[#0b0f19] border border-gray-850 p-4 rounded-xl">
                    {analysis.remediation.validation_steps.map((step: string, idx: number) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    );
  }
  
  // Initial state - not generated yet
  return (
    <div className="bg-[#0e1428] border border-dashed border-gray-800 rounded-xl p-8 text-center">
      <Brain className="w-12 h-12 text-gray-650 mx-auto mb-3" />
      <h3 className="text-sm font-bold text-white">AI Security Intelligence</h3>
      <p className="text-xs text-gray-500 mt-1.5 max-w-md mx-auto leading-relaxed">
        Generate an evidence-grounded explanation for this finding, including root cause, impacts, and safety-verified remediation.
      </p>
      <button 
        onClick={handleGenerate}
        className="mt-5 px-4 py-2 bg-blue-650 hover:bg-blue-600 text-white text-xs font-semibold rounded-lg transition"
      >
        Generate AI Analysis
      </button>
    </div>
  );
}
