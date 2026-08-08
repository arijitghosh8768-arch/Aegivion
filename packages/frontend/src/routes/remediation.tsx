import React, { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { 
  Zap, 
  RotateCw, 
  AlertTriangle, 
  CheckCircle2, 
  Brain, 
  ChevronRight, 
  Search, 
  SlidersHorizontal,
  FolderDot,
  Lightbulb,
  Clock,
  Terminal,
  BookOpen,
  PlayCircle,
  X
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/remediation',
  component: RemediationCenter,
});

interface Recommendation {
  rank: number;
  control_id: string;
  action_type: string;
  description: string;
  security_impact: string;
  operational_risk: string;
  complexity: string;
  paths_affected: number;
  breaks_path: boolean;
  expected_validation: Record<string, any>;
}

interface ValidationLog {
  remediation_id: string;
  validation_status: string;
  resolved_findings: string[];
  removed_relationships: Array<Record<string, any>>;
  validated_at?: string;
}

interface AIPlan {
  title: string;
  priority: string;
  summary: string;
  immediate_action: string;
  console_steps: string[];
  cli_guidance: string[];
  iac_guidance: string[];
  validation_steps: string[];
  rollback_considerations: string[];
  long_term_prevention: string[];
  uncertainty: string[];
}

function RemediationCenter() {
  const queryClient = useQueryClient();
  const [selectedControlId, setSelectedControlId] = useState<string | null>(null);
  const [complexityFilter, setComplexityFilter] = useState('All');

  // Query breakpoints/remediations
  const { data: recoData, isLoading } = useQuery({
    queryKey: ['path-remediations'],
    queryFn: async () => {
      const res = await api.get('/v1/remediation/attack-paths/PATH-4429/remediations');
      return res.data as { path_id: string, recommendations: Recommendation[] };
    }
  });

  // Query AI implementation playbook plan
  const { data: aiPlan, isLoading: planLoading } = useQuery<AIPlan>({
    queryKey: ['remediation-plan', selectedControlId],
    queryFn: async () => {
      const res = await api.post(`/v1/remediation/remediations/${selectedControlId}/plan`);
      return res.data;
    },
    enabled: !!selectedControlId
  });

  // Query validation log status
  const { data: validationStatus, refetch: refetchValidation } = useQuery<ValidationLog>({
    queryKey: ['remediation-validation-status', selectedControlId],
    queryFn: async () => {
      const res = await api.get(`/v1/remediation/remediations/${selectedControlId}/validation`);
      return res.data;
    },
    enabled: !!selectedControlId
  });

  // Validate control mutation
  const validateMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post(`/v1/remediation/remediations/${selectedControlId}/validate`);
      return res.data;
    },
    onSuccess: () => {
      refetchValidation();
    }
  });

  const recommendations = recoData?.recommendations || [];

  const filteredRecos = recommendations.filter(r => {
    if (complexityFilter !== 'All' && r.complexity.toLowerCase() !== complexityFilter.toLowerCase()) return false;
    return true;
  });

  const activeControl = recommendations.find(r => r.control_id === selectedControlId);

  const getPriorityBadge = (impact: string) => {
    if (impact.toLowerCase() === 'high') return 'bg-red-500/10 text-red-400 border-red-500/20';
    return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
  };

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Zap size={22} className="text-indigo-500" />
            Remediation Intelligence
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Prioritized actions to break active attack paths and validate posture corrections.
          </p>
        </div>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Risky Paths Broken</span>
          <span className="text-2xl font-extrabold text-white mt-2 block">
            {recommendations.reduce((sum, r) => sum + r.paths_affected, 0)} Paths
          </span>
        </div>
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Best Action Impact</span>
          <span className="text-2xl font-extrabold text-green-400 mt-2 block">High</span>
        </div>
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Validation Rescan Status</span>
          <span className="text-2xl font-extrabold text-blue-400 mt-2 block">Ready</span>
        </div>
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Remediation Mode</span>
          <span className="text-2xl font-extrabold text-orange-400 mt-2 block">Read-Only</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Recommendations Queue */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-4 flex items-center justify-between gap-4">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider text-gray-400">Prioritized Action Queue</h3>
            <select
              value={complexityFilter}
              onChange={(e) => setComplexityFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Complexities</option>
              <option value="low">Low Complexity</option>
              <option value="medium">Medium Complexity</option>
            </select>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-20">
              <RotateCw className="w-8 h-8 text-blue-500 animate-spin" />
            </div>
          ) : filteredRecos.length === 0 ? (
            <div className="text-center py-16 text-gray-500 text-xs bg-[#0e1428] border border-gray-850 rounded-xl">
              No recommended controls found.
            </div>
          ) : (
            <div className="space-y-3">
              {filteredRecos.map((reco) => (
                <div 
                  key={reco.control_id}
                  onClick={() => setSelectedControlId(reco.control_id === selectedControlId ? null : reco.control_id)}
                  className={`p-5 border rounded-xl cursor-pointer transition flex flex-col justify-between gap-4 ${
                    selectedControlId === reco.control_id 
                      ? 'bg-blue-600/5 border-blue-500/40' 
                      : 'bg-[#0e1428] border-gray-850 hover:bg-gray-850/20'
                  }`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <h4 className="font-bold text-sm text-white">{reco.description}</h4>
                      <div className="text-[10px] text-gray-550 mt-1 font-mono">
                        Control ID: {reco.control_id} &middot; Affected: {reco.paths_affected} attack paths
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 border text-[9px] font-bold rounded-full uppercase ${getPriorityBadge(reco.security_impact)}`}>
                      {reco.security_impact} IMPACT
                    </span>
                  </div>

                  <div className="flex items-center gap-6 text-[11px] text-gray-500 pt-2 border-t border-gray-800/60">
                    <div>
                      Complexity: <span className="font-semibold text-gray-300 uppercase">{reco.complexity}</span>
                    </div>
                    <div>
                      Risk: <span className="font-semibold text-gray-300 uppercase">{reco.operational_risk}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Execution Drawer & Playground */}
        <div className="lg:col-span-1">
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 min-h-[500px]">
            {activeControl ? (
              <div className="space-y-6 text-xs leading-relaxed">
                
                {/* Header */}
                <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                  <div>
                    <span className="text-[9px] text-gray-500 font-mono block">{activeControl.control_id}</span>
                    <h3 className="font-bold text-white uppercase tracking-wider text-gray-400">Playbook</h3>
                  </div>
                  <button onClick={() => setSelectedControlId(null)} className="text-gray-500 hover:text-white">
                    <X size={14} />
                  </button>
                </div>

                {/* Validation Status */}
                <div className="p-3 bg-[#0b0f19] border border-gray-850 rounded-lg flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-gray-500 block">Verification Status</span>
                    <span className={`font-bold uppercase text-[10px] mt-0.5 block ${
                      validationStatus?.validation_status === 'verified' ? 'text-green-400' : 'text-yellow-500'
                    }`}>
                      {validationStatus?.validation_status || 'PENDING'}
                    </span>
                  </div>
                  <button 
                    onClick={() => validateMutation.mutate()}
                    disabled={validateMutation.isPending}
                    className="px-2.5 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-[10px] font-semibold transition"
                  >
                    {validateMutation.isPending ? 'Checking...' : 'Validate Fix'}
                  </button>
                </div>

                {/* Before/After Visualization */}
                <div className="space-y-2 border-t border-gray-800 pt-4">
                  <span className="text-[10px] font-bold text-white uppercase tracking-wider text-gray-500 block">Edge Path Cut Target</span>
                  <div className="p-3 bg-[#0b0f19] border border-gray-850 rounded-lg font-mono text-[9px] text-gray-400 flex items-center justify-between">
                    <div>
                      <span className="text-orange-400">Internet</span>
                      <span className="text-red-400 mx-2">➔ ✕ ➔</span>
                      <span className="text-gray-300">EC2 Exposure</span>
                    </div>
                  </div>
                </div>

                {/* AI Plan Preview */}
                <div className="border-t border-gray-800 pt-4 space-y-4">
                  <span className="text-[10px] font-bold text-white uppercase tracking-wider text-gray-400 flex items-center gap-1">
                    <Brain size={12} className="text-blue-400" /> Grounded AI Playbook Plan
                  </span>
                  
                  {planLoading ? (
                    <div className="flex items-center gap-2 py-4 text-gray-550">
                      <RotateCw size={12} className="animate-spin" />
                      <span>Generating playbook steps...</span>
                    </div>
                  ) : aiPlan ? (
                    <div className="space-y-4">
                      <div>
                        <span className="font-semibold text-white block">Immediate Action</span>
                        <p className="text-gray-400 text-[11px] mt-0.5">{aiPlan.immediate_action}</p>
                      </div>
                      
                      <div>
                        <span className="font-semibold text-white block flex items-center gap-1"><BookOpen size={10} /> Console Guidance</span>
                        <ol className="list-decimal pl-4 mt-1 space-y-1 text-gray-400 text-[10px]">
                          {aiPlan.console_steps.map((step, idx) => (
                            <li key={idx}>{step}</li>
                          ))}
                        </ol>
                      </div>

                      <div>
                        <span className="font-semibold text-white block flex items-center gap-1"><Terminal size={10} /> CLI Execution Examples</span>
                        <div className="bg-[#0b0f19] p-3 rounded-lg border border-gray-850 font-mono text-[9px] text-indigo-300 mt-1 whitespace-pre-wrap leading-relaxed">
                          {aiPlan.cli_guidance.join('\n')}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <p className="text-gray-500">Remediation steps unavailable.</p>
                  )}
                </div>

              </div>
            ) : (
              <div className="flex flex-col items-center justify-center min-h-[300px] text-center space-y-2">
                <Zap className="text-gray-600 w-8 h-8" />
                <span className="text-xs font-bold text-gray-400">Select Control Rule</span>
                <p className="text-[10px] text-gray-550 max-w-xs leading-normal">
                  Select a recommended control from the prioritized list queue to inspect execution steps, run rescan verifications, and view path cuts.
                </p>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
