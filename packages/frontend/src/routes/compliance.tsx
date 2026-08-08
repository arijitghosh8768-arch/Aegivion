import React, { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { 
  FileText, 
  CheckCircle2, 
  XCircle, 
  HelpCircle, 
  AlertTriangle,
  RotateCw,
  Brain,
  Info,
  Shield,
  Layers,
  ArrowLeft
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/compliance',
  component: CompliancePage,
});

interface ControlItem {
  control_code: string;
  title: string;
  category: string;
  status: string;
}

interface Framework {
  title: string;
  passed: number;
  failed: number;
  not_assessed: number;
  not_applicable: number;
  percent: number;
  coverage: number;
  total_controls: number;
  items: ControlItem[];
}

interface ComplianceResponse {
  frameworks: Framework[];
  overall: {
    pass_rate: number;
    coverage: number;
    passed: number;
    failed: number;
    not_assessed: number;
    not_applicable: number;
    total_controls: number;
  };
}

interface AIExplanation {
  summary: string;
  why_failed: string;
  security_relevance: string;
  affected_resources: string[];
  evidence_summary: string[];
  recommended_action: string;
  validation: string;
  limitations: string[];
}

function CompliancePage() {
  const [selectedControlCode, setSelectedControlCode] = useState<string | null>(null);

  // Fetch compliance summary
  const { data, isLoading, isError, refetch } = useQuery<ComplianceResponse>({
    queryKey: ['compliance-summary'],
    queryFn: async () => {
      const res = await api.get('/v1/compliance/summary');
      return res.data;
    }
  });

  // Fetch AI explanation for selected control
  const { data: aiExplanation, isLoading: explainLoading } = useQuery<AIExplanation>({
    queryKey: ['control-explanation', selectedControlCode],
    queryFn: async () => {
      const res = await api.post(`/v1/compliance/controls/${selectedControlCode}/explain`);
      return res.data;
    },
    enabled: !!selectedControlCode
  });

  const getStatusIcon = (status: string) => {
    switch (status.toUpperCase()) {
      case 'PASS':
        return <CheckCircle2 className="text-green-500 shrink-0 w-4 h-4" />;
      case 'FAIL':
        return <XCircle className="text-red-500 shrink-0 w-4 h-4" />;
      case 'NOT_ASSESSED':
        return <HelpCircle className="text-yellow-500 shrink-0 w-4 h-4" />;
      default:
        return <Info className="text-gray-400 shrink-0 w-4 h-4" />;
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status.toUpperCase()) {
      case 'PASS':
        return 'bg-green-500/10 text-green-400 border-green-500/20';
      case 'FAIL':
        return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'NOT_ASSESSED':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      default:
        return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <RotateCw className="w-8 h-8 text-indigo-500 animate-spin" />
      </div>
    );
  }

  if (isError || !data) {
    return (
      <div className="p-6 text-center text-red-400 bg-red-950/10 border border-red-900/20 rounded-xl">
        Failed to load compliance intelligence data. Please check connection to local API server.
      </div>
    );
  }

  const activeFramework = data.frameworks[0];

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Shield size={22} className="text-indigo-500" />
            Compliance Intelligence
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Automated configuration mapping for security frameworks.
          </p>
        </div>
        <button 
          onClick={() => refetch()}
          className="px-4 py-2 bg-indigo-600/10 border border-indigo-500/20 text-indigo-400 hover:text-white hover:bg-indigo-600 rounded-lg text-xs font-semibold transition flex items-center gap-1.5"
        >
          <RotateCw size={14} />
          Sync Compliance
        </button>
      </div>

      {/* Scope Warning Alert */}
      <div className="p-4 bg-yellow-950/20 border border-yellow-900/30 rounded-xl flex items-start gap-3">
        <AlertTriangle className="text-yellow-500 shrink-0 w-5 h-5" />
        <div>
          <h4 className="text-xs font-bold text-yellow-400">Technical Control Scope Warning</h4>
          <p className="text-[11px] text-gray-450 mt-0.5">
            Aegivion provides technical security posture assessments only. It does not certify official framework compliance or constitute a certified audit opinion.
          </p>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Passed controls</span>
          <span className="text-2xl font-extrabold text-green-400 mt-2 block">{data.overall.passed}</span>
        </div>
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Failed Checks</span>
          <span className="text-2xl font-extrabold text-red-400 mt-2 block">{data.overall.failed}</span>
        </div>
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Assessment Coverage</span>
          <span className="text-2xl font-extrabold text-indigo-400 mt-2 block">{data.overall.coverage}%</span>
        </div>
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Technical Pass Rate</span>
          <span className="text-2xl font-extrabold text-white mt-2 block">{data.overall.pass_rate}%</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Framework controls list */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-4 flex items-center justify-between">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider text-gray-400">
              {activeFramework.title} &middot; {activeFramework.total_controls} Controls Checked
            </h3>
            <span className="text-[10px] text-gray-550 font-semibold font-mono">v3.0.0</span>
          </div>

          <div className="space-y-2">
            {activeFramework.items.map((control) => (
              <div
                key={control.control_code}
                onClick={() => setSelectedControlCode(control.control_code === selectedControlCode ? null : control.control_code)}
                className={`p-4 border rounded-xl cursor-pointer transition flex items-center justify-between gap-4 ${
                  selectedControlCode === control.control_code 
                    ? 'bg-indigo-600/5 border-indigo-500/40' 
                    : 'bg-[#0e1428] border-gray-850 hover:bg-gray-850/20'
                }`}
              >
                <div className="flex items-center gap-3">
                  {getStatusIcon(control.status)}
                  <div>
                    <h4 className="font-semibold text-xs text-white">{control.title}</h4>
                    <span className="text-[10px] text-gray-500 block mt-0.5">
                      Category: {control.category} &middot; Code: {control.control_code}
                    </span>
                  </div>
                </div>
                <span className={`px-2 py-0.5 border text-[9px] font-bold rounded uppercase ${getStatusBadgeClass(control.status)}`}>
                  {control.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: AI Explanation Panel */}
        <div className="lg:col-span-1">
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 min-h-[450px]">
            {selectedControlCode ? (
              <div className="space-y-5 text-xs leading-relaxed">
                
                {/* Header */}
                <div className="flex items-start justify-between border-b border-gray-850 pb-3">
                  <div>
                    <span className="text-[9px] text-gray-500 font-mono block">Control Check</span>
                    <h3 className="font-bold text-white uppercase tracking-wider text-gray-400 mt-0.5">Control {selectedControlCode}</h3>
                  </div>
                  <button 
                    onClick={() => setSelectedControlCode(null)}
                    className="text-gray-550 hover:text-white text-xs font-semibold flex items-center gap-1"
                  >
                    <ArrowLeft size={12} /> Back
                  </button>
                </div>

                {explainLoading ? (
                  <div className="flex flex-col items-center justify-center py-20 text-gray-500 gap-2">
                    <RotateCw size={20} className="animate-spin text-indigo-500" />
                    <span>Analyzing check evidence...</span>
                  </div>
                ) : aiExplanation ? (
                  <div className="space-y-4">
                    
                    <div>
                      <span className="font-semibold text-white block">Summary</span>
                      <p className="text-gray-400 text-[11px] mt-0.5">{aiExplanation.summary}</p>
                    </div>

                    <div>
                      <span className="font-semibold text-white block">Why It Failed / Current Posture</span>
                      <p className="text-gray-400 text-[11px] mt-0.5">{aiExplanation.why_failed}</p>
                    </div>

                    <div>
                      <span className="font-semibold text-white block">Security Relevance</span>
                      <p className="text-gray-400 text-[11px] mt-0.5">{aiExplanation.security_relevance}</p>
                    </div>

                    <div>
                      <span className="font-semibold text-white block">Observed Evidence Summary</span>
                      <ul className="list-disc pl-4 mt-1 space-y-1 text-gray-400 text-[10px]">
                        {aiExplanation.evidence_summary.map((ev, idx) => (
                          <li key={idx}>{ev}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="p-3 bg-[#0b0f19] border border-gray-850 rounded-lg space-y-2">
                      <span className="font-semibold text-white block flex items-center gap-1">
                        <Brain size={12} className="text-indigo-400" /> Recommended Action
                      </span>
                      <p className="text-gray-300 text-[10px]">{aiExplanation.recommended_action}</p>
                    </div>

                    <div className="p-3 bg-red-950/10 border border-red-900/20 rounded-lg">
                      <span className="font-semibold text-red-400 block">Assessment Limitations</span>
                      <ul className="list-disc pl-4 mt-1 space-y-0.5 text-gray-400 text-[9px]">
                        {aiExplanation.limitations.map((lim, idx) => (
                          <li key={idx}>{lim}</li>
                        ))}
                      </ul>
                    </div>

                  </div>
                ) : (
                  <p className="text-gray-550 text-center py-10">Compliance analysis details unavailable.</p>
                )}

              </div>
            ) : (
              <div className="flex flex-col items-center justify-center min-h-[350px] text-center space-y-2.5">
                <Layers className="text-gray-600 w-8 h-8" />
                <span className="text-xs font-bold text-gray-400">Select Compliance Check</span>
                <p className="text-[10px] text-gray-550 max-w-xs leading-normal">
                  Select any control from the CIS AWS Benchmark list to inspect observed evidence, read grounded AI posture reasoning, and view recommended actions.
                </p>
              </div>
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
export default CompliancePage;
