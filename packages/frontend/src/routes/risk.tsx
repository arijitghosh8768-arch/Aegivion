import React, { useState } from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { 
  Shield, 
  RotateCw, 
  AlertTriangle, 
  ShieldAlert, 
  Cpu, 
  CheckCircle2, 
  ChevronRight, 
  Activity, 
  Database,
  Users
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/risk',
  component: RiskIntelligencePage,
});

interface RiskFactor {
  type: str;
  value: any;
  contribution: number;
  description: string;
  evidence: string[];
}

interface AssetRisk {
  id: string;
  name: string;
  type: string;
  environment: string;
  exposure: string;
  risk_score: number;
  confidence: number;
  risk_factors: RiskFactor[];
  ai_insight: string;
}

interface CorrelationSummary {
  id: string;
  title: string;
  asset_count: number;
  finding_count: number;
  risk_score: number;
}

interface RiskTelemetry {
  environment: string;
  last_assessed: string;
  overall_risk: {
    score: number;
    level: string;
    confidence: number;
    factors: RiskFactor[];
    calculated_at: string;
    engine_version: string;
  };
  critical_count: number;
  high_count: number;
  correlation_count: number;
  asset_count: number;
  risk_factors: { type: string; label: string; percentage: number }[];
  top_correlations: CorrelationSummary[];
  top_risky_assets: AssetRisk[];
}

function RiskIntelligencePage() {
  const [selectedAsset, setSelectedAsset] = useState<AssetRisk | null>(null);
  const [showExplainDrawer, setShowExplainDrawer] = useState(false);

  const { data: riskData, isLoading, refetch, isRefetching } = useQuery<RiskTelemetry>({
    queryKey: ['risk-intelligence'],
    queryFn: async () => {
      const response = await api.get('/v1/risk/intelligence');
      return response.data;
    },
    refetchInterval: 60000
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <RotateCw className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  const getRiskColor = (score: number) => {
    if (score >= 90) return 'text-red-500 bg-red-500/10 border-red-500/20';
    if (score >= 70) return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
    if (score >= 50) return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
    return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
  };

  const getRiskProgressColor = (score: number) => {
    if (score >= 90) return 'bg-red-500';
    if (score >= 70) return 'bg-orange-500';
    if (score >= 50) return 'bg-yellow-500';
    return 'bg-blue-500';
  };

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-gray-800 pb-6">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Shield size={22} className="text-blue-500 fill-blue-500/10" />
            Risk Intelligence
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            {riskData?.environment || 'AWS Production'} · Last assessed: {riskData?.last_assessed}
          </p>
        </div>
        <button 
          onClick={() => refetch()}
          disabled={isRefetching}
          className="px-4 py-2 bg-blue-600/10 border border-blue-500/20 text-blue-400 hover:text-white hover:bg-blue-600 rounded-lg text-xs font-semibold transition flex items-center gap-1.5"
        >
          {isRefetching ? <RotateCw size={14} className="animate-spin" /> : <RotateCw size={14} />}
          Recalculate Risk
        </button>
      </div>

      {/* Overall Score Card */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Overall Risk Assessment</span>
            <div className="flex items-baseline gap-3">
              <span className="text-5xl font-black text-white tracking-tight">
                {riskData?.overall_risk?.score || 0}<span className="text-sm font-normal text-gray-500">/100</span>
              </span>
              <span className={`px-2.5 py-0.5 border text-xs font-bold rounded-full capitalize ${getRiskColor(riskData?.overall_risk?.score || 0)}`}>
                {riskData?.overall_risk?.level || 'low'}
              </span>
            </div>
            <div className="flex items-center gap-4 text-[10px] text-gray-500 pt-1">
              <span>Confidence: {((riskData?.overall_risk?.confidence || 0.9) * 100).toFixed(0)}%</span>
              <span>•</span>
              <span>Engine: {riskData?.overall_risk?.engine_version || '2.0.0'}</span>
            </div>
          </div>
          
          <button 
            onClick={() => {
              setSelectedAsset(null);
              setShowExplainDrawer(true);
            }}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition"
          >
            Explain Score
          </button>
        </div>

        {/* Progress Bar */}
        <div className="mt-6 w-full bg-gray-800 h-2.5 rounded-full overflow-hidden">
          <div 
            className={`h-full rounded-full transition-all duration-500 ${getRiskProgressColor(riskData?.overall_risk?.score || 0)}`}
            style={{ width: `${riskData?.overall_risk?.score || 0}%` }}
          />
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-[#0e1428] border border-red-950/40 rounded-xl p-5">
          <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Critical Threats</span>
          <span className="block text-2xl font-bold text-red-400 mt-1">{riskData?.critical_count || 0}</span>
        </div>
        <div className="bg-[#0e1428] border border-orange-950/40 rounded-xl p-5">
          <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">High Threats</span>
          <span className="block text-2xl font-bold text-orange-400 mt-1">{riskData?.high_count || 0}</span>
        </div>
        <div className="bg-[#0e1428] border border-blue-950/40 rounded-xl p-5">
          <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Active Correlations</span>
          <span className="block text-2xl font-bold text-blue-400 mt-1">{riskData?.correlation_count || 0}</span>
        </div>
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5">
          <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Total Assets</span>
          <span className="block text-2xl font-bold text-gray-300 mt-1">{riskData?.asset_count || 0}</span>
        </div>
      </div>

      {/* Two Column Layout: Risk Factors & Top Correlations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Factors Breakdown */}
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
            <Activity size={16} className="text-blue-400" />
            Risk Factor Contribution
          </h3>
          <div className="space-y-4 pt-2">
            {riskData?.risk_factors?.map((factor) => (
              <div key={factor.type} className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <span className="text-gray-400">{factor.label}</span>
                  <span className="font-semibold text-white">{factor.percentage}%</span>
                </div>
                <div className="w-full bg-gray-800 h-2 rounded-full overflow-hidden">
                  <div 
                    className="bg-blue-500 h-full rounded-full"
                    style={{ width: `${factor.percentage}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Correlations */}
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
            <ShieldAlert size={16} className="text-red-400" />
            Critical Threat Correlations
          </h3>
          <div className="space-y-2.5 pt-2">
            {riskData?.top_correlations?.map((corr) => (
              <div key={corr.id} className="p-3.5 bg-[#0b0f19] border border-gray-850 rounded-xl flex items-start justify-between gap-3">
                <div>
                  <h4 className="font-bold text-xs text-white leading-snug">{corr.title}</h4>
                  <span className="text-[10px] text-gray-500 mt-1 block">
                    {corr.asset_count} assets · {corr.finding_count} findings
                  </span>
                </div>
                <span className={`px-2.5 py-0.5 border text-[10px] font-bold rounded-full ${getRiskColor(corr.risk_score)}`}>
                  {corr.risk_score}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Risky Assets */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-gray-800 bg-[#0d1326]">
          <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
            <Database size={16} className="text-gray-400" />
            Top Risky Assets
          </h3>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-500 font-semibold bg-[#0b0f19]/30">
                <th className="py-3 px-4">Asset</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Environment</th>
                <th className="py-3 px-4">Exposure</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {riskData?.top_risky_assets?.map((asset) => (
                <tr key={asset.id} className="hover:bg-gray-800/10 transition">
                  <td className="py-3.5 px-4">
                    <div className="font-bold text-white leading-snug">{asset.name}</div>
                    <div className="text-[10px] text-gray-500 mt-0.5 font-mono">{asset.id}</div>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-gray-400">{asset.type}</td>
                  <td className="py-3.5 px-4 capitalize">{asset.environment}</td>
                  <td className="py-3.5 px-4 capitalize">{asset.exposure.replace('_', ' ')}</td>
                  <td className="py-3.5 px-4">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white">{asset.risk_score}</span>
                      <div className="w-16 bg-gray-800 h-1.5 rounded-full overflow-hidden">
                        <div 
                          className={`h-full rounded-full ${getRiskProgressColor(asset.risk_score)}`}
                          style={{ width: `${asset.risk_score}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    <button 
                      onClick={() => {
                        setSelectedAsset(asset);
                        setShowExplainDrawer(true);
                      }}
                      className="px-2.5 py-1.5 bg-blue-600/10 border border-blue-500/20 text-blue-400 hover:text-white rounded hover:bg-blue-600 text-[10px] font-semibold transition"
                    >
                      Explain
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Drawer */}
      {showExplainDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-all">
          <div className="w-full max-w-lg bg-[#0d1326] border-l border-gray-800 h-full flex flex-col justify-between shadow-2xl relative">
            
            {/* Header */}
            <div className="p-6 border-b border-gray-800 flex items-center justify-between">
              <div>
                <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider">Score Breakdown</span>
                <h2 className="text-sm font-bold text-white mt-1 leading-snug">
                  {selectedAsset ? `Risk Factor Analysis: ${selectedAsset.name}` : "Overall Platform Score"}
                </h2>
              </div>
              <button 
                onClick={() => setShowExplainDrawer(false)}
                className="text-gray-500 hover:text-white transition text-xs"
              >
                Close
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
              <div className="flex items-baseline gap-3">
                <span className="text-4xl font-black text-white">
                  {selectedAsset ? selectedAsset.risk_score : (riskData?.overall_risk?.score || 0)}
                </span>
                <span className={`px-2.5 py-0.5 border text-[10px] font-bold rounded-full capitalize ${getRiskColor(selectedAsset ? selectedAsset.risk_score : (riskData?.overall_risk?.score || 0))}`}>
                  {selectedAsset ? getRiskLevel(selectedAsset.risk_score) : (riskData?.overall_risk?.level || 'low')}
                </span>
              </div>

              {/* Factors */}
              <div className="space-y-3">
                <h3 className="text-xs font-bold text-white">Triggered Modifiers</h3>
                <div className="space-y-2">
                  {(selectedAsset ? selectedAsset.risk_factors : (riskData?.overall_risk?.factors || [])).map((factor, idx) => (
                    <div key={idx} className="p-3.5 bg-[#0b0f19] border border-gray-850 rounded-xl flex items-center justify-between gap-4">
                      <div className="space-y-1">
                        <span className="font-bold text-white block capitalize">{factor.type.replace('_', ' ')}</span>
                        <p className="text-[11px] text-gray-400">{factor.description}</p>
                        {factor.evidence && factor.evidence.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {factor.evidence.map((ev, eIdx) => (
                              <span key={eIdx} className="px-1.5 py-0.5 bg-gray-800 text-gray-500 rounded text-[9px] font-mono">
                                {ev}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                      <span className="font-black text-sm shrink-0 text-blue-400">+{factor.contribution}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* AI insight */}
              {selectedAsset && selectedAsset.ai_insight && (
                <div className="space-y-2">
                  <h3 className="text-xs font-bold text-white flex items-center gap-1.5">
                    <Brain size={14} className="text-blue-400" />
                    AI Security Grounding Analysis
                  </h3>
                  <p className="text-gray-300 leading-relaxed bg-[#0b0f19] border border-gray-850 p-4 rounded-xl">
                    {selectedAsset.ai_insight}
                  </p>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-6 border-t border-gray-800/80 bg-[#0b0f19] flex justify-end">
              <button 
                onClick={() => setShowExplainDrawer(false)}
                className="px-4 py-2 border border-gray-850 hover:bg-gray-800 text-gray-300 hover:text-white rounded-lg text-xs font-semibold transition"
              >
                Done
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}

function getRiskLevel(score: number): string {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 50) return 'medium';
  return 'low';
}
export default RiskIntelligencePage;
