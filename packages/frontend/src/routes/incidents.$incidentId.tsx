import React, { useState, useEffect } from 'react';
import { createRoute, Link, useParams } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  ArrowLeft, 
  ShieldAlert, 
  RotateCw, 
  AlertTriangle,
  Info,
  Clock,
  CheckCircle,
  Brain,
  SlidersHorizontal,
  ChevronRight,
  Database,
  FileText
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/incidents/$incidentId',
  component: IncidentDetailPage,
});

interface Note {
  id: string;
  author: string;
  content: string;
  created_at: string;
}

interface TimelineEvent {
  timestamp: string;
  title: string;
  description: string;
}

interface IncidentDetail {
  incident_id: string;
  id: string;
  title: string;
  description: string;
  severity: string;
  risk_score: number;
  confidence: number;
  status: string;
  finding_ids: string[];
  asset_ids: string[];
  evidence: Record<string, any>;
  timeline: TimelineEvent[];
  notes: Note[];
  account_id: string;
  region: string;
  updated_at: string;
}

interface AIAnalysis {
  summary: string;
  why_related: string[];
  potential_scenario: string;
  technical_impact: string;
  evidence_summary: Array<{ statement: string, evidence_refs: string[] }>;
  uncertainty: string[];
  confidence: number;
}

function IncidentDetailPage() {
  const { incidentId } = useParams({ from: Route.id });
  const queryClient = useQueryClient();
  const [selectedTab, setSelectedTab] = useState<'overview' | 'findings' | 'assets' | 'ai'>('overview');

  // Query incident detail
  const { data: incident, isLoading, isError, refetch } = useQuery<IncidentDetail>({
    queryKey: ['incident', incidentId],
    queryFn: async () => {
      const res = await api.get(`/v1/incidents/${incidentId}`);
      return res.data;
    }
  });

  // Query AI reasoning analysis
  const { data: aiAnalysis, isLoading: aiLoading, refetch: runAIAnalysis } = useQuery<AIAnalysis>({
    queryKey: ['incident-ai', incidentId],
    queryFn: async () => {
      const res = await api.post(`/v1/incidents/${incidentId}/analyze`);
      return res.data;
    },
    enabled: !!incident
  });

  // Patch status mutation
  const updateStatusMutation = useMutation({
    mutationFn: async (status: string) => {
      const res = await api.patch(`/v1/incidents/${incidentId}/status`, { status });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident', incidentId] });
      refetch();
    }
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <RotateCw className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  if (isError || !incident) {
    return (
      <div className="text-center py-20 text-red-400 bg-red-950/10 border border-red-900/20 rounded-xl max-w-md mx-auto mt-10">
        <AlertTriangle className="mx-auto w-8 h-8 mb-3" />
        Failed to locate incident details or access is forbidden.
      </div>
    );
  }

  const getSeverityBadge = (severity: string) => {
    const sev = severity.toLowerCase();
    if (sev === 'critical') return 'bg-red-500/10 text-red-400 border-red-500/20';
    if (sev === 'high') return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
  };

  const statusOptions = [
    { value: 'open', label: 'Open' },
    { value: 'investigating', label: 'Investigating' },
    { value: 'mitigated', label: 'Mitigated' },
    { value: 'resolved', label: 'Resolved' },
    { value: 'closed', label: 'Closed' }
  ];

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      {/* Back button */}
      <div>
        <Link to="/incidents" className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-white transition">
          <ArrowLeft size={14} /> Back to Incidents
        </Link>
      </div>

      {/* Header card */}
      <div className="bg-[#0e1428] border border-gray-850 p-6 rounded-xl space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-2">
            <span className="text-[10px] text-gray-500 font-bold uppercase tracking-wider font-mono block">
              {incident.incident_id}
            </span>
            <h1 className="text-xl font-bold text-white tracking-tight leading-snug">{incident.title}</h1>
            <div className="flex flex-wrap items-center gap-3 pt-1">
              <span className={`px-2.5 py-0.5 border text-[9px] font-bold rounded-full uppercase ${getSeverityBadge(incident.severity)}`}>
                {incident.severity}
              </span>
              <span className="text-xs text-gray-500">
                Score: <span className="font-bold text-red-400">{incident.risk_score}/100</span>
              </span>
              <span className="text-xs text-gray-500">
                Confidence: <span className="font-semibold text-gray-300">{(incident.confidence * 100).toFixed(0)}%</span>
              </span>
            </div>
          </div>

          {/* Lifecycle control */}
          <div className="flex items-center gap-2 bg-[#0b0f19] p-2 border border-gray-800 rounded-lg">
            <span className="text-[10px] text-gray-500 uppercase tracking-wider font-bold pl-1.5">Status</span>
            <select
              value={incident.status}
              onChange={(e) => updateStatusMutation.mutate(e.target.value)}
              className="px-2.5 py-1 bg-[#0d1326] border border-gray-850 rounded text-xs text-gray-300 focus:outline-none focus:border-blue-500"
            >
              {statusOptions.map(opt => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-gray-800/60 text-xs">
          <div>
            <span className="text-gray-500 block">Cloud Account</span>
            <span className="text-white font-semibold block pt-0.5 uppercase">{incident.account_id || 'AWS Production'}</span>
          </div>
          <div>
            <span className="text-gray-500 block">Region</span>
            <span className="text-white font-semibold block pt-0.5">{incident.region || 'ap-south-1'}</span>
          </div>
          <div>
            <span className="text-gray-500 block">Correlated Indicators</span>
            <span className="text-white font-semibold block pt-0.5">{incident.finding_ids.length} Findings</span>
          </div>
          <div>
            <span className="text-gray-500 block">Last Assessment</span>
            <span className="text-white font-semibold block pt-0.5">
              {new Date(incident.updated_at).toLocaleDateString()}
            </span>
          </div>
        </div>
      </div>

      {/* Warning of partial scan coverage */}
      <div className="p-4 bg-yellow-950/20 border border-yellow-900/30 rounded-xl flex items-start gap-3">
        <AlertTriangle className="text-yellow-500 shrink-0 w-4 h-4 mt-0.5" />
        <div>
          <h4 className="text-[11px] font-bold text-yellow-400">Incomplete Assessment Coverage</h4>
          <p className="text-[10px] text-gray-400 mt-0.5">
            Scan metadata reveals missing context headers. Advanced relationships could be missing.
          </p>
        </div>
      </div>

      {/* Main split details layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Tabs and Evidence */}
        <div className="lg:col-span-2 space-y-6">
          <div className="flex border-b border-gray-800">
            {(['overview', 'findings', 'assets', 'ai'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setSelectedTab(tab)}
                className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition ${
                  selectedTab === tab 
                    ? 'border-blue-500 text-white' 
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                {tab === 'ai' ? 'AI Incident Intelligence' : tab}
              </button>
            ))}
          </div>

          <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6">
            
            {selectedTab === 'overview' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-xs font-bold text-white mb-2 uppercase tracking-wider text-gray-400">Description</h3>
                  <p className="text-xs text-gray-300 leading-relaxed">{incident.description}</p>
                </div>

                <div className="border-t border-gray-800 pt-6 space-y-4">
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider text-gray-400">Deterministic Evidence</h3>
                  <div className="space-y-2.5">
                    <div className="flex items-start gap-2.5 text-xs text-gray-300">
                      <CheckCircle className="text-green-500 shrink-0 mt-0.5" size={14} />
                      <div>
                        <span className="font-semibold text-white">Workload Exposure Check</span>
                        <p className="text-[10px] text-gray-450 mt-0.5">VPC and public gateways routing detected towards the public IPv4 asset.</p>
                      </div>
                    </div>
                    <div className="flex items-start gap-2.5 text-xs text-gray-300">
                      <CheckCircle className="text-green-500 shrink-0 mt-0.5" size={14} />
                      <div>
                        <span className="font-semibold text-white">Ingress Port Validation</span>
                        <p className="text-[10px] text-gray-450 mt-0.5">Open SSH rules configured pointing towards the Internet (0.0.0.0/0).</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {selectedTab === 'findings' && (
              <div className="space-y-4">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider text-gray-400">Correlated Findings</h3>
                <div className="space-y-3">
                  {incident.finding_ids.map((fid) => (
                    <div key={fid} className="p-4 bg-[#0b0f19] border border-gray-850 rounded-lg flex items-center justify-between">
                      <div>
                        <div className="font-bold text-xs text-white">Finding ID: {fid}</div>
                        <p className="text-[11px] text-gray-450 mt-1">Rule correlation matched.</p>
                      </div>
                      <Link to={`/findings/${fid}` as any} className="text-[10px] text-blue-400 hover:underline flex items-center gap-1">
                        View Detail <ChevronRight size={12} />
                      </Link>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedTab === 'assets' && (
              <div className="space-y-4">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider text-gray-400">Affected Resources</h3>
                <div className="space-y-3">
                  {incident.asset_ids.map((aid) => (
                    <div key={aid} className="p-4 bg-[#0b0f19] border border-gray-850 rounded-lg flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="p-1.5 bg-blue-950/20 border border-blue-900/30 rounded text-blue-400">
                          <Database size={14} />
                        </div>
                        <div>
                          <div className="font-bold text-xs text-white truncate max-w-xs">{aid}</div>
                          <span className="text-[9px] text-gray-500 font-mono">Resource Node</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedTab === 'ai' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider text-gray-400 flex items-center gap-1.5">
                    <Brain size={14} className="text-blue-400" />
                    AI Reasoning Explainability
                  </h3>
                  <button 
                    onClick={() => runAIAnalysis()}
                    className="p-1 text-gray-400 hover:text-white transition flex items-center gap-1 text-[10px]"
                  >
                    <RotateCw size={10} className={aiLoading ? 'animate-spin' : ''} />
                    Rerun Reasoning
                  </button>
                </div>

                {aiLoading ? (
                  <div className="flex flex-col items-center justify-center py-12 space-y-3">
                    <RotateCw className="w-6 h-6 text-blue-500 animate-spin" />
                    <span className="text-[10px] text-gray-500">Generating contextual graph analysis...</span>
                  </div>
                ) : aiAnalysis ? (
                  <div className="space-y-6 text-xs leading-relaxed">
                    <div>
                      <h4 className="font-bold text-white text-[11px] uppercase tracking-wider text-gray-500 mb-1">Executive Summary</h4>
                      <p className="text-gray-300">{aiAnalysis.summary}</p>
                    </div>
                    
                    <div className="border-t border-gray-800 pt-4">
                      <h4 className="font-bold text-white text-[11px] uppercase tracking-wider text-gray-500 mb-1">Potential Attack Path Scenario</h4>
                      <p className="text-gray-300 font-medium">{aiAnalysis.potential_scenario}</p>
                    </div>

                    <div className="border-t border-gray-800 pt-4">
                      <h4 className="font-bold text-white text-[11px] uppercase tracking-wider text-gray-500 mb-1">Technical Impact</h4>
                      <p className="text-gray-300">{aiAnalysis.technical_impact}</p>
                    </div>

                    <div className="border-t border-gray-800 pt-4 bg-[#ef4444]/5 p-4 border-l-2 border-[#ef4444] rounded-r-xl">
                      <h4 className="font-bold text-red-400 text-[11px] uppercase tracking-wider mb-1">Uncertainties & Missing Telemetry</h4>
                      <ul className="list-disc pl-4 space-y-1 text-gray-400">
                        {aiAnalysis.uncertainty.map((un, idx) => (
                          <li key={idx}>{un}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-10">
                    <p className="text-xs text-gray-500">AI security analysis pending. Run the reasoning helper.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Timeline & Recommendations */}
        <div className="space-y-6">
          {/* Timeline */}
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider text-gray-400 flex items-center gap-1.5">
              <Clock size={14} className="text-blue-500" />
              Resolution Timeline
            </h3>
            <div className="relative border-l border-gray-800 ml-2.5 pl-4 space-y-4 py-2">
              {incident.timeline && incident.timeline.length > 0 ? (
                incident.timeline.map((event, idx) => (
                  <div key={idx} className="relative text-[11px]">
                    <span className="absolute -left-[21px] top-1 w-2 h-2 rounded-full bg-blue-500" />
                    <span className="text-[9px] text-gray-500 block">
                      {new Date(event.timestamp).toLocaleDateString()}
                    </span>
                    <span className="font-semibold text-white block mt-0.5">{event.title}</span>
                    <p className="text-gray-450 mt-0.5 leading-normal">{event.description}</p>
                  </div>
                ))
              ) : (
                <div className="relative text-[11px] text-gray-500 pl-2">
                  No timeline actions logged yet.
                </div>
              )}
            </div>
          </div>

          {/* Recommendations */}
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 space-y-4">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider text-gray-400 flex items-center gap-1.5">
              <SlidersHorizontal size={14} className="text-green-500" />
              Remediation Action Plan
            </h3>
            <ul className="space-y-3 text-xs">
              <li className="p-3 bg-[#0b0f19] border border-gray-850 rounded-lg flex items-start gap-2.5">
                <span className="w-5 h-5 bg-blue-500/10 border border-blue-500/25 rounded-full flex items-center justify-center text-[10px] font-bold text-blue-400 shrink-0">1</span>
                <div>
                  <span className="font-semibold text-white block">Restrict Network Exposure</span>
                  <p className="text-[10px] text-gray-450 mt-0.5">Restrict SSH port 22 access to secure VPN CIDR ranges only.</p>
                </div>
              </li>
              <li className="p-3 bg-[#0b0f19] border border-gray-850 rounded-lg flex items-start gap-2.5">
                <span className="w-5 h-5 bg-blue-500/10 border border-blue-500/25 rounded-full flex items-center justify-center text-[10px] font-bold text-blue-400 shrink-0">2</span>
                <div>
                  <span className="font-semibold text-white block">Enforce MFA Policies</span>
                  <p className="text-[10px] text-gray-450 mt-0.5">Enforce multi-factor auth on all associated IAM identities.</p>
                </div>
              </li>
            </ul>
          </div>
        </div>

      </div>
    </div>
  );
}
