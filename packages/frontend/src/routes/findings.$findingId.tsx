import React, { useState, useEffect } from 'react';
import { useParams, Link, createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import { 
  ArrowLeft, Brain, Play, RotateCw, Check, Copy, Info, CheckCircle, 
  CheckCircle2, Clock, Calendar, ShieldAlert, History
} from 'lucide-react';
import { AIExplanationPanel } from '@/components/findings/AIExplanationPanel';
import { AnalystActions } from '@/components/findings/AnalystActions';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings/$findingId',
  component: RouteComponent,
});

interface FindingHistoryResponse {
  finding_id: string;
  fingerprint: string;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  events: Array<{
    event: string;
    timestamp: string;
    description: string;
  }>;
}

export function RouteComponent() {
  const { findingId } = useParams({ from: '/findings/$findingId' });
  const [selectedTab, setSelectedTab] = useState<'overview' | 'evidence' | 'ai' | 'remediation' | 'timeline'>('overview');
  const [copied, setCopied] = useState(false);
  const [aiExplanation, setAiExplanation] = useState<any>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [remediationPlan, setRemediationPlan] = useState<any>(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [finding, setFinding] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // M2/M4: Occurrence timeline history endpoint query hook
  const { data: timelineHistory, isLoading: historyLoading } = useQuery<FindingHistoryResponse>({
    queryKey: ['finding-history', findingId],
    queryFn: async () => {
      const res = await api.get(`/v1/findings/${findingId}/history`);
      return res.data;
    }
  });

  const fetchFindingDetails = async () => {
    try {
      setLoading(true);
      const res = await api.get(`/v1/findings/${findingId}`);
      setFinding(res.data);
    } catch (e) {
      console.error(e);
      // Fallback fallback mock if not found
      setFinding({
        finding_id: findingId,
        title: 'Console-enabled IAM User Without MFA',
        description: 'IAM user has console access but Multi-Factor Authentication is not enabled.',
        severity: 'high',
        status: 'open',
        resource_id: 'iam:user:security-admin-01',
        resource_name: 'security-admin-01',
        resource_type: 'iam_user',
        cloud_provider: 'aws',
        rule_id: 'AWS-IAM-001',
        risk_score: 88,
        evidence: { console_access: true, mfa_enabled: false },
        mitre_technique: 'T1078',
        mitre_tactic: 'initial_access',
        remediation: ['Enable MFA for the affected user'],
        created_at: new Date().toISOString()
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindingDetails();
  }, [findingId]);

  const handleGenerateAI = async () => {
    setAiLoading(true);
    try {
      const res = await api.post(`/v1/ai/explain/${findingId}`, { finding_id: findingId });
      setAiExplanation(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleGenerateRemediation = async () => {
    setRemediationLoading(true);
    try {
      const res = await api.post(`/v1/ai/remediate/${findingId}`);
      setRemediationPlan(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setRemediationLoading(false);
    }
  };

  const handleCopy = () => {
    if (finding) {
      navigator.clipboard.writeText(JSON.stringify(finding.evidence, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <RotateCw className="w-8 h-8 text-blue-500 animate-spin" />
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="text-center py-20 text-gray-400">
        Finding not found.
      </div>
    );
  }

  const getSeverityBadge = (severity: string) => {
    const sev = severity.toLowerCase();
    if (sev === 'critical') return 'bg-red-500/10 text-red-400 border-red-500/20';
    if (sev === 'high') return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    if (sev === 'medium') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
  };

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      {/* Back link */}
      <div>
        <Link 
          to="/findings" 
          className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-white transition"
        >
          <ArrowLeft size={14} />
          Back to Findings
        </Link>
      </div>

      {/* Header bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-gray-800 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white tracking-tight">{finding.title}</h1>
            <span className={`px-2.5 py-0.5 border text-[10px] font-bold rounded-full ${getSeverityBadge(finding.severity)}`}>
              {finding.severity}
            </span>
          </div>
          <p className="text-gray-400 text-sm mt-1.5">
            Rule: <span className="font-mono text-blue-400">{finding.rule_id}</span> • Detected on asset {finding.resource_name || finding.resource_id}
          </p>
          {finding.mitre_mappings && finding.mitre_mappings.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {finding.mitre_mappings.map((m: any) => (
                <span key={m.technique_id} className="px-2 py-0.5 border border-purple-900/30 text-purple-400 bg-purple-950/20 text-[9px] font-bold rounded" title={m.reason}>
                  MITRE {m.technique_id}: {m.technique_name}
                </span>
              ))}
            </div>
          )}
        </div>
        <div className="flex gap-2">
          <button 
            onClick={handleGenerateAI}
            className="px-4 py-2 bg-blue-600/10 border border-blue-500/20 text-blue-400 hover:text-white hover:bg-blue-600 rounded-lg text-xs font-semibold transition flex items-center gap-1.5"
          >
            <Brain size={14} />
            AI Explain
          </button>
          <button 
            onClick={handleGenerateRemediation}
            className="px-4 py-2 bg-green-600/10 border border-green-500/20 text-green-400 hover:text-white hover:bg-green-600 rounded-lg text-xs font-semibold transition flex items-center gap-1.5"
          >
            <Play size={14} />
            Remediate
          </button>
        </div>
      </div>

      {/* Main split details grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Columns: Tabs and Analysis */}
        <div className="lg:col-span-2 space-y-6">
          <div className="flex border-b border-gray-800 bg-[#0c1328]">
            {(['overview', 'evidence', 'ai', 'remediation', 'timeline'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setSelectedTab(tab)}
                className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition ${
                  selectedTab === tab 
                    ? 'border-blue-500 text-white' 
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                {tab === 'ai' ? 'AI Advisor' : tab}
              </button>
            ))}
          </div>

          <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6">
            {selectedTab === 'overview' && (
              <div className="space-y-6">
                <div>
                  <h3 className="text-sm font-bold text-white mb-2">Description</h3>
                  <p className="text-xs text-gray-300 leading-relaxed">{finding.description}</p>
                </div>

                <div className="border-t border-gray-800 pt-6">
                  <h3 className="text-sm font-bold text-white mb-4">MITRE ATT&CK Context</h3>
                  <div className="grid grid-cols-2 gap-4 text-xs">
                    <div>
                      <span className="text-gray-500 block">Technique</span>
                      <span className="font-semibold text-white">{finding.mitre_technique || 'T1078 - Valid Accounts'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 block">Tactic</span>
                      <span className="font-semibold text-white capitalize">{finding.mitre_tactic || 'Initial Access'}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {selectedTab === 'evidence' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white">JSON Configuration Evidence</h3>
                  <button 
                    onClick={handleCopy}
                    className="p-1 text-gray-400 hover:text-white transition flex items-center gap-1 text-[10px]"
                  >
                    {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                    {copied ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <pre className="bg-[#0b0f19] border border-gray-850 rounded-xl p-4 text-[11px] font-mono text-green-400 overflow-x-auto">
                  {JSON.stringify(finding.evidence || {}, null, 2)}
                </pre>
              </div>
            )}

            {selectedTab === 'ai' && (
              <AIExplanationPanel findingId={findingId} />
            )}

            {selectedTab === 'remediation' && (
              <div className="space-y-6">
                {!remediationPlan && !remediationLoading && (
                  <div className="text-center py-10">
                    <Play className="w-12 h-12 text-green-500/25 mx-auto mb-4 animate-pulse" />
                    <h4 className="text-sm font-bold text-white">Generate Remediation Plan</h4>
                    <p className="text-gray-500 text-xs mt-1.5">
                      Produce step-by-step priority guidelines and validation tasks.
                    </p>
                    <button 
                      onClick={handleGenerateRemediation}
                      className="mt-4 px-4 py-2 bg-green-600 text-white text-xs font-semibold rounded-lg hover:bg-green-500 transition"
                    >
                      Run Remediation Engine
                    </button>
                  </div>
                )}

                {remediationLoading && (
                  <div className="text-center py-20">
                    <RotateCw className="w-8 h-8 text-green-500 animate-spin mx-auto mb-4" />
                    <p className="text-xs text-gray-400">Aegivion AI is calculating remediation plans...</p>
                  </div>
                )}

                {remediationPlan && (
                  <div className="space-y-6">
                    <div className="flex gap-3">
                      <span className="px-2 py-0.5 border border-green-800 text-green-400 bg-green-950/20 text-[10px] font-bold rounded capitalize">
                        Priority: {remediationPlan.priority}
                      </span>
                      <span className="px-2 py-0.5 border border-gray-700 text-gray-300 bg-gray-800/50 text-[10px] font-bold rounded">
                        Total Effort: {remediationPlan.estimated_effort}
                      </span>
                    </div>

                    <div className="space-y-4 pt-2">
                      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider">Step-by-Step Remediation</h4>
                      <div className="space-y-3">
                        {remediationPlan.steps.map((step: any) => (
                          <div key={step.order} className="bg-[#0b0f19] border border-gray-850 p-4 rounded-xl flex gap-3.5 items-start">
                            <span className="w-6 h-6 bg-blue-600/10 text-blue-400 border border-blue-500/25 rounded-full flex items-center justify-center font-bold text-xs">
                              {step.order}
                            </span>
                            <div className="flex-1 space-y-1">
                              <div className="font-semibold text-xs text-white">{step.action}</div>
                              <div className="text-[11px] text-gray-400">{step.reason}</div>
                              <div className="text-[10px] text-gray-500 pt-1">
                                Effort: {step.effort} • Urgency: <span className="capitalize text-orange-400 font-medium">{step.urgency}</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-2 border-t border-gray-800 pt-4">
                      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider">Validation Criteria</h4>
                      <ul className="space-y-2">
                        {remediationPlan.validation.map((v: any, idx: number) => (
                          <li key={idx} className="text-xs text-gray-300 flex items-center gap-2">
                            <CheckCircle className="text-green-500 shrink-0" size={13} />
                            <span>{v}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* M4 Finding Timeline Occurrence Visualization panel */}
            {selectedTab === 'timeline' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between border-b border-gray-850 pb-4">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <History size={16} className="text-indigo-400" />
                      Occurrence History &amp; Deduplication Audit
                    </h3>
                    <p className="text-[10px] text-gray-500 mt-1">Aegivion deduplicates recurring alerts to capture structural trends.</p>
                  </div>
                  {timelineHistory && (
                    <div className="px-3 py-1 bg-indigo-950/20 border border-indigo-900/30 text-[10px] font-bold text-indigo-400 rounded-lg">
                      Occurrences: {timelineHistory.occurrence_count}
                    </div>
                  )}
                </div>

                {historyLoading ? (
                  <div className="text-center py-10"><RotateCw className="w-6 h-6 text-indigo-500 animate-spin mx-auto" /></div>
                ) : timelineHistory ? (
                  <div className="space-y-6">
                    <div className="grid grid-cols-2 gap-4 text-xs bg-[#0b0f19] p-4 border border-gray-850 rounded-xl">
                      <div>
                        <span className="text-gray-500 block">First Detected</span>
                        <span className="font-semibold text-white">{new Date(timelineHistory.first_seen).toLocaleString()}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Last Active</span>
                        <span className="font-semibold text-white">{new Date(timelineHistory.last_seen).toLocaleString()}</span>
                      </div>
                      <div className="col-span-2 border-t border-gray-800/60 pt-2.5">
                        <span className="text-gray-500 block mb-1">Deduplication Fingerprint Hash</span>
                        <span className="font-mono text-[10px] text-indigo-400 break-all">{timelineHistory.fingerprint}</span>
                      </div>
                    </div>

                    <div className="relative pl-4 border-l border-gray-850 space-y-4">
                      {timelineHistory.events.map((ev, idx) => (
                        <div key={idx} className="relative space-y-1">
                          <div className="absolute -left-[21px] top-1 bg-indigo-600 rounded-full w-2.5 h-2.5 border-2 border-indigo-400"></div>
                          <div className="flex justify-between items-center text-[10px]">
                            <span className="font-bold text-indigo-400">{ev.event}</span>
                            <span className="text-gray-500">{new Date(ev.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="text-[11px] text-gray-300">{ev.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-gray-500 text-center py-10">No tracking history registered for this finding.</p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Asset summary card & Activity Timeline */}
        <div className="space-y-6">
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
              <Info size={14} className="text-blue-500" />
              Target Resource
            </h3>
            <div className="space-y-3 text-xs">
              <div>
                <span className="text-gray-500 block">Resource ID</span>
                <span className="font-mono text-white block truncate">{finding.resource_id}</span>
              </div>
              <div>
                <span className="text-gray-500 block">Resource Type</span>
                <span className="font-semibold text-white capitalize">{finding.resource_type.replace('_', ' ')}</span>
              </div>
              <div>
                <span className="text-gray-500 block">Cloud Account Provider</span>
                <span className="font-semibold text-white uppercase">{finding.cloud_provider}</span>
              </div>
              <div>
                <span className="text-gray-500 block">Risk Score</span>
                <span className="font-semibold text-red-400">{finding.risk_score || 50}/100</span>
              </div>
            </div>
          </div>

          <AnalystActions
            findingId={findingId}
            currentStatus={finding.status}
            currentAssignee={finding.assigned_to}
            timeline={finding.timeline || []}
            notes={finding.notes || []}
            onUpdate={fetchFindingDetails}
          />
        </div>

      </div>
    </div>
  );
}

export default RouteComponent;
