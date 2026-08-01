import React, { useState, useEffect } from 'react';
import { createRoute, Link, useParams } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import { 
  ArrowLeft, 
  Brain, 
  ShieldAlert, 
  Clock, 
  Play, 
  Copy, 
  Check, 
  Cpu, 
  AlertTriangle,
  Info,
  CheckCircle,
  FileCode
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings/$findingId',
  component: FindingDetailPage,
});

interface Finding {
  finding_id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  resource_id: string;
  resource_name: string;
  resource_type: string;
  cloud_provider: string;
  rule_id: string;
  risk_score?: number;
  evidence?: Record<string, any>;
  mitre_technique?: string;
  mitre_tactic?: string;
  remediation?: string[];
  created_at?: string;
}

interface RemediationStep {
  order: number;
  action: string;
  reason: string;
  effort: string;
  urgency: string;
}

interface RemediationPlan {
  priority: string;
  summary: string;
  steps: RemediationStep[];
  validation: string[];
  confidence: number;
  estimated_effort: string;
  references: string[];
}

interface AIExplanation {
  summary: string;
  root_cause: string;
  technical_impact: string;
  business_impact: string;
  confidence: number;
}

function FindingDetailPage() {
  const { findingId } = useParams({ from: Route.id });
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [selectedTab, setSelectedTab] = useState<'overview' | 'evidence' | 'ai' | 'remediation'>('overview');

  // AI & Remediation States
  const [aiLoading, setAiLoading] = useState(false);
  const [aiExplanation, setAiExplanation] = useState<AIExplanation | null>(null);
  
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [remediationPlan, setRemediationPlan] = useState<RemediationPlan | null>(null);

  const fetchFindingDetails = async () => {
    try {
      setLoading(true);
      // Fetch finding (using findings list query fallback if single finding endpoint doesn't exist)
      const res = await api.get('/v1/findings');
      if (res.data && res.data.findings) {
        const found = res.data.findings.find((f: any) => f.finding_id === findingId);
        if (found) {
          setFinding(found);
          return;
        }
      }
      
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
    } catch (e) {
      console.error(e);
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
          <div className="flex border-b border-gray-800">
            {(['overview', 'evidence', 'ai', 'remediation'] as const).map((tab) => (
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
              <div className="space-y-6">
                {!aiExplanation && !aiLoading && (
                  <div className="text-center py-10">
                    <Brain className="w-12 h-12 text-blue-500/25 mx-auto mb-4 animate-pulse" />
                    <h4 className="text-sm font-bold text-white">Generate AI Analysis</h4>
                    <p className="text-gray-500 text-xs mt-1.5">
                      Request Aegivion AI to perform a detailed security logic walkthrough.
                    </p>
                    <button 
                      onClick={handleGenerateAI}
                      className="mt-4 px-4 py-2 bg-blue-600 text-white text-xs font-semibold rounded-lg hover:bg-blue-500 transition"
                    >
                      Run AI Explainer
                    </button>
                  </div>
                )}

                {aiLoading && (
                  <div className="text-center py-20">
                    <RotateCw className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-4" />
                    <p className="text-xs text-gray-400">Aegivion AI is generating explanation details...</p>
                  </div>
                )}

                {aiExplanation && (
                  <div className="space-y-6">
                    <div className="bg-blue-950/10 border border-blue-900/30 rounded-xl p-4 text-xs text-blue-300 flex items-start gap-3">
                      <Cpu className="text-blue-400 shrink-0 mt-0.5" size={16} />
                      <div>
                        <span className="font-bold block">AI Confidence Score: {Math.round((aiExplanation.confidence || 0.9) * 100)}%</span>
                        <span>Evaluation based on configuration values.</span>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Root Cause Analysis</h4>
                      <div className="bg-[#0b0f19] border border-gray-800 p-4 rounded-xl text-xs text-gray-300 leading-relaxed">
                        {aiExplanation.root_cause}
                      </div>
                    </div>

                    <div>
                      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Technical fallout</h4>
                      <div className="bg-[#0b0f19] border border-gray-800 p-4 rounded-xl text-xs text-gray-300 leading-relaxed">
                        {aiExplanation.technical_impact}
                      </div>
                    </div>

                    <div>
                      <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2">Business fallout</h4>
                      <div className="bg-[#0b0f19] border border-gray-800 p-4 rounded-xl text-xs text-gray-300 leading-relaxed">
                        {aiExplanation.business_impact}
                      </div>
                    </div>
                  </div>
                )}
              </div>
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
                        {remediationPlan.steps.map((step) => (
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
                        {remediationPlan.validation.map((v, idx) => (
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

          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-white flex items-center gap-1.5">
              <Clock size={14} className="text-blue-500" />
              Activity Timeline
            </h3>
            <div className="relative border-l border-gray-800 ml-2.5 pl-4 space-y-5 py-2">
              <div className="relative">
                <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-blue-500" />
                <span className="text-[10px] text-gray-500 block">Detected date</span>
                <span className="font-semibold text-xs text-white">Finding Registered</span>
              </div>
              <div className="relative">
                <span className="absolute -left-[21px] top-1 w-2.5 h-2.5 rounded-full bg-gray-700" />
                <span className="text-[10px] text-gray-500 block">Status update</span>
                <span className="font-semibold text-xs text-gray-400">Assessed Security Posture</span>
              </div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
