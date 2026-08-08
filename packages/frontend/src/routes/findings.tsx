import React, { useState, useEffect } from 'react';
import { createRoute, useNavigate } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import { 
  Search, 
  RotateCw, 
  X, 
  Brain, 
  ShieldAlert, 
  CheckCircle,
  ExternalLink,
  ChevronRight,
  TrendingUp,
  AlertTriangle
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings',
  component: FindingsPage,
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
  remediation?: string[];
}

interface AIExplanation {
  root_cause: string;
  technical_impact: string;
  business_impact: string;
  recommendations: string[];
  confidence: number;
}

function FindingsPage() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [serviceFilter, setServiceFilter] = useState('All');
  const [sortFilter, setSortFilter] = useState('risk_desc');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  // Selected Finding / Drawer details
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'ai'>('overview');
  
  // AI Explain State
  const [aiLoading, setAiLoading] = useState(false);
  const [aiExplanation, setAiExplanation] = useState<AIExplanation | null>(null);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      const res = await api.get('/v1/findings');
      if (res.data && res.data.findings) {
        setFindings(res.data.findings);
      }
    } catch (e) {
      console.error(e);
      // Fallback mocks
      setFindings([
        {
          finding_id: 'F-001',
          title: 'SSH exposed to internet',
          description: 'Security group allows SSH from unrestricted IPv4 sources (0.0.0.0/0 on port 22).',
          severity: 'critical',
          status: 'open',
          resource_id: 'asset-sg-001',
          resource_name: 'test-public-ssh',
          resource_type: 'security_group',
          cloud_provider: 'aws',
          rule_id: 'rule-ssh-open',
          risk_score: 92,
          evidence: { port: 22, protocol: 'tcp', cidr: '0.0.0.0/0' },
          mitre_technique: 'T1021 - Remote Services',
          remediation: [
            'Restrict SSH access to approved administrative networks',
            'Implement bastion host architecture',
            'Remove direct SSH access for non-critical resources'
          ]
        },
        {
          finding_id: 'F-002',
          title: 'S3 Bucket Public Access Protection Disabled',
          description: 'S3 bucket does not have public access protection fully enabled.',
          severity: 'critical',
          status: 'open',
          resource_id: 'asset-s3-001',
          resource_name: 'aegivion-customer-data-bucket',
          resource_type: 's3',
          cloud_provider: 'aws',
          rule_id: 'AWS-S3-001',
          risk_score: 85,
          evidence: { block_public_acls: false, block_public_policy: false },
          mitre_technique: 'T1530',
          remediation: [
            'Enable S3 Block Public Access at the bucket level',
            'Review existing bucket policies for public access'
          ]
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
    const interval = setInterval(fetchFindings, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleSync = () => {
    setSyncing(true);
    fetchFindings().finally(() => setSyncing(false));
  };

  const handleExplain = async (findingId: string) => {
    setAiLoading(true);
    setAiExplanation(null);
    try {
      const res = await api.post(`/v1/ai/explain/${findingId}`, {
        finding_id: findingId
      });
      if (res.data && !res.data.error) {
        setAiExplanation(res.data);
      } else if (res.data.fallback) {
        setAiExplanation(res.data.fallback);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setAiLoading(false);
    }
  };

  // Severity Distribution Calculations
  const criticalCount = findings.filter(f => f.severity.toLowerCase() === 'critical').length;
  const highCount = findings.filter(f => f.severity.toLowerCase() === 'high').length;
  const mediumCount = findings.filter(f => f.severity.toLowerCase() === 'medium').length;
  const lowCount = findings.filter(f => f.severity.toLowerCase() === 'low').length;

  const openCount = findings.filter(f => f.status.toLowerCase() === 'open').length;
  const inProgressCount = findings.filter(f => f.status.toLowerCase() === 'in progress' || f.status.toLowerCase() === 'in_progress').length;
  const resolvedCount = findings.filter(f => f.status.toLowerCase() === 'resolved').length;
  const suppressedCount = findings.filter(f => f.status.toLowerCase() === 'suppressed' || f.status.toLowerCase() === 'false_positive').length;

  const serviceOptions = Array.from(new Set(findings.map(f => f.resource_type || 'Unknown').filter(Boolean)));

  const filteredFindings = findings.filter(f => {
    const matchesSearch = f.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          f.finding_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === 'All' || f.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesStatus = statusFilter === 'All' || f.status.toLowerCase() === statusFilter.toLowerCase();
    const matchesService = serviceFilter === 'All' || (f.resource_type || 'Unknown').toLowerCase() === serviceFilter.toLowerCase();
    return matchesSearch && matchesSeverity && matchesStatus && matchesService;
  });

  const sortedFindings = [...filteredFindings].sort((a, b) => {
    if (sortFilter === 'risk_desc') {
      return (b.risk_score || 0) - (a.risk_score || 0);
    }
    if (sortFilter === 'risk_asc') {
      return (a.risk_score || 0) - (b.risk_score || 0);
    }
    if (sortFilter === 'latest') {
      return b.finding_id.localeCompare(a.finding_id);
    }
    if (sortFilter === 'oldest') {
      return a.finding_id.localeCompare(b.finding_id);
    }
    return 0;
  });

  const totalPages = Math.ceil(sortedFindings.length / pageSize) || 1;
  const paginatedFindings = sortedFindings.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const getSeverityBadge = (severity: string) => {
    const sev = severity.toLowerCase();
    if (sev === 'critical') return 'bg-red-500/10 text-red-400 border-red-500/20';
    if (sev === 'high') return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    if (sev === 'medium') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
  };

  return (
    <div className="space-y-6 text-gray-200 pb-10">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security Findings</h1>
          <p className="text-gray-400 text-sm mt-1">Vulnerabilities and misconfigurations requiring attention.</p>
        </div>
        <button 
          onClick={handleSync}
          disabled={syncing}
          className="px-4 py-2 border border-gray-800 bg-[#0d1326] text-gray-300 rounded-lg text-sm hover:text-white transition flex items-center gap-2"
        >
          <RotateCw size={14} className={syncing ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Severity Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { name: 'Critical', count: criticalCount, color: 'text-red-500', border: 'border-red-500/20' },
          { name: 'High', count: highCount, color: 'text-orange-500', border: 'border-orange-500/20' },
          { name: 'Medium', count: mediumCount, color: 'text-yellow-500', border: 'border-yellow-500/20' },
          { name: 'Low', count: lowCount, color: 'text-blue-500', border: 'border-blue-500/20' }
        ].map(card => (
          <div key={card.name} className={`bg-[#0e1428] border ${card.border} rounded-xl p-4 flex items-center justify-between`}>
            <div>
              <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">{card.name} findings</span>
              <span className="text-2xl font-extrabold text-white mt-1 block">{card.count}</span>
            </div>
            <ShieldAlert size={20} className={card.color} />
          </div>
        ))}
      </div>

      {/* Status Breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Open', value: openCount, color: 'border-red-500 text-red-400' },
          { label: 'In Progress', value: inProgressCount, color: 'border-yellow-500 text-yellow-400' },
          { label: 'Resolved', value: resolvedCount, color: 'border-green-500 text-green-400' },
          { label: 'Suppressed / False Positive', value: suppressedCount, color: 'border-blue-500 text-blue-400' }
        ].map(card => (
          <div key={card.label} className={`border-l-4 rounded-xl p-4 bg-[#0e1428] border-gray-800 ${card.color}`}>
            <span className="text-[10px] text-gray-500 uppercase tracking-wider block">{card.label}</span>
            <span className="text-xl font-bold text-white mt-1 block">{card.value}</span>
          </div>
        ))}
      </div>

      {/* Toolbar filters */}
      <div className="flex flex-wrap gap-4 items-center justify-between bg-[#0e1428] border border-[#1e293b] p-4 rounded-xl">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3.5 top-3 text-gray-500" size={14} />
          <input
            type="text"
            placeholder="Search findings by ID or keyword..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-[#0b0f19] border border-gray-800 rounded-xl pl-10 pr-4 py-2 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-gray-700 transition"
          />
        </div>

        <div className="flex items-center gap-3">
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-[#0b0f19] border border-gray-800 text-xs text-gray-300 rounded-lg px-3 py-1.5 focus:outline-none"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            value={serviceFilter}
            onChange={(e) => {
              setServiceFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-[#0b0f19] border border-gray-800 text-xs text-gray-300 rounded-lg px-3 py-1.5 focus:outline-none"
          >
            <option value="All">All Services</option>
            {serviceOptions.map(service => (
              <option key={service} value={service}>{service.toUpperCase()}</option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-[#0b0f19] border border-gray-800 text-xs text-gray-300 rounded-lg px-3 py-1.5 focus:outline-none"
          >
            <option value="All">All Statuses</option>
            <option value="Open">Open</option>
            <option value="In Progress">In Progress</option>
            <option value="Resolved">Resolved</option>
          </select>

          <select
            value={sortFilter}
            onChange={(e) => {
              setSortFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-[#0b0f19] border border-gray-800 text-xs text-gray-300 rounded-lg px-3 py-1.5 focus:outline-none"
          >
            <option value="risk_desc">Risk (High → Low)</option>
            <option value="risk_asc">Risk (Low → High)</option>
            <option value="latest">Newest First</option>
            <option value="oldest">Oldest First</option>
          </select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-gray-300">
            <thead className="bg-[#0d1326] text-gray-400 uppercase text-[9px] tracking-wider font-semibold border-b border-gray-800">
              <tr>
                <th className="px-6 py-4">Finding ID</th>
                <th className="px-6 py-4">Vulnerability Description</th>
                <th className="px-6 py-4">Severity</th>
                <th className="px-6 py-4">Target Resource</th>
                <th className="px-6 py-4">Status</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
             <tbody className="divide-y divide-gray-800/60">
              {paginatedFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-10 text-gray-500">No security findings found.</td>
                </tr>
              ) : (
                paginatedFindings.map((f) => (
                  <tr key={f.finding_id} className="hover:bg-gray-800/10 transition group">
                    <td className="px-6 py-4 font-mono font-bold text-blue-400">{f.finding_id}</td>
                    <td className="px-6 py-4 font-semibold text-white max-w-sm">{f.title}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-0.5 border text-[10px] font-bold rounded ${getSeverityBadge(f.severity)}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-gray-400 capitalize">{f.resource_name || f.resource_id}</td>
                    <td className="px-6 py-4 capitalize">
                      <span className="px-2 py-0.5 border border-blue-900/30 text-blue-400 bg-blue-950/20 text-[10px] font-semibold rounded">
                        {f.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button 
                        onClick={() => {
                          navigate({ to: `/findings/${f.finding_id}` });
                        }}
                        className="px-2.5 py-1 text-xs text-blue-400 hover:text-white bg-blue-600/5 hover:bg-blue-600 rounded border border-blue-500/20 transition flex items-center gap-1 ml-auto"
                      >
                        Inspect
                        <ChevronRight size={12} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        
        {/* Pagination Controls */}
        <div className="flex justify-between items-center px-6 py-4 bg-[#0d1326] border-t border-gray-800 text-xs text-gray-400">
          <div>
            Showing {Math.min(filteredFindings.length, (currentPage - 1) * pageSize + 1)}-{Math.min(filteredFindings.length, currentPage * pageSize)} of {filteredFindings.length} findings
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1.5 rounded bg-[#0b0f19] border border-gray-800 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-gray-800 text-white transition"
            >
              Previous
            </button>
            <span className="font-semibold text-white">Page {currentPage} of {totalPages}</span>
            <button
              onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
              disabled={currentPage === totalPages}
              className="px-3 py-1.5 rounded bg-[#0b0f19] border border-gray-800 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-gray-800 text-white transition"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      {/* Drawer */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-all">
          <div className="w-full max-w-lg bg-[#0d1326] border-l border-gray-800 h-full flex flex-col justify-between shadow-2xl relative">
            
            {/* Header */}
            <div className="p-6 border-b border-gray-800 flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-white leading-snug">{selectedFinding.title}</h2>
                <span className="text-[10px] text-gray-500 font-mono block mt-0.5">{selectedFinding.finding_id}</span>
              </div>
              <button 
                onClick={() => setSelectedFinding(null)}
                className="p-1.5 hover:bg-gray-800 text-gray-400 hover:text-white rounded-lg transition"
              >
                <X size={18} />
              </button>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-gray-800 px-6 bg-[#0e1428]">
              {(['overview', 'evidence', 'ai'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition ${
                    activeTab === tab 
                      ? 'border-blue-500 text-white' 
                      : 'border-transparent text-gray-400 hover:text-white'
                  }`}
                >
                  {tab === 'ai' ? 'AI Advisor' : tab}
                </button>
              ))}
            </div>

            {/* Content Panel */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 space-y-3">
                    <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Vulnerability Overview</h4>
                    <p className="text-xs text-gray-300 leading-relaxed">{selectedFinding.description}</p>
                    <div className="grid grid-cols-2 gap-4 text-xs pt-2">
                      <div>
                        <span className="text-gray-500 block">Severity</span>
                        <span className={`font-semibold capitalize ${
                          selectedFinding.severity === 'critical' ? 'text-red-400' : 'text-orange-400'
                        }`}>{selectedFinding.severity}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Calculated Risk Score</span>
                        <span className="font-semibold text-white">{selectedFinding.risk_score || 50}/100</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">MITRE Reference</span>
                        <span className="font-semibold text-white">{selectedFinding.mitre_technique || 'N/A'}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Rule ID</span>
                        <span className="font-mono text-white">{selectedFinding.rule_id}</span>
                      </div>
                    </div>
                  </div>

                  {/* Remediation steps */}
                  {selectedFinding.remediation && (
                    <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 space-y-3">
                      <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Recommended Remediation</h4>
                      <ul className="space-y-2">
                        {selectedFinding.remediation.map((step, idx) => (
                          <li key={idx} className="text-xs text-gray-300 flex items-start gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-1.5 shrink-0" />
                            <span>{step}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'evidence' && (
                <div className="space-y-3">
                  <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Asset Config Evidence</h4>
                  <pre className="bg-[#0b0f19] border border-gray-850 rounded-xl p-4 text-[10px] font-mono text-green-400 overflow-x-auto">
                    {JSON.stringify(selectedFinding.evidence || {}, null, 2)}
                  </pre>
                </div>
              )}

              {activeTab === 'ai' && (
                <div className="space-y-6">
                  {!aiExplanation && !aiLoading && (
                    <div className="text-center py-10">
                      <Brain className="w-12 h-12 text-blue-500/25 mx-auto mb-4 animate-bounce" />
                      <h4 className="text-sm font-bold text-white">Generate AI Analysis</h4>
                      <p className="text-gray-500 text-xs mt-1.5 max-w-xs mx-auto">
                        Ask Aegivion AI to evaluate the root cause, technical fallout, and business impacts of this configuration.
                      </p>
                      <button 
                        onClick={() => handleExplain(selectedFinding.finding_id)}
                        className="mt-5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg transition shadow-lg shadow-blue-500/25"
                      >
                        Explain Finding
                      </button>
                    </div>
                  )}

                  {aiLoading && (
                    <div className="text-center py-20">
                      <RotateCw className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-4" />
                      <p className="text-xs text-gray-400">Aegivion AI is reasoning about this finding...</p>
                    </div>
                  )}

                  {aiExplanation && (
                    <div className="space-y-6">
                      <div className="bg-blue-950/10 border border-blue-900/30 rounded-xl p-4 text-xs leading-relaxed text-blue-300 flex items-start gap-3">
                        <AlertTriangle className="shrink-0 text-blue-400 mt-0.5" size={16} />
                        <div>
                          <span className="font-bold block">AI Confidence Score: {Math.round(aiExplanation.confidence * 100)}%</span>
                          <span>Based strictly on provided S3 block and security configurations.</span>
                        </div>
                      </div>

                      <div className="space-y-1">
                        <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Root Cause Analysis</h5>
                        <div className="bg-[#0e1428] border border-gray-850 p-4 rounded-xl text-xs text-gray-300 leading-relaxed">
                          {aiExplanation.root_cause}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Technical Fallout</h5>
                        <div className="bg-[#0e1428] border border-gray-850 p-4 rounded-xl text-xs text-gray-300 leading-relaxed">
                          {aiExplanation.technical_impact}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Business Implications</h5>
                        <div className="bg-[#0e1428] border border-gray-850 p-4 rounded-xl text-xs text-gray-300 leading-relaxed">
                          {aiExplanation.business_impact}
                        </div>
                      </div>

                      <div className="space-y-1">
                        <h5 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Remediation Action Plan</h5>
                        <div className="bg-[#0e1428] border border-gray-850 p-4 rounded-xl space-y-2">
                          {aiExplanation.recommendations.map((rec, idx) => (
                            <div key={idx} className="text-xs text-gray-300 flex items-start gap-2">
                              <span className="text-blue-500 font-bold">{idx + 1}.</span>
                              <span>{rec}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-6 border-t border-gray-800 bg-[#0e1428] flex items-center justify-between text-xs">
              <span className="text-gray-500">Day 11 Security Advisor</span>
              <button 
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg transition"
              >
                Close Drawer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
