import React, { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { 
  Plus, 
  FileText, 
  Download, 
  RotateCw, 
  AlertTriangle,
  Brain,
  Shield,
  Layers,
  ArrowLeft,
  X
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reports',
  component: ReportsPage,
});

interface Report {
  id: string;
  snapshot_id: string;
  report_type: string;
  status: string;
  title: string;
  created_at: string;
  content: {
    summary: string;
    priorities: string[];
    limitations: string[];
    metrics?: {
      findings: { critical: number; high: number; medium: number; low: number };
      incidents: { open: number; investigating: number };
      assets: { total: number; high_risk: number };
      compliance: { pass: number; fail: number; not_assessed: number };
    };
  };
}

function ReportsPage() {
  const queryClient = useQueryClient();
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [generateType, setGenerateType] = useState<'EXECUTIVE' | 'TECHNICAL' | 'COMPLIANCE'>('EXECUTIVE');

  // Query report library list
  const { data: libraryData, isLoading, isError, refetch } = useQuery<{ reports: Report[] }>({
    queryKey: ['reports-library'],
    queryFn: async () => {
      const res = await api.get('/v1/reports/library');
      return res.data;
    }
  });

  // Generate report mutation
  const generateMutation = useMutation({
    mutationFn: async (type: string) => {
      const res = await api.post(`/v1/reports/generate?report_type=${type}`);
      return res.data;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['reports-library'] });
      refetch();
      setShowGenerateModal(false);
      setSelectedReportId(data.id);
    }
  });

  const reports = libraryData?.reports || [];
  const activeReport = reports.find(r => r.id === selectedReportId);

  const getReportTypeBadgeClass = (type: string) => {
    switch (type.toUpperCase()) {
      case 'EXECUTIVE':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
      case 'TECHNICAL':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/20';
      case 'COMPLIANCE':
        return 'bg-green-500/10 text-green-400 border-green-500/20';
      default:
        return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
    }
  };

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <FileText size={22} className="text-indigo-500" />
            Reports Center
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Generate executive, technical, and GRC compliance posture reviews.
          </p>
        </div>
        <button 
          onClick={() => setShowGenerateModal(true)}
          className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-1.5"
        >
          <Plus size={14} />
          Generate Report
        </button>
      </div>

      {/* Row 1 Quick Info */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-36">
          <div>
            <h3 className="font-bold text-white text-xs uppercase tracking-wider text-gray-400">Executive Report</h3>
            <p className="text-[11px] text-gray-500 mt-2 leading-relaxed">
              Board-ready posture summaries, risk distributions, and priority remediation lists.
            </p>
          </div>
          <button 
            onClick={() => { setGenerateType('EXECUTIVE'); setShowGenerateModal(true); }}
            className="w-fit px-3 py-1.5 bg-gray-850 hover:bg-gray-800 text-white border border-gray-800 rounded-lg text-[10px] font-semibold transition"
          >
            Select Template
          </button>
        </div>

        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-36">
          <div>
            <h3 className="font-bold text-white text-xs uppercase tracking-wider text-gray-400">Technical Report</h3>
            <p className="text-[11px] text-gray-500 mt-2 leading-relaxed">
              Full finding detail lists, affected EC2/S3 identifiers, and technical validate steps.
            </p>
          </div>
          <button 
            onClick={() => { setGenerateType('TECHNICAL'); setShowGenerateModal(true); }}
            className="w-fit px-3 py-1.5 bg-gray-850 hover:bg-gray-800 text-white border border-gray-800 rounded-lg text-[10px] font-semibold transition"
          >
            Select Template
          </button>
        </div>

        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-36">
          <div>
            <h3 className="font-bold text-white text-xs uppercase tracking-wider text-gray-400">Compliance Review</h3>
            <p className="text-[11px] text-gray-500 mt-2 leading-relaxed">
              CIS AWS Foundations mapping results, pass rate metrics, and assessment limitations GRC summaries.
            </p>
          </div>
          <button 
            onClick={() => { setGenerateType('COMPLIANCE'); setShowGenerateModal(true); }}
            className="w-fit px-3 py-1.5 bg-gray-850 hover:bg-gray-800 text-white border border-gray-800 rounded-lg text-[10px] font-semibold transition"
          >
            Select Template
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Report Library */}
        <div className="lg:col-span-2 space-y-4">
          <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-4 flex items-center justify-between">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider text-gray-400">Report Library</h3>
            <span className="text-[10px] text-gray-550 font-semibold">{reports.length} generated documents</span>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-20">
              <RotateCw className="w-8 h-8 text-indigo-500 animate-spin" />
            </div>
          ) : isError ? (
            <div className="text-center py-16 text-red-400 text-xs bg-red-950/10 border border-red-900/20 rounded-xl">
              Failed to load reports. Please verify backend API connection.
            </div>
          ) : reports.length === 0 ? (
            <div className="text-center py-16 text-gray-500 text-xs bg-[#0e1428] border border-gray-850 rounded-xl">
              No security posture reports generated yet.
            </div>
          ) : (
            <div className="space-y-3">
              {reports.map((rep) => (
                <div
                  key={rep.id}
                  onClick={() => setSelectedReportId(rep.id === selectedReportId ? null : rep.id)}
                  className={`p-5 border rounded-xl cursor-pointer transition flex items-center justify-between gap-4 ${
                    selectedReportId === rep.id 
                      ? 'bg-indigo-600/5 border-indigo-500/40' 
                      : 'bg-[#0e1428] border-gray-850 hover:bg-gray-850/20'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <FileText className="text-gray-500 shrink-0" size={18} />
                    <div>
                      <h4 className="font-semibold text-xs text-white">{rep.title}</h4>
                      <span className="text-[10px] text-gray-500 block mt-0.5">
                        Created: {new Date(rep.created_at).toLocaleDateString()} &middot; ID: {rep.id.slice(0,8)}
                      </span>
                    </div>
                  </div>
                  <span className={`px-2 py-0.5 border text-[9px] font-bold rounded uppercase ${getReportTypeBadgeClass(rep.report_type)}`}>
                    {rep.report_type}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Report Inspector Preview */}
        <div className="lg:col-span-1">
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 min-h-[450px]">
            {activeReport ? (
              <div className="space-y-5 text-xs leading-relaxed">
                
                {/* Header */}
                <div className="flex items-start justify-between border-b border-gray-850 pb-3">
                  <div>
                    <span className="text-[9px] text-gray-500 font-mono block">Document Preview</span>
                    <h3 className="font-bold text-white uppercase tracking-wider text-gray-400 mt-0.5">{activeReport.report_type} Review</h3>
                  </div>
                  <button 
                    onClick={() => setSelectedReportId(null)}
                    className="text-gray-550 hover:text-white"
                  >
                    <X size={14} />
                  </button>
                </div>

                {/* Scope Warning Banner */}
                <div className="p-3 bg-[#0b0f19] border border-gray-850 rounded-lg text-[10px] text-gray-450 space-y-1">
                  <span className="font-bold text-white block uppercase text-[9px] tracking-wider">Report Scope</span>
                  <div>AWS Account: production-account</div>
                  <div>Region: ap-south-1 &middot; Coverage: PARTIAL</div>
                </div>

                {/* Report Content */}
                <div className="space-y-4">
                  <div>
                    <span className="font-semibold text-white block uppercase tracking-wider text-gray-500 text-[9px]">Summary Statement</span>
                    <p className="text-gray-300 text-[11px] mt-1 font-sans">{activeReport.content.summary}</p>
                  </div>

                  {activeReport.content.metrics && (
                    <div className="grid grid-cols-2 gap-2 border-t border-gray-800 pt-3 text-[10px]">
                      <div>
                        <span className="text-gray-500 block">Critical Findings</span>
                        <span className="font-bold text-red-400">{activeReport.content.metrics.findings.critical}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Open Incidents</span>
                        <span className="font-bold text-orange-400">{activeReport.content.metrics.incidents.open}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Total Assets</span>
                        <span className="font-bold text-white">{activeReport.content.metrics.assets.total}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Compliance PASS</span>
                        <span className="font-bold text-green-400">{activeReport.content.metrics.compliance.pass} / {activeReport.content.metrics.compliance.pass + activeReport.content.metrics.compliance.fail}</span>
                      </div>
                    </div>
                  )}

                  <div className="border-t border-gray-800 pt-3">
                    <span className="font-semibold text-white block uppercase tracking-wider text-gray-500 text-[9px] mb-1">Top Priorities</span>
                    <ol className="list-decimal pl-4 space-y-1 text-gray-400 text-[10px]">
                      {activeReport.content.priorities.map((p, idx) => (
                        <li key={idx}>{p}</li>
                      ))}
                    </ol>
                  </div>

                  <div className="border-t border-gray-800 pt-3">
                    <span className="font-semibold text-red-400 block uppercase tracking-wider text-[9px] mb-1">Assessment Limitations</span>
                    <ul className="list-disc pl-4 space-y-0.5 text-gray-450 text-[9px]">
                      {activeReport.content.limitations.map((l, idx) => (
                        <li key={idx}>{l}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="border-t border-gray-800 pt-3 flex justify-end gap-2">
                  <button 
                    onClick={() => window.print()}
                    className="px-3 py-1.5 bg-gray-850 hover:bg-gray-850/80 border border-gray-800 rounded font-semibold text-[10px] text-gray-300 transition"
                  >
                    Print PDF
                  </button>
                </div>

              </div>
            ) : (
              <div className="flex flex-col items-center justify-center min-h-[350px] text-center space-y-2.5">
                <Layers className="text-gray-600 w-8 h-8" />
                <span className="text-xs font-bold text-gray-400">Select Posture Report</span>
                <p className="text-[10px] text-gray-550 max-w-xs leading-normal">
                  Select a generated executive, technical, or compliance review document from the library list to preview posture logs, priorities, and export PDFs.
                </p>
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-6 max-w-md w-full space-y-5">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h3 className="font-bold text-white text-sm">Generate Posture Assessment</h3>
              <button onClick={() => setShowGenerateModal(false)} className="text-gray-500 hover:text-white">
                <X size={14} />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block mb-2">Report Template</label>
                <div className="grid grid-cols-3 gap-2">
                  {(['EXECUTIVE', 'TECHNICAL', 'COMPLIANCE'] as const).map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setGenerateType(t)}
                      className={`px-3 py-2 border rounded-lg text-[10px] font-bold uppercase transition ${
                        generateType === t 
                          ? 'border-indigo-500 text-indigo-400 bg-indigo-500/5' 
                          : 'border-gray-800 text-gray-400 hover:bg-gray-850/50'
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>

              <div className="p-3 bg-[#0b0f19] border border-gray-850 rounded-lg flex items-start gap-2.5">
                <Brain className="text-indigo-400 shrink-0 w-4 h-4 mt-0.5" />
                <p className="text-[10px] text-gray-450 leading-relaxed">
                  Aegivion AI Report Engine will compile findings, incidents, and CIS mapping results from the current active cloud scan snapshot.
                </p>
              </div>
            </div>

            <div className="flex justify-end gap-2 border-t border-gray-800 pt-4">
              <button
                type="button"
                onClick={() => setShowGenerateModal(false)}
                className="px-4 py-2 border border-gray-800 hover:bg-gray-850 text-gray-300 rounded-lg text-[10px] font-semibold transition"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => generateMutation.mutate(generateType)}
                disabled={generateMutation.isPending}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-[10px] font-semibold transition flex items-center gap-1"
              >
                {generateMutation.isPending && <RotateCw size={10} className="animate-spin" />}
                Generate Report
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
export default ReportsPage;
