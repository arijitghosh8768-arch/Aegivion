import React, { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { Plus, FileText, Download } from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/reports',
  component: ReportsPage,
});

function ReportsPage() {
  const [reports, setReports] = useState([
    { name: 'Executive Security Posture — April', type: 'Executive', typeColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20', date: 'Apr 05, 2026', pages: 12 },
    { name: 'SOC 2 Type II Evidence Pack', type: 'Compliance', typeColor: 'bg-green-500/10 text-green-400 border-green-500/20', date: 'Apr 02, 2026', pages: 48 },
    { name: 'Critical Findings Deep Dive', type: 'Technical', typeColor: 'bg-purple-500/10 text-purple-400 border-purple-500/20', date: 'Mar 29, 2026', pages: 26 },
    { name: 'Cloud Attack Surface Review', type: 'Technical', typeColor: 'bg-purple-500/10 text-purple-400 border-purple-500/20', date: 'Mar 22, 2026', pages: 19 }
  ]);

  const handleGenerate = (type: 'Executive' | 'Technical') => {
    const newReport = {
      name: `${type} Security Report — ${new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric' })}`,
      type: type,
      typeColor: type === 'Executive' 
        ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' 
        : 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      date: new Date().toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' }),
      pages: Math.floor(Math.random() * 30) + 10
    };
    setReports(prev => [newReport, ...prev]);
  };

  return (
    <div className="space-y-6 text-gray-200 pb-10">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Reports</h1>
          <p className="text-gray-400 text-sm mt-1">Executive and technical reporting for leadership and auditors.</p>
        </div>
        <button 
          onClick={() => handleGenerate('Executive')}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition flex items-center gap-2"
        >
          <Plus size={16} />
          New report
        </button>
      </div>

      {/* Row 1 cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-44">
          <div>
            <h3 className="font-bold text-white text-sm">Executive report</h3>
            <p className="text-xs text-gray-500 mt-2 leading-relaxed">
              Board-ready posture summary, risk trend and top remediation wins.
            </p>
          </div>
          <button 
            onClick={() => handleGenerate('Executive')}
            className="w-fit px-4 py-2 bg-gray-850 hover:bg-gray-800 text-white border border-gray-800 rounded-lg text-xs font-semibold transition"
          >
            Generate
          </button>
        </div>

        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-44">
          <div>
            <h3 className="font-bold text-white text-sm">Technical report</h3>
            <p className="text-xs text-gray-500 mt-2 leading-relaxed">
              Full finding detail, affected resources and remediation runbooks.
            </p>
          </div>
          <button 
            onClick={() => handleGenerate('Technical')}
            className="w-fit px-4 py-2 bg-gray-850 hover:bg-gray-800 text-white border border-gray-800 rounded-lg text-xs font-semibold transition"
          >
            Generate
          </button>
        </div>
      </div>

      {/* Report library */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 space-y-4">
        <div>
          <h3 className="text-sm font-semibold text-white">Report library</h3>
          <p className="text-xs text-gray-500">Previously generated documents</p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-gray-300">
            <thead className="bg-[#0d1326] text-gray-400 uppercase text-[10px] tracking-wider font-semibold border-b border-gray-800">
              <tr>
                <th className="px-6 py-4">Report</th>
                <th className="px-6 py-4">Type</th>
                <th className="px-6 py-4">Generated</th>
                <th className="px-6 py-4">Pages</th>
                <th className="px-6 py-4 text-right">Export</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/65">
              {reports.map((rep, idx) => (
                <tr key={idx} className="hover:bg-gray-800/10 transition">
                  <td className="px-6 py-4 flex items-center gap-3">
                    <FileText size={16} className="text-gray-500 shrink-0" />
                    <span className="font-semibold text-white">{rep.name}</span>
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-0.5 border text-[10px] rounded font-semibold ${rep.typeColor}`}>
                      {rep.type}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-gray-400">{rep.date}</td>
                  <td className="px-6 py-4 text-gray-400">{rep.pages}</td>
                  <td className="px-6 py-4 text-right space-x-3">
                    <button className="text-gray-400 hover:text-white inline-flex items-center gap-1">
                      <Download size={12} />
                      PDF
                    </button>
                    <button className="text-gray-400 hover:text-white inline-flex items-center gap-1">
                      <Download size={12} />
                      MD
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
