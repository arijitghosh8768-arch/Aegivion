import React from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { FileText, CheckCircle2, XCircle } from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer 
} from 'recharts';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/compliance',
  component: CompliancePage,
});

function CompliancePage() {
  const trendData = [
    { name: 'Nov', score: 65 },
    { name: 'Dec', score: 70 },
    { name: 'Jan', score: 74 },
    { name: 'Feb', score: 80 },
    { name: 'Mar', score: 84 },
    { name: 'Apr', score: 87 },
  ];

  const frameworks = [
    {
      title: 'SOC 2 Type II',
      passed: 118,
      failed: 12,
      percent: 91,
      items: [
        { status: 'fail', code: 'cc6.1', label: 'Logical access controls' },
        { status: 'fail', code: 'cc6.6', label: 'Encryption of data at rest' },
        { status: 'pass', code: 'cc7.2', label: 'Security event monitoring' }
      ]
    },
    {
      title: 'CIS AWS Benchmark v3',
      passed: 148,
      failed: 28,
      percent: 84,
      items: [
        { status: 'pass', code: '1.12', label: 'No root account access keys' },
        { status: 'fail', code: '4.1', label: 'No 0.0.0.0/0 ingress on port 22' },
        { status: 'fail', code: '2.1.5', label: 'S3 block public access enabled' }
      ]
    },
    {
      title: 'ISO 27001:2022',
      passed: 82,
      failed: 11,
      percent: 88,
      items: [
        { status: 'fail', code: 'A.8.12', label: 'Data leakage prevention' },
        { status: 'pass', code: 'A.5.15', label: 'Access control' },
        { status: 'fail', code: 'A.8.24', label: 'Use of cryptography' }
      ]
    },
    {
      title: 'PCI DSS 4.0',
      passed: 96,
      failed: 26,
      percent: 79,
      items: [
        { status: 'fail', code: '1.2.1', label: 'Restrict inbound traffic' },
        { status: 'pass', code: '3.5.1', label: 'Render PAN unreadable' },
        { status: 'fail', code: '7.2.1', label: 'Least privilege access model' }
      ]
    }
  ];

  return (
    <div className="space-y-6 text-gray-200 pb-10">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Compliance</h1>
          <p className="text-gray-400 text-sm mt-1">Control coverage across four active frameworks.</p>
        </div>
        <button className="px-4 py-2 border border-gray-800 bg-[#0d1326] text-gray-300 rounded-lg text-sm hover:text-white transition flex items-center gap-2">
          <FileText size={16} />
          Evidence pack
        </button>
      </div>

      {/* Compliance Trend Chart */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5">
        <div className="mb-4">
          <h3 className="text-sm font-semibold text-white">Compliance trend</h3>
          <p className="text-xs text-gray-500">Weighted score across all frameworks</p>
        </div>
        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" stroke="#6b7280" fontSize={11} tickLine={false} />
              <YAxis stroke="#6b7280" fontSize={11} tickLine={false} domain={[50, 100]} />
              <Tooltip contentStyle={{ backgroundColor: '#0d1326', borderColor: '#1f2937' }} />
              <Area type="monotone" dataKey="score" stroke="#10b981" fill="#10b981" fillOpacity={0.08} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Frameworks Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {frameworks.map((fw, idx) => (
          <div key={idx} className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 space-y-4">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="font-bold text-white text-sm">{fw.title}</h3>
                <span className="text-xs text-gray-500 mt-1 block">
                  {fw.passed} passed &middot; {fw.failed} failed
                </span>
              </div>
              <span className="text-xl font-extrabold text-white">{fw.percent}%</span>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-gray-850 h-2 rounded-full overflow-hidden">
              <div className="bg-blue-500 h-full rounded-full" style={{ width: `${fw.percent}%` }}></div>
            </div>

            {/* Control items list */}
            <div className="space-y-2 pt-2 border-t border-gray-800/80">
              {fw.items.map((item, itemIdx) => (
                <div key={itemIdx} className="flex items-center gap-3 text-xs">
                  {item.status === 'pass' ? (
                    <CheckCircle2 className="text-green-500 shrink-0" size={14} />
                  ) : (
                    <XCircle className="text-red-500 shrink-0" size={14} />
                  )}
                  <span className="font-mono text-gray-400 shrink-0">{item.code}</span>
                  <span className="text-gray-300 truncate">{item.label}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
