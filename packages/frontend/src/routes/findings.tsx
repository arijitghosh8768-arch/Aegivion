import React, { useState, useEffect } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { Search, SlidersHorizontal } from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/findings',
  component: FindingsPage,
});

function FindingsPage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [findingsList, setFindingsList] = useState([]);

  const fetchFindings = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/v1/findings');
      const data = await res.json();
      setFindingsList(data.findings || []);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, []);

  const defaultFindings = [
    { id: 'AEG-1041', finding: 'S3 bucket publicly readable with customer PII', severity: 'Critical', severityColor: 'bg-red-500/20 text-red-400 border-red-500/30', resource: 'customer-exports', category: 'Data Exposure', status: 'Open', statusColor: 'border-blue-500/30 text-blue-400 bg-blue-500/10', firstSeen: '2h ago' },
    { id: 'AEG-1039', finding: 'Security group allows 0.0.0.0/0 on port 22', severity: 'Critical', severityColor: 'bg-red-500/20 text-red-400 border-red-500/30', resource: 'sg-public-ssh', category: 'Network Exposure', status: 'In Progress', statusColor: 'border-yellow-500/30 text-yellow-400 bg-yellow-500/10', firstSeen: '6h ago' },
    { id: 'AEG-1032', finding: 'IAM user with unused administrator privileges', severity: 'High', severityColor: 'bg-orange-500/20 text-orange-400 border-orange-500/30', resource: 'legacy-ci-user', category: 'Identity', status: 'Open', statusColor: 'border-blue-500/30 text-blue-400 bg-blue-500/10', firstSeen: '1d ago' },
    { id: 'AEG-1020', finding: 'RDS instance publicly accessible', severity: 'High', severityColor: 'bg-orange-500/20 text-orange-400 border-orange-500/30', resource: 'billing-postgres', category: 'Network Exposure', status: 'Open', statusColor: 'border-blue-500/30 text-blue-400 bg-blue-500/10', firstSeen: '1d ago' },
    { id: 'AEG-1019', finding: 'Encryption at rest disabled on reporting database', severity: 'Medium', severityColor: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', resource: 'reporting-mysql', category: 'Encryption', status: 'In Progress', statusColor: 'border-yellow-500/30 text-yellow-400 bg-yellow-500/10', firstSeen: '3d ago' },
    { id: 'AEG-1007', finding: 'Object versioning disabled on build cache bucket', severity: 'Low', severityColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30', resource: 'build-cache', category: 'Resilience', status: 'Resolved', statusColor: 'border-green-500/30 text-green-400 bg-green-500/10', firstSeen: '6d ago' }
  ];

  const currentFindings = findingsList.length > 0 ? findingsList.map((f: any, index: number) => {
    const matchingDefault = defaultFindings.find(d => f.title.includes(d.resource) || d.finding === f.title);
    return {
      id: `AEG-10${40 + index}`,
      finding: f.title,
      severity: f.severity,
      severityColor: f.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                     f.severity === 'High' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                     f.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                     'bg-blue-500/20 text-blue-400 border-blue-500/30',
      resource: matchingDefault ? matchingDefault.resource : f.resource_id.split(':').pop(),
      category: matchingDefault ? matchingDefault.category : 'Config',
      status: 'Open',
      statusColor: 'border-blue-500/30 text-blue-400 bg-blue-500/10',
      firstSeen: matchingDefault ? matchingDefault.firstSeen : 'Just now'
    };
  }) : defaultFindings;

  const filteredFindings = currentFindings.filter(f => {
    const matchesSearch = f.finding.toLowerCase().includes(searchQuery.toLowerCase()) || f.id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = severityFilter === 'All' || f.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesStatus = statusFilter === 'All' || f.status.toLowerCase() === statusFilter.toLowerCase();
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="space-y-6 text-gray-200">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Findings</h1>
          <p className="text-gray-400 text-sm mt-1">Every open misconfiguration ranked by exploitability and blast radius.</p>
        </div>
        <button className="px-4 py-2 border border-gray-800 bg-[#0d1326] text-gray-300 rounded-lg text-sm hover:text-white transition flex items-center gap-2">
          <SlidersHorizontal size={16} />
          Saved views
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 items-center justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 text-gray-500" size={16} />
          <input
            type="text"
            placeholder="Search findings"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#0d1326] border border-gray-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-gray-700 transition"
          />
        </div>
        <div className="flex items-center gap-3">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#0d1326] border border-gray-800 text-xs text-gray-300 rounded-lg px-3 py-2 focus:outline-none"
          >
            <option value="All">All severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-[#0d1326] border border-gray-800 text-xs text-gray-300 rounded-lg px-3 py-2 focus:outline-none"
          >
            <option value="All">All statuses</option>
            <option value="Open">Open</option>
            <option value="In Progress">In Progress</option>
            <option value="Resolved">Resolved</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-gray-300">
            <thead className="bg-[#0d1326] text-gray-400 uppercase text-[10px] tracking-wider font-semibold border-b border-gray-800">
              <tr>
                <th className="px-6 py-4">ID</th>
                <th className="px-6 py-4">Finding</th>
                <th className="px-6 py-4">Severity</th>
                <th className="px-6 py-4">Resource</th>
                <th className="px-6 py-4">Category</th>
                <th className="px-6 py-4">Status</th>
                <th className="px-6 py-4">First seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/65">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-gray-500">No matching findings found.</td>
                </tr>
              ) : (
                filteredFindings.map((item, idx) => (
                  <tr key={idx} className="hover:bg-gray-800/10 transition">
                    <td className="px-6 py-4 font-semibold text-blue-400 font-mono">{item.id}</td>
                    <td className="px-6 py-4 font-semibold text-white max-w-xs">{item.finding}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-0.5 border text-[10px] font-bold rounded ${item.severityColor}`}>
                        {item.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 font-mono text-gray-400">{item.resource}</td>
                    <td className="px-6 py-4 text-gray-400">{item.category}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-0.5 border text-[10px] font-semibold rounded ${item.statusColor}`}>
                        {item.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-gray-500">{item.firstSeen}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
