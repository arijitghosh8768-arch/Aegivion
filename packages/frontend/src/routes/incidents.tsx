import React, { useState } from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { 
  ShieldAlert, 
  RotateCw, 
  Search, 
  SlidersHorizontal, 
  AlertTriangle,
  Info,
  Clock
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/incidents',
  component: IncidentsPage,
});

interface Incident {
  incident_id: str;
  id: string;
  title: string;
  severity: string;
  risk_score: number;
  affected_assets_count: number;
  findings_count: number;
  status: string;
  account_id: string;
  region: string;
  updated_at: string;
}

function IncidentsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('All');
  const [selectedStatus, setSelectedStatus] = useState('All');
  const [selectedRegion, setSelectedRegion] = useState('All');

  // Query incidents from backend
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['incidents'],
    queryFn: async () => {
      const res = await api.get('/v1/incidents');
      return res.data;
    }
  });

  const rawIncidents: Incident[] = data?.incidents || [];

  // Filter logic
  const filteredIncidents = rawIncidents.filter(inc => {
    const matchesSearch = inc.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          inc.incident_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = selectedSeverity === 'All' || inc.severity.toLowerCase() === selectedSeverity.toLowerCase();
    const matchesStatus = selectedStatus === 'All' || inc.status.toLowerCase() === selectedStatus.toLowerCase();
    const matchesRegion = selectedRegion === 'All' || inc.region.toLowerCase() === selectedRegion.toLowerCase();
    return matchesSearch && matchesSeverity && matchesStatus && matchesRegion;
  });

  // KPI Calculations
  const totalCount = rawIncidents.length;
  const criticalCount = rawIncidents.filter(i => i.severity.toLowerCase() === 'critical').length;
  const highCount = rawIncidents.filter(i => i.severity.toLowerCase() === 'high').length;
  const openCount = rawIncidents.filter(i => i.status.toLowerCase() === 'open').length;

  const getSeverityBadge = (severity: string) => {
    const sev = severity.toLowerCase();
    if (sev === 'critical') return 'bg-red-500/10 text-red-400 border-red-500/20';
    if (sev === 'high') return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    if (sev === 'medium') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
  };

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <ShieldAlert size={22} className="text-red-500" />
            Security Incidents
          </h1>
          <p className="text-gray-400 text-sm mt-1">Correlated security risks requiring prioritization and response.</p>
        </div>
        <button 
          onClick={() => refetch()}
          className="px-4 py-2 bg-blue-600/10 border border-blue-500/20 text-blue-400 hover:text-white hover:bg-blue-600 rounded-lg text-xs font-semibold transition flex items-center gap-1.5"
        >
          <RotateCw size={14} className={isLoading ? 'animate-spin' : ''} />
          Sync Incidents
        </button>
      </div>

      {/* Warning of partial scan coverage */}
      <div className="p-4 bg-yellow-950/20 border border-yellow-900/30 rounded-xl flex items-start gap-3">
        <AlertTriangle className="text-yellow-500 shrink-0 w-5 h-5" />
        <div>
          <h4 className="text-xs font-bold text-yellow-400">Assessment coverage warning</h4>
          <p className="text-[11px] text-gray-400 mt-0.5">
            Cloud scans have partial collector coverage. Incident correlation graphs may omit hidden cross-account attack vectors.
          </p>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Critical Risks</span>
          <span className="text-2xl font-extrabold text-red-400 mt-2 block">{criticalCount}</span>
        </div>
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">High Severity</span>
          <span className="text-2xl font-extrabold text-orange-400 mt-2 block">{highCount}</span>
        </div>
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Active Open</span>
          <span className="text-2xl font-extrabold text-blue-400 mt-2 block">{openCount}</span>
        </div>
        <div className="p-5 bg-[#0e1428] border border-gray-850 rounded-xl">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Total Correlated</span>
          <span className="text-2xl font-extrabold text-white mt-2 block">{totalCount}</span>
        </div>
      </div>

      {/* Filters and search */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search incidents..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-blue-500 transition"
          />
        </div>
        
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <SlidersHorizontal size={12} className="text-gray-500" />
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-3 py-1.5 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="px-3 py-1.5 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Statuses</option>
              <option value="open">Open</option>
              <option value="closed">Closed</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <select
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
              className="px-3 py-1.5 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Regions</option>
              <option value="ap-south-1">ap-south-1</option>
              <option value="us-east-1">us-east-1</option>
            </select>
          </div>
        </div>
      </div>

      {/* Incidents Table */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <RotateCw className="w-8 h-8 text-blue-500 animate-spin" />
        </div>
      ) : isError ? (
        <div className="text-center py-16 text-red-400 text-xs bg-red-950/10 border border-red-900/20 rounded-xl">
          Failed to load security incidents. Please check connection to local API server.
        </div>
      ) : filteredIncidents.length === 0 ? (
        <div className="text-center py-16 text-gray-500 text-xs bg-[#0e1428] border border-gray-850 rounded-xl">
          No correlated security incidents found.
        </div>
      ) : (
        <div className="bg-[#0e1428] border border-gray-850 rounded-xl overflow-hidden">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-gray-800 bg-[#0b0f19]/35 text-[10px] text-gray-500 uppercase tracking-wider font-bold">
                <th className="py-3 px-5">Severity</th>
                <th className="py-3 px-5">Incident</th>
                <th className="py-3 px-5 text-center">Risk Score</th>
                <th className="py-3 px-5 text-center">Assets Affected</th>
                <th className="py-3 px-5 text-center">Findings</th>
                <th className="py-3 px-5">Region</th>
                <th className="py-3 px-5">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-y-gray-800/40 text-xs">
              {filteredIncidents.map((inc) => (
                <tr key={inc.id} className="hover:bg-gray-850/20 transition">
                  <td className="py-4 px-5">
                    <span className={`px-2.5 py-0.5 border text-[9px] font-bold rounded-full uppercase ${getSeverityBadge(inc.severity)}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="py-4 px-5">
                    <div className="font-semibold text-white leading-normal">
                      <Link to="/incidents/$incidentId" params={{ incidentId: inc.id }} className="hover:underline hover:text-blue-400 transition">
                        {inc.title}
                      </Link>
                    </div>
                    <div className="text-[10px] text-gray-550 mt-0.5 font-mono">{inc.incident_id}</div>
                  </td>
                  <td className="py-4 px-5 text-center font-bold text-red-400">
                    {inc.risk_score}/100
                  </td>
                  <td className="py-4 px-5 text-center text-gray-300">
                    {inc.affected_assets_count}
                  </td>
                  <td className="py-4 px-5 text-center text-gray-300">
                    {inc.findings_count}
                  </td>
                  <td className="py-4 px-5 font-mono text-gray-400">
                    {inc.region}
                  </td>
                  <td className="py-4 px-5">
                    <span className="px-2 py-0.5 border border-blue-900/30 text-blue-400 bg-blue-950/10 text-[9px] font-bold rounded capitalize">
                      {inc.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
