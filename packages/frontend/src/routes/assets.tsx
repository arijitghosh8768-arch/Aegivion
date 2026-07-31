import React, { useState, useEffect } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { Search, Download, Plus } from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/assets',
  component: AssetsPage,
});

function AssetsPage() {
  const [filterType, setFilterType] = useState('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [providerFilter, setProviderFilter] = useState('All');
  const [assetsList, setAssetsList] = useState([]);

  const fetchAssets = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/v1/findings/assets');
      const data = await res.json();
      setAssetsList(data.assets || []);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  // Baseline data if API database is not populated
  const defaultAssets = [
    { name: 'prod-api-gateway-01', id: 'i-8af12c9d', type: 'EC2', provider: 'AWS', region: 'us-east-1', account: 'aegivion-prod', risk: 'Critical', riskColor: 'bg-red-500/20 text-red-400 border-red-500/30', exposure: 'Internet-facing', expColor: 'text-red-500 font-semibold' },
    { name: 'prod-worker-04', id: 'i-0bb77c21', type: 'EC2', provider: 'AWS', region: 'us-east-1', account: 'aegivion-prod', risk: 'Medium', riskColor: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', exposure: 'Internal', expColor: 'text-gray-400' },
    { name: 'customer-exports', id: 's3-cust-exports', type: 'S3', provider: 'AWS', region: 'us-east-1', account: 'aegivion-data', risk: 'Critical', riskColor: 'bg-red-500/20 text-red-400 border-red-500/30', exposure: 'Internet-facing', expColor: 'text-red-500 font-semibold' },
    { name: 'build-cache', id: 's3-build-cache', type: 'S3', provider: 'AWS', region: 'eu-west-1', account: 'aegivion-staging', risk: 'Low', riskColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30', exposure: 'Internal', expColor: 'text-gray-400' },
    { name: 'deploy-automation', id: 'iam-deploy', type: 'IAM', provider: 'AWS', region: 'global', account: 'aegivion-prod', risk: 'High', riskColor: 'bg-orange-500/20 text-orange-400 border-orange-500/30', exposure: 'Internal', expColor: 'text-gray-400' },
    { name: 'legacy-ci-user', id: 'iam-legacy', type: 'IAM', provider: 'AWS', region: 'global', account: 'aegivion-staging', risk: 'High', riskColor: 'bg-orange-500/20 text-orange-400 border-orange-500/30', exposure: 'Internal', expColor: 'text-gray-400' },
    { name: 'billing-postgres', id: 'rds-billing', type: 'RDS', provider: 'AWS', region: 'us-east-1', account: 'aegivion-prod', risk: 'High', riskColor: 'bg-orange-500/20 text-orange-400 border-orange-500/30', exposure: 'Internet-facing', expColor: 'text-red-500 font-semibold' },
    { name: 'reporting-mysql', id: 'rds-reporting', type: 'RDS', provider: 'Azure', region: 'westeurope', account: 'corp-analytics', risk: 'Medium', riskColor: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', exposure: 'Internal', expColor: 'text-gray-400' },
    { name: 'sg-public-ssh', id: 'sg-public-ssh', type: 'Security Group', provider: 'AWS', region: 'us-east-1', account: 'aegivion-prod', risk: 'Critical', riskColor: 'bg-red-500/20 text-red-400 border-red-500/30', exposure: 'Internet-facing', expColor: 'text-red-500 font-semibold' },
    { name: 'sg-internal-mesh', id: 'sg-internal', type: 'Security Group', provider: 'GCP', region: 'us-central1', account: 'ml-platform', risk: 'Low', riskColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30', exposure: 'Internal', expColor: 'text-gray-400' },
    { name: 'ml-training-node-7', id: 'i-ecc89fa1', type: 'EC2', provider: 'GCP', region: 'us-central1', account: 'ml-platform', risk: 'Medium', riskColor: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', exposure: 'Internal', expColor: 'text-gray-400' },
    { name: 'model-weights', id: 's3-model-weights', type: 'S3', provider: 'GCP', region: 'us-central1', account: 'ml-platform', risk: 'Medium', riskColor: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', exposure: 'Internal', expColor: 'text-gray-400' }
  ];

  const currentAssets = assetsList.length > 0 ? assetsList.map((a: any) => {
    // Map database structures to fit representation
    const matchingDefault = defaultAssets.find(d => a.resource_id.includes(d.name) || d.id === a.resource_id);
    return {
      name: matchingDefault ? matchingDefault.name : a.resource_id.split(':').pop(),
      id: a.resource_id,
      type: a.type.replace('aws_', '').toUpperCase(),
      provider: a.provider,
      region: a.region,
      account: matchingDefault ? matchingDefault.account : 'aegivion-prod',
      risk: matchingDefault ? matchingDefault.risk : 'Low',
      riskColor: matchingDefault ? matchingDefault.riskColor : 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      exposure: matchingDefault ? matchingDefault.exposure : 'Internal',
      expColor: matchingDefault ? matchingDefault.expColor : 'text-gray-400'
    };
  }) : defaultAssets;

  const tabs = ['All', 'EC2', 'S3', 'IAM', 'RDS', 'Security Group'];

  const filteredAssets = currentAssets.filter(asset => {
    const matchesTab = filterType === 'All' || 
      asset.type.toLowerCase().replace(/_/g, ' ').includes(filterType.toLowerCase().replace(/_/g, ' '));
    const matchesSearch = asset.name.toLowerCase().includes(searchQuery.toLowerCase()) || asset.id.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesProvider = providerFilter === 'All' || asset.provider.toLowerCase() === providerFilter.toLowerCase();
    return matchesTab && matchesSearch && matchesProvider;
  });

  return (
    <div className="space-y-6 text-gray-200">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Assets</h1>
          <p className="text-gray-400 text-sm mt-1">{currentAssets.length} discovered resources across AWS, Azure and GCP.</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="px-4 py-2 border border-gray-800 bg-[#0d1326] text-gray-300 rounded-lg text-sm hover:text-white transition flex items-center gap-2">
            <Download size={14} />
            Export
          </button>
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition flex items-center gap-2">
            <Plus size={16} />
            Add source
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 pt-2">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setFilterType(tab)}
            className={`px-4 py-1.5 rounded-lg text-xs font-semibold border transition ${
              filterType === tab 
                ? 'bg-white text-gray-900 border-white' 
                : 'bg-[#0d1326]/60 text-gray-400 border-gray-800 hover:text-white'
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Search and Filters */}
      <div className="flex gap-4 items-center justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 text-gray-500" size={16} />
          <input
            type="text"
            placeholder="Filter by name or resource ID"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#0d1326] border border-gray-800 rounded-lg pl-9 pr-4 py-2 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-gray-700 transition"
          />
        </div>
        <select
          value={providerFilter}
          onChange={(e) => setProviderFilter(e.target.value)}
          className="bg-[#0d1326] border border-gray-800 text-xs text-gray-300 rounded-lg px-3 py-2 focus:outline-none focus:border-gray-700"
        >
          <option value="All">All providers</option>
          <option value="AWS">AWS</option>
          <option value="Azure">Azure</option>
          <option value="GCP">GCP</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-gray-300">
            <thead className="bg-[#0d1326] text-gray-400 uppercase text-[10px] tracking-wider font-semibold border-b border-gray-800">
              <tr>
                <th className="px-6 py-4">Resource</th>
                <th className="px-6 py-4">Type</th>
                <th className="px-6 py-4">Provider</th>
                <th className="px-6 py-4">Region</th>
                <th className="px-6 py-4">Account</th>
                <th className="px-6 py-4">Risk</th>
                <th className="px-6 py-4">Exposure</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/65">
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-gray-500">No matching assets found.</td>
                </tr>
              ) : (
                filteredAssets.map((asset, idx) => (
                  <tr key={idx} className="hover:bg-gray-800/10 transition">
                    <td className="px-6 py-3.5">
                      <div className="font-semibold text-white text-sm">{asset.name}</div>
                      <div className="text-[10px] text-gray-500 font-mono mt-0.5">{asset.id}</div>
                    </td>
                    <td className="px-6 py-3.5 font-medium text-gray-400">{asset.type}</td>
                    <td className="px-6 py-3.5 text-gray-400">{asset.provider}</td>
                    <td className="px-6 py-3.5 text-gray-400">{asset.region}</td>
                    <td className="px-6 py-3.5 text-gray-400">{asset.account}</td>
                    <td className="px-6 py-3.5">
                      <span className={`px-2 py-0.5 border text-[10px] font-bold rounded ${asset.riskColor}`}>
                        {asset.risk}
                      </span>
                    </td>
                    <td className={`px-6 py-3.5 ${asset.expColor}`}>{asset.exposure}</td>
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
