import React, { useState, useEffect } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import { useQuery } from '@tanstack/react-query';
import { 
  Search, 
  Download, 
  RotateCw, 
  X, 
  ChevronRight,
  Database,
  ShieldAlert,
  SlidersHorizontal,
  History,
  Info,
  Layers,
  ArrowRightLeft
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/assets',
  component: AssetsPage,
});

interface Relationship {
  type: string;
  target_id: string;
  target_type: string;
}

interface Asset {
  id: string;
  resource_id: string;
  name: string;
  type: string;
  region: string;
  provider: string;
  configuration?: Record<string, any>;
  relationships?: Relationship[];
  findings_count?: number;
  risk_score?: number;
}

interface HistoricalVersion {
  version_number: number;
  configuration: Record<string, any>;
  configuration_hash: string;
  scan_id: string;
  created_at: string;
}

function AssetsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedProvider, setSelectedProvider] = useState('All');
  const [selectedType, setSelectedType] = useState('All');
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'config' | 'relationships' | 'history'>('overview');
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);

  // M1/M4: Query Asset History versions dynamically
  const { data: historyData, isLoading: historyLoading } = useQuery<{ asset_id: string; versions: HistoricalVersion[] }>({
    queryKey: ['asset-history', selectedAsset?.resource_id],
    queryFn: async () => {
      const res = await api.get(`/v1/history/${selectedAsset?.resource_id}/history`);
      return res.data;
    },
    enabled: !!selectedAsset
  });

  const fetchAssets = async () => {
    try {
      setLoading(true);
      const res = await api.get('/v1/findings/assets');
      if (res.data && res.data.assets) {
        setAssets(res.data.assets);
      }
    } catch (e) {
      console.error(e);
      // Fallback base data for development representation
      setAssets([
        {
          id: '1',
          resource_id: 'i-0abcdef1234567890',
          name: 'production-web-server',
          type: 'EC2',
          region: 'ap-south-1',
          provider: 'aws',
          configuration: {
            state: 'running',
            instance_type: 't3.medium',
            public_ip: '54.210.12.34',
            private_ip: '10.0.1.4',
            vpc_id: 'vpc-09ab12cd',
            security_groups: ['sg-01ffbcde12']
          },
          relationships: [
            { type: 'located_in', target_id: 'vpc-09ab12cd', target_type: 'vpc' },
            { type: 'protected_by', target_id: 'sg-01ffbcde12', target_type: 'security_group' }
          ],
          findings_count: 1,
          risk_score: 92
        },
        {
          id: '2',
          resource_id: 's3-customer-exports',
          name: 'aegivion-customer-data-bucket',
          type: 'S3_BUCKET',
          region: 'ap-south-1',
          provider: 'aws',
          configuration: {
            is_public: true,
            encryption_enabled: false,
            versioning_enabled: false
          },
          relationships: [],
          findings_count: 2,
          risk_score: 85
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
    const interval = setInterval(fetchAssets, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleSyncNow = () => {
    setSyncing(true);
    fetchAssets().finally(() => setSyncing(false));
  };

  const getRiskBadge = (score: number) => {
    if (score >= 80) return 'bg-red-500/10 text-red-400 border-red-500/20';
    if (score >= 40) return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
    if (score >= 20) return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    return 'bg-green-500/10 text-green-400 border-green-500/20';
  };

  const filteredAssets = assets.filter(asset => {
    const matchesSearch = asset.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
                           asset.resource_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesProvider = selectedProvider === 'All' || asset.provider.toLowerCase() === selectedProvider.toLowerCase();
    const matchesType = selectedType === 'All' || asset.type.toLowerCase().includes(selectedType.toLowerCase());
    return matchesSearch && matchesProvider && matchesType;
  });

  return (
    <div className="space-y-6 text-gray-200 relative min-h-screen pb-10">
      
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Asset Inventory</h1>
          <p className="text-gray-400 text-sm mt-1">Discovered cloud resources across connected accounts.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={handleSyncNow}
            disabled={syncing}
            className="px-4 py-2 border border-gray-800 bg-[#0d1326] text-gray-300 rounded-lg text-xs hover:text-white transition flex items-center gap-2"
          >
            <RotateCw size={14} className={syncing ? 'animate-spin' : ''} />
            Sync Now
          </button>
        </div>
      </div>

      {/* Toolbar filters */}
      <div className="flex flex-wrap gap-4 items-center justify-between bg-[#0e1428] border border-gray-850 p-4 rounded-xl">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3.5 top-3 text-gray-500" size={14} />
          <input
            type="text"
            placeholder="Search by asset name, IP, or resource ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#0b0f19] border border-gray-800 rounded-xl pl-10 pr-4 py-2 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-gray-700 transition"
          />
        </div>
        
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Provider:</span>
            <select
              value={selectedProvider}
              onChange={(e) => setSelectedProvider(e.target.value)}
              className="bg-[#0b0f19] border border-gray-800 text-xs text-gray-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-gray-750"
            >
              <option value="All">All Providers</option>
              <option value="AWS">AWS</option>
              <option value="Azure">Azure</option>
              <option value="GCP">GCP</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Type:</span>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="bg-[#0b0f19] border border-gray-800 text-xs text-gray-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-gray-750"
            >
              <option value="All">All Types</option>
              <option value="EC2">EC2 Instance</option>
              <option value="S3">S3 Bucket</option>
              <option value="Security Group">Security Group</option>
            </select>
          </div>
        </div>
      </div>

      {/* Asset Table */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-gray-300">
            <thead className="bg-[#0d1326] text-gray-400 uppercase text-[9px] tracking-wider font-semibold border-b border-gray-800">
              <tr>
                <th className="px-6 py-4">Resource</th>
                <th className="px-6 py-4">Type</th>
                <th className="px-6 py-4">Provider / Region</th>
                <th className="px-6 py-4">Risk Score</th>
                <th className="px-6 py-4">Findings</th>
                <th className="px-6 py-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {loading ? (
                <tr>
                  <td colSpan={6} className="text-center py-10 text-gray-500">Loading asset database...</td>
                </tr>
              ) : filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-10 text-gray-500">No matching assets found.</td>
                </tr>
              ) : (
                filteredAssets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-gray-800/10 transition group">
                    <td className="px-6 py-4">
                      <div className="font-semibold text-white text-sm">{asset.name}</div>
                      <div className="text-[10px] text-gray-500 font-mono mt-0.5">{asset.resource_id}</div>
                    </td>
                    <td className="px-6 py-4 font-medium text-gray-400 capitalize">{asset.type.replace('_', ' ')}</td>
                    <td className="px-6 py-4 text-gray-400 capitalize">
                      <span className="font-semibold">{asset.provider}</span> ({asset.region})
                    </td>
                    <td className="px-6 py-4">
                      <span className={`px-2 py-0.5 border text-[10px] font-bold rounded ${getRiskBadge(asset.risk_score || 0)}`}>
                        {asset.risk_score || 0} / 100
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      {asset.findings_count && asset.findings_count > 0 ? (
                        <span className="text-red-400 font-bold flex items-center gap-1.5">
                          <ShieldAlert size={14} />
                          {asset.findings_count}
                        </span>
                      ) : (
                        <span className="text-green-400">Compliant</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <button 
                        onClick={() => { setSelectedAsset(asset); setActiveTab('overview'); }}
                        className="px-2.5 py-1 text-xs text-blue-400 hover:text-white bg-blue-600/5 hover:bg-blue-600 rounded border border-blue-500/20 transition flex items-center gap-1 ml-auto"
                      >
                        Details
                        <ChevronRight size={12} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Details Side Drawer */}
      {selectedAsset && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-all">
          <div className="w-full max-w-lg bg-[#0d1326] border-l border-gray-800 h-full flex flex-col justify-between shadow-2xl relative">
            
            {/* Drawer Header */}
            <div className="p-6 border-b border-gray-800 flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-white leading-snug">{selectedAsset.name}</h2>
                <span className="text-[10px] text-gray-550 font-mono block mt-0.5">{selectedAsset.resource_id}</span>
              </div>
              <button 
                onClick={() => setSelectedAsset(null)}
                className="p-1.5 hover:bg-gray-800 text-gray-400 hover:text-white rounded-lg transition"
              >
                <X size={18} />
              </button>
            </div>

            {/* Tabs Selector */}
            <div className="flex border-b border-gray-800 px-6 bg-[#0e1428]">
              {(['overview', 'config', 'relationships', 'history'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`py-3 px-4 text-xs font-semibold uppercase tracking-wider border-b-2 transition ${
                    activeTab === tab 
                      ? 'border-blue-500 text-white' 
                      : 'border-transparent text-gray-400 hover:text-white'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            {/* Drawer Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 space-y-4">
                    <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Database size={13} className="text-blue-500" />
                      Resource Metadata
                    </h4>
                    <div className="grid grid-cols-2 gap-4 text-xs">
                      <div>
                        <span className="text-gray-500 block">Cloud Provider</span>
                        <span className="font-semibold text-white uppercase">{selectedAsset.provider}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Region</span>
                        <span className="font-semibold text-white">{selectedAsset.region}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Type</span>
                        <span className="font-semibold text-white">{selectedAsset.type}</span>
                      </div>
                      <div>
                        <span className="text-gray-500 block">Risk Rating</span>
                        <span className="font-semibold text-white">{selectedAsset.risk_score || 0}/100</span>
                      </div>
                    </div>
                  </div>

                  {selectedAsset.configuration && (
                    <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 space-y-4">
                      <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                        <SlidersHorizontal size={13} className="text-blue-500" />
                        Status & Networking
                      </h4>
                      <div className="grid grid-cols-2 gap-4 text-xs">
                        {Object.entries(selectedAsset.configuration).slice(0, 4).map(([key, val]) => (
                          <div key={key}>
                            <span className="text-gray-500 block capitalize">{key.replace('_', ' ')}</span>
                            <span className="font-semibold text-white">{String(val)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'config' && (
                <div className="space-y-3">
                  <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Raw Asset Configuration</h4>
                  <pre className="bg-[#0b0f19] border border-gray-850 rounded-xl p-4 text-[10px] font-mono text-blue-400 overflow-x-auto">
                    {JSON.stringify(selectedAsset.configuration || {}, null, 2)}
                  </pre>
                </div>
              )}

              {activeTab === 'relationships' && (
                <div className="space-y-4">
                  <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Discovered Relationships</h4>
                  {selectedAsset.relationships && selectedAsset.relationships.length > 0 ? (
                    <div className="space-y-2">
                      {selectedAsset.relationships.map((rel, idx) => (
                        <div key={idx} className="bg-[#0e1428] border border-gray-850 rounded-xl p-3.5 flex items-center justify-between text-xs">
                          <div>
                            <span className="text-gray-500 block">Relation</span>
                            <span className="font-semibold text-white capitalize">{rel.type.replace('_', ' ')}</span>
                          </div>
                          <div className="text-right">
                            <span className="text-gray-500 block capitalize">{rel.target_type}</span>
                            <span className="font-mono text-blue-400">{rel.target_id}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-gray-500">No relationships mapped for this resource.</p>
                  )}
                </div>
              )}

              {activeTab === 'history' && (
                <div className="space-y-4">
                  <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                    <History size={14} className="text-blue-500" />
                    Asset Configuration Drift Timeline
                  </h4>

                  {historyLoading ? (
                    <div className="flex justify-center py-10">
                      <RotateCw className="w-6 h-6 text-indigo-500 animate-spin" />
                    </div>
                  ) : historyData?.versions && historyData.versions.length > 0 ? (
                    <div className="space-y-4 relative pl-4 border-l border-gray-800">
                      {historyData.versions.map((ver, idx) => (
                        <div key={idx} className="relative space-y-1.5 pb-2">
                          <div className="absolute -left-[21px] top-1 bg-indigo-600 rounded-full w-2.5 h-2.5 border-2 border-indigo-400"></div>
                          <div className="flex justify-between items-center text-[10px]">
                            <span className="font-bold text-indigo-400">VERSION #{ver.version_number}</span>
                            <span className="text-gray-500">{new Date(ver.created_at).toLocaleString()}</span>
                          </div>
                          <div className="p-3 bg-[#0e1428] border border-gray-850 rounded-xl space-y-2">
                            <div className="flex justify-between text-[9px] text-gray-400">
                              <span>Scan Target: {ver.scan_id}</span>
                              <span className="font-mono text-gray-500 truncate max-w-[150px]">Hash: {ver.configuration_hash.slice(0, 12)}</span>
                            </div>
                            <pre className="bg-[#0b0f19] border border-gray-850 rounded p-2 text-[9px] font-mono text-indigo-300 overflow-x-auto">
                              {JSON.stringify(ver.configuration, null, 2)}
                            </pre>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-gray-500">No configuration version drift has occurred yet.</p>
                  )}
                </div>
              )}
            </div>

            {/* Drawer Footer */}
            <div className="p-6 border-t border-gray-800 bg-[#0e1428] flex items-center justify-between text-xs">
              <span className="text-gray-500">Discovered in sync inventory.</span>
              <button 
                onClick={() => setSelectedAsset(null)}
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
export default AssetsPage;
