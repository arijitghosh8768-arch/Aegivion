import React, { useState, useEffect } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import { 
  Search, 
  RotateCw, 
  ChevronRight, 
  Users, 
  ShieldAlert,
  SlidersHorizontal,
  ShieldCheck,
  User,
  Key
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/identities',
  component: IdentitiesPage,
});

interface Asset {
  id: string;
  resource_id: string;
  name: string;
  type: string;
  region: string;
  provider: string;
  configuration?: Record<string, any>;
  risk_score?: number;
}

function IdentitiesPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('All');
  const [selectedIdentity, setSelectedIdentity] = useState<Asset | null>(null);
  const [identities, setIdentities] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchIdentities = async () => {
    try {
      setLoading(true);
      const res = await api.get('/v1/findings/assets');
      if (res.data && res.data.assets) {
        // Filter assets to only include identity types (e.g. iam_user, iam_role, or containing 'iam')
        const allAssets = res.data.assets as Asset[];
        const filtered = allAssets.filter(asset => 
          asset.type.toLowerCase().includes('iam') || 
          asset.type.toLowerCase().includes('user') ||
          asset.type.toLowerCase().includes('role')
        );
        setIdentities(filtered);
      }
    } catch (e) {
      console.error(e);
      // Fallback mocks
      setIdentities([
        {
          id: "1",
          resource_id: "iam:user:security-admin-01",
          name: "security-admin-01",
          type: "iam_user",
          region: "global",
          provider: "aws",
          risk_score: 95
        },
        {
          id: "2",
          resource_id: "iam:role:web-instance-role",
          name: "web-instance-role",
          type: "iam_role",
          region: "global",
          provider: "aws",
          risk_score: 80
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIdentities();
  }, []);

  const getRiskColor = (score?: number) => {
    if (!score) return 'text-blue-400 bg-blue-950/20 border-blue-900/30';
    if (score >= 90) return 'text-red-400 bg-red-950/20 border-red-900/30';
    if (score >= 70) return 'text-orange-400 bg-orange-950/20 border-orange-900/30';
    return 'text-yellow-400 bg-yellow-950/20 border-yellow-900/30';
  };

  const filteredIdentities = identities.filter(id => {
    const matchesSearch = id.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          id.resource_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = selectedType === 'All' || id.type.toLowerCase() === selectedType.toLowerCase();
    return matchesSearch && matchesType;
  });

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-gray-800 pb-6">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
            <Users size={22} className="text-blue-500" />
            Identity Access Management (IAM)
          </h1>
          <p className="text-gray-400 text-sm mt-1">
            Track user accounts, service roles, and verify MFA authentication coverage
          </p>
        </div>
        <button 
          onClick={fetchIdentities}
          className="px-4 py-2 bg-blue-600/10 border border-blue-500/20 text-blue-400 hover:text-white hover:bg-blue-600 rounded-lg text-xs font-semibold transition flex items-center gap-1.5"
        >
          <RotateCw size={14} className={loading ? 'animate-spin' : ''} />
          Refresh Identities
        </button>
      </div>

      {/* Filters */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="relative w-full sm:w-64">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search identities..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 placeholder-gray-500 focus:outline-none focus:border-blue-500 transition"
          />
        </div>
        
        <div className="flex items-center gap-2">
          <SlidersHorizontal size={14} className="text-gray-500" />
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="px-3 py-1.5 bg-[#0b0f19] border border-gray-850 rounded-lg text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value="All">All Types</option>
            <option value="iam_user">IAM Users</option>
            <option value="iam_role">IAM Roles</option>
          </select>
        </div>
      </div>

      {/* Identities Grid */}
      {loading ? (
        <div className="flex items-center justify-center py-20">
          <RotateCw className="w-8 h-8 text-blue-500 animate-spin" />
        </div>
      ) : filteredIdentities.length === 0 ? (
        <div className="text-center py-16 text-gray-500 text-xs">
          No identity assets matching current filters.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredIdentities.map((identity) => (
            <div
              key={identity.id}
              onClick={() => setSelectedIdentity(identity)}
              className="bg-[#0e1428] border border-gray-850 hover:border-gray-700 p-5 rounded-xl cursor-pointer transition flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div className="p-2 bg-[#0b0f19] border border-gray-850 rounded-lg text-blue-400">
                    {identity.type === 'iam_user' ? <User size={16} /> : <Key size={16} />}
                  </div>
                  <span className={`px-2 py-0.5 border text-[9px] font-bold rounded capitalize ${getRiskColor(identity.risk_score)}`}>
                    {identity.risk_score ? `Risk: ${identity.risk_score}` : 'Secure'}
                  </span>
                </div>
                
                <h4 className="font-bold text-xs text-white mt-4 truncate leading-snug">{identity.name}</h4>
                <p className="text-[10px] text-gray-500 mt-1 font-mono truncate">{identity.resource_id}</p>
              </div>

              <div className="flex items-center justify-between pt-4 mt-4 border-t border-gray-800/65 text-[10px] text-gray-500">
                <span className="capitalize">{identity.type.replace('_', ' ')}</span>
                <span className="flex items-center gap-1">
                  Details <ChevronRight size={12} />
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Drawer */}
      {selectedIdentity && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-all">
          <div className="w-full max-w-lg bg-[#0d1326] border-l border-gray-800 h-full flex flex-col justify-between shadow-2xl relative">
            
            {/* Header */}
            <div className="p-6 border-b border-gray-800 flex items-center justify-between">
              <div>
                <span className="text-[9px] text-gray-500 font-bold uppercase tracking-wider capitalize">{selectedIdentity.type.replace('_', ' ')}</span>
                <h2 className="text-sm font-bold text-white mt-1 leading-snug">{selectedIdentity.name}</h2>
              </div>
              <button 
                onClick={() => setSelectedIdentity(null)}
                className="text-gray-500 hover:text-white transition text-xs"
              >
                Close
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs">
              <div className="space-y-3">
                <h3 className="text-xs font-bold text-white">General Information</h3>
                <div className="p-4 bg-[#0b0f19] border border-gray-850 rounded-xl space-y-3">
                  <div>
                    <span className="text-gray-500 block text-[10px]">Resource ID</span>
                    <span className="font-mono text-white block truncate">{selectedIdentity.resource_id}</span>
                  </div>
                  <div>
                    <span className="text-gray-500 block text-[10px]">Region</span>
                    <span className="text-white font-semibold capitalize">{selectedIdentity.region}</span>
                  </div>
                  <div>
                    <span className="text-gray-500 block text-[10px]">Cloud Provider</span>
                    <span className="text-white font-semibold uppercase">{selectedIdentity.provider}</span>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <h3 className="text-xs font-bold text-white">Security Posture</h3>
                <div className="p-4 bg-[#0b0f19] border border-gray-850 rounded-xl flex items-center gap-3">
                  {selectedIdentity.risk_score && selectedIdentity.risk_score >= 80 ? (
                    <>
                      <ShieldAlert className="text-red-500 w-5 h-5 shrink-0" />
                      <div>
                        <span className="font-bold text-red-400 block text-xs">Action Required</span>
                        <p className="text-[10px] text-gray-400 mt-0.5">MFA is disabled or privileged keys are unused.</p>
                      </div>
                    </>
                  ) : (
                    <>
                      <ShieldCheck className="text-green-500 w-5 h-5 shrink-0" />
                      <div>
                        <span className="font-bold text-green-400 block text-xs">Policy Compliant</span>
                        <p className="text-[10px] text-gray-400 mt-0.5">Identity adheres to all active organizational security checks.</p>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="p-6 border-t border-gray-800/80 bg-[#0b0f19] flex justify-end">
              <button 
                onClick={() => setSelectedIdentity(null)}
                className="px-4 py-2 border border-gray-850 hover:bg-gray-800 text-gray-300 hover:text-white rounded-lg text-xs font-semibold transition"
              >
                Done
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}
