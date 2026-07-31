import React, { useState } from 'react';
import { createRoute } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { 
  Shield, 
  RotateCw, 
  Plus, 
  Cloud 
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/cloud-accounts',
  component: CloudAccountsPage,
});

function CloudAccountsPage() {
  const [syncing, setSyncing] = useState(false);

  const accounts = [
    {
      name: 'aegivion-prod',
      id: '0213-4402-1130',
      provider: 'AWS',
      status: 'Connected',
      statusColor: 'bg-green-500/10 text-green-400 border-green-500/20',
      syncTime: '5 min ago',
      assets: '4,821'
    },
    {
      name: 'aegivion-staging',
      id: '0213-4402-7701',
      provider: 'AWS',
      status: 'Connected',
      statusColor: 'bg-green-500/10 text-green-400 border-green-500/20',
      syncTime: '6 min ago',
      assets: '1,442'
    },
    {
      name: 'aegivion-data',
      id: '0213-4402-0001',
      provider: 'AWS',
      status: 'Syncing',
      statusColor: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      syncTime: 'syncing...',
      assets: '1,157'
    },
    {
      name: 'corp-identity',
      id: 'sub-4f21-aa9b',
      provider: 'Azure',
      status: 'Connected',
      statusColor: 'bg-green-500/10 text-green-400 border-green-500/20',
      syncTime: '11 min ago',
      assets: '1,884'
    },
    {
      name: 'corp-analytics',
      id: 'sub-4f21-bb18',
      provider: 'Azure',
      status: 'Error',
      statusColor: 'bg-red-500/10 text-red-400 border-red-500/20',
      syncTime: '2 h ago',
      assets: '1,284'
    },
    {
      name: 'ml-platform',
      id: 'proj-ml-88213',
      provider: 'GCP',
      status: 'Connected',
      statusColor: 'bg-green-500/10 text-green-400 border-green-500/20',
      syncTime: '8 min ago',
      assets: '2,259'
    }
  ];

  const handleSyncAll = () => {
    setSyncing(true);
    setTimeout(() => setSyncing(false), 2000);
  };

  return (
    <div className="space-y-6 text-gray-200">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Cloud accounts</h1>
          <p className="text-gray-400 text-sm mt-1">Connection health and inventory coverage per account.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={handleSyncAll}
            disabled={syncing}
            className="px-4 py-2 border border-gray-800 bg-[#0d1326] text-gray-300 rounded-lg text-sm hover:text-white transition flex items-center gap-2"
          >
            <RotateCw size={16} className={syncing ? 'animate-spin' : ''} />
            Sync all
          </button>
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition flex items-center gap-2">
            <Plus size={16} />
            Connect account
          </button>
        </div>
      </div>

      {/* Accounts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {accounts.map((acc, idx) => (
          <div key={idx} className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-44">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="font-bold text-white text-base leading-snug">{acc.name}</h3>
                <span className="text-xs text-gray-500 font-mono block mt-0.5">{acc.id}</span>
              </div>
              <span className={`px-2.5 py-0.5 border text-xs font-semibold rounded ${acc.statusColor}`}>
                {acc.status}
              </span>
            </div>

            <div className="flex items-center gap-2 text-xs text-gray-400 mt-2">
              <Cloud size={14} className="text-blue-400" />
              <span className="font-semibold text-gray-300">{acc.provider}</span>
              <span className="text-gray-600">|</span>
              <span>Last sync: {acc.syncTime}</span>
            </div>

            <div className="border-t border-gray-800/80 pt-3 mt-4 flex flex-col justify-end">
              <span className="text-2xl font-bold text-white leading-none">{acc.assets}</span>
              <span className="text-[10px] text-gray-500 mt-1 uppercase tracking-wider font-semibold">assets discovered</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
