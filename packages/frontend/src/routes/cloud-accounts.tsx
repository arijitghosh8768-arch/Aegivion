import React, { useState, useEffect } from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import { 
  Shield, 
  RotateCw, 
  Plus, 
  Cloud,
  CheckCircle,
  XCircle,
  Loader2,
  Lock,
  RefreshCw,
  Info
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/cloud-accounts',
  component: CloudAccountsPage,
});

interface CloudAccount {
  id: string;
  account_name: string;
  provider: string;
  account_id: string;
  connection_status: string;
  default_region: string;
}

function CloudAccountsPage() {
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState<string | null>(null);
  
  // Modal states
  const [modalOpen, setModalOpen] = useState(false);
  const [accountName, setAccountName] = useState('');
  const [region, setRegion] = useState('ap-south-1');
  const [accessKey, setAccessKey] = useState('');
  const [secretKey, setSecretKey] = useState('');
  
  // Test connection states
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [discoveredAccountId, setDiscoveredAccountId] = useState<string | null>(null);

  // Form submission state
  const [submitting, setSubmitting] = useState(false);

  const fetchAccounts = async () => {
    try {
      setLoading(true);
      const res = await api.get('/v1/cloud-accounts');
      if (res.data.success) {
        setAccounts(res.data.data);
      }
    } catch (err) {
      console.error('Failed to load cloud accounts', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAccounts();
  }, []);

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setTestResult(null);
    setDiscoveredAccountId(null);
    try {
      const res = await api.post('/v1/cloud-accounts/aws/test', {
        aws_access_key_id: accessKey || undefined,
        aws_secret_access_key: secretKey || undefined,
        aws_region: region
      });
      if (res.data.connected) {
        setTestResult({ success: true, message: 'Identity verified successfully!' });
        setDiscoveredAccountId(res.data.account_id);
      } else {
        setTestResult({ success: false, message: 'Authentication failed. Please verify credentials.' });
      }
    } catch (err) {
      setTestResult({ success: false, message: 'Unable to connect to validation servers.' });
    } finally {
      setTestingConnection(false);
    }
  };

  const handleCreateAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!discoveredAccountId) {
      alert('Please verify your connection using the "Test Connection" button first.');
      return;
    }
    setSubmitting(true);
    try {
      const res = await api.post('/v1/cloud-accounts', {
        account_name: accountName,
        provider: 'aws',
        account_id: discoveredAccountId,
        default_region: region,
        aws_access_key_id: accessKey || undefined,
        aws_secret_access_key: secretKey || undefined
      });
      if (res.data.success) {
        // Reset and close
        setModalOpen(false);
        setAccountName('');
        setAccessKey('');
        setSecretKey('');
        setTestResult(null);
        setDiscoveredAccountId(null);
        fetchAccounts();
      }
    } catch (err) {
      alert('Failed to register cloud account.');
    } finally {
      setSubmitting(false);
    }
  };

  const triggerSync = (accountId: string) => {
    setSyncing(accountId);
    setTimeout(() => {
      setSyncing(null);
    }, 2000);
  };

  return (
    <div className="space-y-6 text-gray-200">
      {/* Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Cloud Accounts</h1>
          <p className="text-gray-400 text-sm mt-1">Connection health and inventory coverage per account.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={() => setModalOpen(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-semibold transition flex items-center gap-2 shadow-lg shadow-blue-500/20"
          >
            <Plus size={16} />
            Connect AWS
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        </div>
      ) : accounts.length === 0 ? (
        <div className="bg-[#0e1428] border border-gray-850 rounded-2xl p-12 text-center max-w-lg mx-auto">
          <Cloud className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-bold text-white">No Cloud Accounts Connected</h3>
          <p className="text-gray-400 text-xs mt-2">
            Aegivion scans, inventories, and analyzes configurations to detect compliance violations. Connect your first AWS account to start monitoring.
          </p>
          <button 
            onClick={() => setModalOpen(true)}
            className="mt-6 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg transition inline-flex items-center gap-2"
          >
            <Plus size={14} />
            Get Started
          </button>
        </div>
      ) : (
        /* Accounts Grid */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {accounts.map((acc) => {
            const isConnected = acc.connection_status === 'connected';
            const isSyncing = syncing === acc.id;
            return (
              <div key={acc.id} className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between h-48 hover:border-gray-750 transition duration-300">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="font-bold text-white text-base leading-snug">{acc.account_name}</h3>
                    <span className="text-xs text-gray-500 font-mono block mt-0.5">Account ID: {acc.account_id}</span>
                  </div>
                  
                  {/* Status Indicator */}
                  <span className={`px-2 py-0.5 border text-[10px] font-bold uppercase rounded flex items-center gap-1.5 ${
                    isConnected 
                      ? 'bg-green-500/10 text-green-400 border-green-500/20' 
                      : 'bg-red-500/10 text-red-400 border-red-500/20'
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                    {isConnected ? 'Connected' : 'Error'}
                  </span>
                </div>

                <div className="flex flex-col gap-1 text-xs text-gray-400 mt-2">
                  <div className="flex items-center gap-1.5">
                    <Cloud size={13} className="text-blue-400" />
                    <span className="font-semibold text-gray-300 capitalize">{acc.provider} ({acc.default_region})</span>
                  </div>
                  <span className="text-[10px] text-gray-500">Last Sync: {isSyncing ? 'Syncing...' : 'Not synced'}</span>
                </div>

                <div className="border-t border-gray-800/80 pt-3 mt-4 flex items-center justify-between">
                  <Link 
                    to={'/cloud-accounts/$accountId/scan'}
                    params={{ accountId: acc.id }}
                    className="text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center gap-1.5 bg-blue-600/5 hover:bg-blue-600/10 px-2.5 py-1.5 rounded-lg border border-blue-500/10 transition"
                  >
                    <RefreshCw size={12} />
                    Scan Manager
                  </Link>
                  
                  <span className="text-xs text-gray-500 font-mono">0 Assets</span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Connection Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0d1326] border border-gray-800 rounded-2xl w-full max-w-md p-6 relative overflow-hidden shadow-2xl">
            <button 
              onClick={() => setModalOpen(false)}
              className="absolute right-4 top-4 p-1 hover:bg-gray-800 text-gray-400 hover:text-white rounded-lg transition"
            >
              <XCircle size={20} />
            </button>

            <h2 className="text-lg font-bold text-white flex items-center gap-2 mb-2">
              <Shield className="text-blue-500" size={20} />
              Connect AWS Account
            </h2>
            <p className="text-gray-400 text-xs mb-6">
              Enter your AWS API Keys. Aegivion validates connection via AWS STS before committing settings.
            </p>

            <form onSubmit={handleCreateAccount} className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">Account Profile Name</label>
                <input 
                  type="text" 
                  required 
                  value={accountName}
                  onChange={(e) => setAccountName(e.target.value)}
                  placeholder="e.g. aegivion-production"
                  className="w-full bg-[#0b0f19] border border-gray-850 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">Default AWS Region</label>
                <input 
                  type="text" 
                  required 
                  value={region}
                  onChange={(e) => setRegion(e.target.value)}
                  placeholder="ap-south-1"
                  className="w-full bg-[#0b0f19] border border-gray-850 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">AWS Access Key ID (Optional)</label>
                <input 
                  type="text" 
                  value={accessKey}
                  onChange={(e) => setAccessKey(e.target.value)}
                  placeholder="Leave empty to use host environment profile"
                  className="w-full bg-[#0b0f19] border border-gray-850 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] font-bold text-gray-400 uppercase tracking-wider block">AWS Secret Access Key (Optional)</label>
                <div className="relative">
                  <Lock size={14} className="absolute left-3 top-3 text-gray-500" />
                  <input 
                    type="password" 
                    value={secretKey}
                    onChange={(e) => setSecretKey(e.target.value)}
                    placeholder="••••••••••••••••••••"
                    className="w-full bg-[#0b0f19] border border-gray-850 rounded-xl pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition"
                  />
                </div>
              </div>

              {testResult && (
                <div className={`p-3.5 rounded-xl border text-xs flex items-start gap-2 ${
                  testResult.success 
                    ? 'bg-green-950/20 border-green-500/20 text-green-400' 
                    : 'bg-red-950/20 border-red-500/20 text-red-400'
                }`}>
                  {testResult.success ? <CheckCircle size={16} className="shrink-0" /> : <XCircle size={16} className="shrink-0" />}
                  <div>
                    <span className="font-semibold block">{testResult.message}</span>
                    {discoveredAccountId && (
                      <span className="block mt-0.5 font-mono text-[10px] text-gray-500">Discovered ID: {discoveredAccountId}</span>
                    )}
                  </div>
                </div>
              )}

              <div className="flex gap-3 pt-3">
                <button 
                  type="button"
                  onClick={handleTestConnection}
                  disabled={testingConnection}
                  className="flex-1 px-4 py-2 border border-gray-800 bg-[#0e1428] hover:bg-[#141b35] text-gray-300 font-semibold rounded-xl text-xs transition flex items-center justify-center gap-1.5"
                >
                  {testingConnection ? <Loader2 size={12} className="animate-spin" /> : null}
                  Test Connection
                </button>
                <button 
                  type="submit"
                  disabled={submitting || !discoveredAccountId}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/40 text-white font-semibold rounded-xl text-xs transition flex items-center justify-center"
                >
                  {submitting ? 'Registering...' : 'Connect Account'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
