import React, { useState, useEffect } from 'react';
import { createRoute, Link, useParams } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import { 
  Play, 
  RotateCw, 
  ArrowLeft, 
  ShieldCheck, 
  AlertTriangle,
  Server,
  Cloud,
  CheckCircle,
  XCircle,
  Database
} from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/cloud-accounts/$accountId/scan',
  component: ScanPage,
});

interface CollectorProgress {
  status: 'pending' | 'running' | 'completed' | 'failed';
  label: string;
}

function ScanPage() {
  const { accountId } = useParams({ from: Route.id });
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<string>('pending');
  const [polling, setPolling] = useState(false);
  const [scanProgress, setScanProgress] = useState<Record<string, CollectorProgress>>({
    ec2: { status: 'pending', label: 'EC2 Instance Discovery' },
    s3: { status: 'pending', label: 'S3 Storage Configurations' },
    iam: { status: 'pending', label: 'IAM User Posture Audit' },
    security_groups: { status: 'pending', label: 'Network Firewall Maps' }
  });
  
  const [discoveredCount, setDiscoveredCount] = useState(0);
  const [findingsCount, setFindingsCount] = useState(0);

  const startScan = async () => {
    try {
      setScanStatus('queued');
      const res = await api.post('/v1/scans/start', {
        cloud_account_id: accountId,
        region: 'ap-south-1'
      });
      if (res.data && res.data.scan_id) {
        setScanId(res.data.scan_id);
        setPolling(true);
      }
    } catch (e) {
      console.error(e);
      setScanStatus('failed');
    }
  };

  const pollScanStatus = async (id: string) => {
    try {
      const res = await api.get(`/v1/scans/${id}`);
      const data = res.data;
      
      setScanStatus(data.status);
      setDiscoveredCount(data.assets_discovered);
      setFindingsCount(data.findings_generated);

      if (data.collector_status) {
        setScanProgress(prev => {
          const updated = { ...prev };
          Object.keys(data.collector_status).forEach((collector) => {
            if (updated[collector]) {
              updated[collector].status = data.collector_status[collector];
            }
          });
          return updated;
        });
      }

      if (data.status === 'completed' || data.status === 'failed') {
        setPolling(false);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    if (!polling || !scanId) return;
    
    const interval = setInterval(() => {
      pollScanStatus(scanId);
    }, 3000);

    return () => clearInterval(interval);
  }, [polling, scanId]);

  const getStatusBadge = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'completed') return 'bg-green-500/10 text-green-400 border-green-500/20';
    if (s === 'running') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
    if (s === 'failed') return 'bg-red-500/10 text-red-400 border-red-500/20';
    return 'bg-gray-500/10 text-gray-400 border-gray-500/20';
  };

  const getCollectorIcon = (collectorName: string) => {
    if (collectorName === 'ec2') return <Server className="text-blue-400 shrink-0" size={16} />;
    if (collectorName === 's3') return <Database className="text-purple-400 shrink-0" size={16} />;
    if (collectorName === 'iam') return <ShieldCheck className="text-orange-400 shrink-0" size={16} />;
    return <Cloud className="text-teal-400 shrink-0" size={16} />;
  };

  return (
    <div className="space-y-6 text-gray-200 pb-16">
      {/* Back button */}
      <div>
        <Link 
          to="/cloud-accounts" 
          className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-white transition"
        >
          <ArrowLeft size={14} />
          Back to Cloud Accounts
        </Link>
      </div>

      {/* Header */}
      <div className="border-b border-gray-800 pb-5">
        <h1 className="text-2xl font-bold text-white tracking-tight">Cloud Security Scanner</h1>
        <p className="text-gray-400 text-sm mt-1">Audit AWS configurations, credential age, permissions and network rules.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Control Card / Progress */}
        <div className="lg:col-span-2 space-y-6">
          
          {!scanId && (
            <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-8 text-center space-y-6">
              <Cloud className="w-16 h-16 text-blue-500/25 mx-auto mb-2 animate-pulse" />
              <div className="space-y-2 max-w-sm mx-auto">
                <h2 className="text-lg font-bold text-white">AWS Configuration Audit</h2>
                <p className="text-xs text-gray-400 leading-relaxed">
                  Triggering a scan gathers all target assets (EC2, S3, IAM, SGs) and evaluates them against rules.
                </p>
              </div>
              <button 
                onClick={startScan}
                className="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition flex items-center gap-2 mx-auto shadow-lg shadow-blue-500/20"
              >
                <Play size={14} fill="currentColor" />
                Start Full Scan
              </button>
            </div>
          )}

          {scanId && (
            <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 space-y-6">
              <div className="flex justify-between items-center border-b border-gray-850 pb-4">
                <div>
                  <h3 className="text-sm font-bold text-white">Scan Job Status</h3>
                  <span className="text-[10px] text-gray-500 font-mono block mt-0.5">ID: {scanId}</span>
                </div>
                <span className={`px-2.5 py-0.5 border text-[10px] font-bold rounded-full capitalize ${getStatusBadge(scanStatus)}`}>
                  {scanStatus}
                </span>
              </div>

              {/* Progress items */}
              <div className="space-y-3">
                {Object.entries(scanProgress).map(([key, collector]) => (
                  <div key={key} className="bg-[#0b0f19] border border-gray-850 p-4 rounded-xl flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      {getCollectorIcon(key)}
                      <span className="text-xs font-semibold text-white">{collector.label}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {collector.status === 'running' && <RotateCw className="w-3.5 h-3.5 text-yellow-500 animate-spin" />}
                      <span className={`text-[10px] font-semibold capitalize px-2 py-0.5 rounded border ${getStatusBadge(collector.status)}`}>
                        {collector.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Running indicator */}
              {polling && (
                <div className="text-center text-xs text-gray-500 flex items-center justify-center gap-2 pt-2">
                  <RotateCw className="w-4 h-4 text-blue-500 animate-spin" />
                  <span>Polling scan progress results...</span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column: Scan results widget */}
        <div className="space-y-6">
          <div className="bg-[#0e1428] border border-gray-850 rounded-xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-white">Discovery Stats</h3>
            <div className="space-y-4">
              <div className="bg-[#0b0f19] border border-gray-850 p-4 rounded-xl flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Assets discovered</span>
                  <span className="text-xl font-extrabold text-white mt-0.5">{discoveredCount}</span>
                </div>
                <Server className="text-blue-500" size={18} />
              </div>

              <div className="bg-[#0b0f19] border border-gray-850 p-4 rounded-xl flex items-center justify-between">
                <div>
                  <span className="text-[10px] font-bold text-gray-500 uppercase tracking-wider block">Findings generated</span>
                  <span className="text-xl font-extrabold text-red-400 mt-0.5">{findingsCount}</span>
                </div>
                <AlertTriangle className="text-red-500" size={18} />
              </div>
            </div>
          </div>

          {scanStatus === 'completed' && (
            <div className="bg-green-950/10 border border-green-900/30 rounded-xl p-5 text-center space-y-4">
              <CheckCircle className="text-green-500 w-10 h-10 mx-auto" />
              <div className="space-y-1">
                <h4 className="text-xs font-bold text-white">Scan Completed Successfully</h4>
                <p className="text-[10px] text-gray-400 leading-normal">
                  All target cloud configuration rules have been updated.
                </p>
              </div>
              <Link 
                to="/" 
                className="block text-center px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg text-xs font-semibold transition"
              >
                Go to Dashboard
              </Link>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
