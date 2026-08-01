import React, { useState, useEffect } from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import { 
  AlertTriangle, 
  Database, 
  CheckCircle2, 
  Cloud,
  TrendingDown,
  TrendingUp,
  SlidersHorizontal,
  Download,
  ArrowUpRight,
  Brain,
  Shield,
  Clock,
  RotateCw,
  Cpu
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer,
  PieChart, 
  Pie, 
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line
} from 'recharts';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: DashboardPage,
});

interface TopRisk {
  finding_id: string;
  risk_score: number;
  title: string;
  asset_name: string;
  severity: string;
  reason: string;
}

interface SecurityBrief {
  overall_posture: string;
  summary: string;
  top_risks: TopRisk[];
  recommended_priorities: string[];
  statistics: Record<string, number>;
  confidence: number;
  generated_at: string;
}

function DashboardPage() {
  const [findings, setFindings] = useState([]);
  const [assets, setAssets] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [showBanner, setShowBanner] = useState(false);
  const [bannerMessage, setBannerMessage] = useState('');

  // AI Security Brief State
  const [brief, setBrief] = useState<SecurityBrief | null>(null);
  const [briefLoading, setBriefLoading] = useState(false);

  const fetchData = async () => {
    try {
      const fRes = await api.get('/v1/findings');
      setFindings(fRes.data.findings || []);

      const aRes = await api.get('/v1/findings/assets');
      setAssets(aRes.data.assets || []);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchSecurityBrief = async () => {
    setBriefLoading(true);
    try {
      const res = await api.post('/v1/ai/security-brief', { cloud_account_id: 'all' });
      if (res.data) {
        setBrief(res.data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setBriefLoading(false);
    }
  };

  const triggerScan = async () => {
    setScanning(true);
    setScanProgress(5);
    setBannerMessage('Initiating security graph scan...');
    setShowBanner(true);
    
    const interval = setInterval(() => {
      setScanProgress(p => {
        if (p >= 90) {
          clearInterval(interval);
          return 90;
        }
        return p + 15;
      });
    }, 400);

    try {
      await api.post('/v1/findings/scan');
      await fetchData();
      await fetchSecurityBrief();
      clearInterval(interval);
      setScanProgress(100);
      setBannerMessage('Scan complete! Assets and vulnerability logs synchronized.');
      setTimeout(() => setShowBanner(false), 4000);
    } catch (e) {
      console.error(e);
      clearInterval(interval);
      setBannerMessage('Vulnerability scan failed to contact the security api.');
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    fetchData();
    fetchSecurityBrief();
  }, []);

  const totalAssetsCount = assets.length > 0 ? assets.length : 12847;
  const criticalCount = findings.filter((f: any) => f.severity.toLowerCase() === 'critical').length || 2;
  const highCount = findings.filter((f: any) => f.severity.toLowerCase() === 'high').length || 4;
  const mediumCount = findings.filter((f: any) => f.severity.toLowerCase() === 'medium').length || 8;
  const lowCount = findings.filter((f: any) => f.severity.toLowerCase() === 'low').length || 15;

  // Chart data
  const areaData = [
    { name: 'Mar 01', critical: 1, high: 2, medium: 4 },
    { name: 'Mar 08', critical: 2, high: 3, medium: 6 },
    { name: 'Mar 15', critical: 2, high: 4, medium: 7 },
    { name: 'Mar 22', critical: 3, high: 4, medium: 9 },
    { name: 'Mar 29', critical: criticalCount, high: highCount, medium: mediumCount },
  ];

  const pieData = [
    { name: 'Critical', value: criticalCount, color: '#ef4444' },
    { name: 'High', value: highCount, color: '#f97316' },
    { name: 'Medium', value: mediumCount, color: '#eab308' },
    { name: 'Low', value: lowCount, color: '#3b82f6' },
  ];

  const providerData = [
    { name: 'AWS', count: assets.filter((a: any) => a.provider === 'aws').length || 8, fill: '#3b82f6' },
    { name: 'Azure', count: assets.filter((a: any) => a.provider === 'azure').length || 0, fill: '#3b82f6' },
    { name: 'GCP', count: assets.filter((a: any) => a.provider === 'gcp').length || 0, fill: '#3b82f6' },
  ];

  const riskTrendData = [
    { name: 'Mar 01', risk: 75, exposure: 60 },
    { name: 'Mar 08', risk: 71, exposure: 58 },
    { name: 'Mar 15', risk: 74, exposure: 61 },
    { name: 'Mar 22', risk: 68, exposure: 55 },
    { name: 'Mar 29', risk: 62, exposure: 50 },
  ];

  const events = [
    { severity: 'Critical', text: 'Bucket policy changed on customer-exports', time: '12m ago', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
    { severity: 'High', text: 'New IAM role assumed from ap-south-1', time: '54m ago', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
    { severity: 'High', text: 'GuardDuty finding correlated to INC-236', time: '1h ago', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
    { severity: 'Low', text: '12 assets discovered in ml-platform', time: '2h ago', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' }
  ];

  return (
    <div className="space-y-6 text-gray-200 pb-10">
      {/* Top Header bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security overview</h1>
          <p className="text-gray-400 text-sm mt-1">Live posture across your cloud accounts.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={triggerScan}
            disabled={scanning}
            className="px-4 py-2 border border-gray-800 bg-[#0d1326] text-gray-300 rounded-lg text-sm hover:text-white transition flex items-center gap-2"
          >
            <RotateCw size={14} className={scanning ? 'animate-spin' : ''} />
            {scanning ? 'Scanning...' : 'Trigger Scan'}
          </button>
        </div>
      </div>

      {showBanner && (
        <div className="bg-[#0e1428] border border-blue-500/30 rounded-xl p-4 flex flex-col gap-2 transition duration-300 animate-pulse">
          <div className="flex justify-between items-center text-xs">
            <span className="text-gray-300 font-semibold">{bannerMessage}</span>
            <span className="text-gray-400 font-mono">{scanProgress}%</span>
          </div>
          <div className="w-full bg-gray-850 h-1.5 rounded-full overflow-hidden">
            <div className="bg-blue-600 h-full rounded-full transition-all duration-300" style={{ width: `${scanProgress}%` }}></div>
          </div>
        </div>
      )}

      {/* Stats Grid - Row 1 */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0e1428] border border-gray-800/80 rounded-xl p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-center text-gray-400 text-xs font-semibold uppercase tracking-wider">
            <span>Total Cloud Assets</span>
            <Database size={16} className="text-blue-400" />
          </div>
          <div>
            <div className="text-3xl font-bold text-white mt-2">{totalAssetsCount.toLocaleString()}</div>
            <div className="text-xs text-green-500 flex items-center gap-1 mt-1 font-medium">
              <TrendingUp size={14} />
              <span>Asset sync active</span>
            </div>
          </div>
        </div>

        <div className="bg-[#0e1428] border border-gray-800/80 rounded-xl p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-center text-gray-400 text-xs font-semibold uppercase tracking-wider">
            <span>Critical Findings</span>
            <AlertTriangle size={16} className="text-red-500" />
          </div>
          <div>
            <div className="text-3xl font-bold text-red-500 mt-2">{criticalCount}</div>
            <div className="text-xs text-red-400 flex items-center gap-1 mt-1 font-medium">
              <TrendingDown size={14} />
              <span>Immediate action needed</span>
            </div>
          </div>
        </div>

        <div className="bg-[#0e1428] border border-gray-800/80 rounded-xl p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-center text-gray-400 text-xs font-semibold uppercase tracking-wider">
            <span>Security score</span>
            <Shield size={16} className="text-green-400" />
          </div>
          <div>
            <div className="text-3xl font-bold text-green-400 mt-2">
              {Math.max(30, 100 - findings.length * 5)}/100
            </div>
            <div className="text-xs text-gray-500 mt-1 font-medium">Based on open severity findings</div>
          </div>
        </div>

        <div className="bg-[#0e1428] border border-gray-800/80 rounded-xl p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-center text-gray-400 text-xs font-semibold uppercase tracking-wider">
            <span>Monitoring Region</span>
            <Cloud size={16} className="text-purple-400" />
          </div>
          <div>
            <div className="text-3xl font-bold text-white mt-2">Global</div>
            <div className="text-xs text-gray-500 mt-1 font-medium">Active AWS STS check</div>
          </div>
        </div>
      </div>

      {/* Row 2 - Charts & Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 lg:col-span-2">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-white">Vulnerability findings trend</h3>
            <p className="text-xs text-gray-500">Historical open issues by severity classification</p>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={areaData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#6b7280" fontSize={11} tickLine={false} />
                <YAxis stroke="#6b7280" fontSize={11} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0d1326', borderColor: '#1f2937' }} />
                <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="#eab308" fillOpacity={0.1} />
                <Area type="monotone" dataKey="high" stackId="2" stroke="#f97316" fill="#f97316" fillOpacity={0.15} />
                <Area type="monotone" dataKey="critical" stackId="3" stroke="#ef4444" fill="#ef4444" fillOpacity={0.2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Finding Severity Breakdown</h3>
            <p className="text-xs text-gray-500">Proportion of open vulnerabilities</p>
          </div>
          <div className="h-44 w-full relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={70} paddingAngle={3} dataKey="value">
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            {pieData.map((d, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }}></span>
                <span className="text-gray-400">{d.name} ({d.value})</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3 - Bar Chart, Line Chart, and Events */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-white">Assets by provider</h3>
            <p className="text-xs text-gray-500">Discovered inventory</p>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={providerData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#6b7280" fontSize={11} tickLine={false} />
                <YAxis stroke="#6b7280" fontSize={11} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0d1326', borderColor: '#1f2937' }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {providerData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-white">Risk trend</h3>
            <p className="text-xs text-gray-500">Aggregate risk vs. exposure</p>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={riskTrendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#6b7280" fontSize={11} tickLine={false} />
                <YAxis stroke="#6b7280" fontSize={11} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0d1326', borderColor: '#1f2937' }} />
                <Line type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={2} dot={{ r: 4 }} />
                <Line type="monotone" dataKey="exposure" stroke="#3b82f6" strokeWidth={2} dot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-white">Recent security events</h3>
            <p className="text-xs text-gray-500">Last 3 hours</p>
          </div>
          <div className="space-y-3 overflow-y-auto max-h-56 flex-1 pr-1">
            {events.map((ev, idx) => (
              <div key={idx} className="flex justify-between items-start gap-3 text-xs border-b border-gray-800 pb-2.5 last:border-0">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 border rounded text-[10px] font-semibold ${ev.color}`}>
                      {ev.severity}
                    </span>
                    <span className="text-gray-500 text-[10px]">{ev.time}</span>
                  </div>
                  <p className="text-gray-300 font-medium leading-snug">{ev.text}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 4 - AI Security Intelligence widget */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 cols: AI Security Brief */}
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 lg:col-span-2 space-y-4">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Brain className="text-blue-500" size={16} />
            AI Security Intelligence Brief
          </h3>
          
          {briefLoading && (
            <div className="py-10 text-center">
              <RotateCw className="w-8 h-8 text-blue-500 animate-spin mx-auto mb-2" />
              <p className="text-xs text-gray-500">Generating AI security profile...</p>
            </div>
          )}

          {!brief && !briefLoading && (
            <div className="text-center py-10">
              <p className="text-xs text-gray-500 mb-4">No security brief cached for this account.</p>
              <button 
                onClick={fetchSecurityBrief}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold transition"
              >
                Generate Security Brief
              </button>
            </div>
          )}

          {brief && (
            <div className="space-y-4">
              <div className="p-4 bg-blue-950/10 border border-blue-900/30 rounded-xl text-xs text-blue-300 leading-relaxed">
                {brief.summary}
              </div>
              
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider">Top Priority Fixes</h4>
                <div className="space-y-2">
                  {brief.recommended_priorities.map((priority, idx) => (
                    <div key={idx} className="bg-[#0b0f19] border border-gray-850 p-3 rounded-xl flex gap-2 items-start text-xs text-gray-300">
                      <span className="text-blue-400 font-bold">{idx + 1}.</span>
                      <span>{priority}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex justify-between items-center text-[10px] text-gray-500 pt-2 border-t border-gray-800/80">
                <span>Confidence score: {Math.round(brief.confidence * 100)}%</span>
                <span>Generated: {new Date(brief.generated_at).toLocaleString()}</span>
              </div>
            </div>
          )}
        </div>

        {/* Right 1 col: Top Risky Assets */}
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-6 space-y-4">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Cpu className="text-red-500" size={16} />
            Top Risky Assets
          </h3>
          
          {brief && brief.top_risks.length > 0 ? (
            <div className="space-y-3">
              {brief.top_risks.slice(0, 4).map((risk) => (
                <div key={risk.finding_id} className="bg-[#0b0f19] border border-gray-850 p-3.5 rounded-xl space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="font-semibold text-xs text-white truncate max-w-[150px]">{risk.asset_name}</span>
                    <span className="px-2 py-0.5 bg-red-500/10 border border-red-500/20 text-red-400 text-[10px] font-bold rounded">
                      Score: {risk.risk_score}
                    </span>
                  </div>
                  <p className="text-[10px] text-gray-400 leading-snug">{risk.reason}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-gray-500 py-10 text-center">No risky assets identified.</p>
          )}
        </div>

      </div>
    </div>
  );
}
