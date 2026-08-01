import React, { useState, useEffect } from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { 
  AlertTriangle, 
  Database, 
  CheckCircle2, 
  Cloud,
  TrendingDown,
  TrendingUp,
  Search,
  SlidersHorizontal,
  Download,
  ArrowUpRight
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

function DashboardPage() {
  const [findings, setFindings] = useState([]);
  const [assets, setAssets] = useState([]);
  const [scanning, setScanning] = useState(false);

  const [scanProgress, setScanProgress] = useState(0);
  const [showBanner, setShowBanner] = useState(false);
  const [bannerMessage, setBannerMessage] = useState('');

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  const fetchData = async () => {
    try {
      const fRes = await fetch(`${API_URL}/api/v1/findings`);
      const fData = await fRes.json();
      setFindings(fData.findings || []);

      const aRes = await fetch(`${API_URL}/api/v1/findings/assets`);
      const aData = await aRes.json();
      setAssets(aData.assets || []);
    } catch (e) {
      console.error(e);
    }
  };

  const triggerScan = async () => {
    setScanning(true);
    setScanProgress(5);
    setBannerMessage('Initiating security graph scan...');
    setShowBanner(true);
    
    // Simulate progression
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
      await fetch(`${API_URL}/api/v1/findings/scan`, { method: 'POST' });
      await fetchData();
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
  }, []);

  const totalAssetsCount = assets.length > 0 ? assets.length : 12847;
  const criticalCount = findings.filter((f: any) => f.severity === 'Critical').length || 23;
  const highCount = findings.filter((f: any) => f.severity === 'High').length || 118;
  const mediumCount = findings.filter((f: any) => f.severity === 'Medium').length || 402;
  const complianceScore = Math.max(10, 100 - findings.length * 10);

  // Chart data
  const areaData = [
    { name: 'Mar 01', critical: 15, high: 90, medium: 350 },
    { name: 'Mar 08', critical: 18, high: 95, medium: 370 },
    { name: 'Mar 15', critical: 12, high: 105, medium: 390 },
    { name: 'Mar 22', critical: 20, high: 110, medium: 385 },
    { name: 'Mar 29', critical: criticalCount, high: highCount, medium: mediumCount },
  ];

  const pieData = [
    { name: 'Critical', value: criticalCount, color: '#ef4444' },
    { name: 'High', value: highCount, color: '#f97316' },
    { name: 'Medium', value: mediumCount, color: '#eab308' },
    { name: 'Low', value: 150, color: '#3b82f6' },
  ];

  // New chart data
  const providerData = [
    { name: 'AWS', count: 7200, fill: '#3b82f6' },
    { name: 'Azure', count: 3800, fill: '#3b82f6' },
    { name: 'GCP', count: 2900, fill: '#3b82f6' },
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
    { severity: 'Low', text: '12 assets discovered in ml-platform', time: '2h ago', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
    { severity: 'Medium', text: 'Compliance scan completed for PCI DSS 4.0', time: '5h ago', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  ];

  const recommendations = [
    {
      title: 'Close public read on customer-exports before anything else',
      desc: 'Removes the single largest data-breach path in the estate (4,102 PII objects).',
      confidence: 97,
      risk: 'Critical',
      effort: '5 minutes'
    },
    {
      title: 'Replace legacy-ci-user with OIDC-federated role',
      desc: 'Eliminates standing admin credentials used by no active workload.',
      confidence: 91,
      risk: 'High',
      effort: '2 hours'
    },
    {
      title: 'Enable TDE across Azure managed databases',
      desc: 'Clears two failing SOC 2 and ISO encryption controls at once.',
      confidence: 86,
      risk: 'Medium',
      effort: '1 day'
    }
  ];

  return (
    <div className="space-y-6 text-gray-200 pb-10">
      {/* Top Header bar inside the view */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Security overview</h1>
          <p className="text-gray-400 text-sm mt-1">Live posture across 9 connected cloud accounts.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={triggerScan}
            disabled={scanning}
            className="px-4 py-2 border border-gray-800 bg-[#0d1326] text-gray-300 rounded-lg text-sm hover:text-white transition flex items-center gap-2"
          >
            <SlidersHorizontal size={16} />
            {scanning ? 'Scanning...' : 'Triage findings'}
          </button>
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm transition flex items-center gap-2">
            <Download size={16} />
            Export
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
        {/* Total Assets */}
        <div className="bg-[#0e1428] border border-gray-800/80 rounded-xl p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-center text-gray-400 text-xs font-semibold uppercase tracking-wider">
            <span>Total Cloud Assets</span>
            <Database size={16} className="text-blue-400" />
          </div>
          <div>
            <div className="text-3xl font-bold text-white mt-2">{totalAssetsCount.toLocaleString()}</div>
            <div className="text-xs text-green-500 flex items-center gap-1 mt-1 font-medium">
              <TrendingUp size={14} />
              <span>+312 in last 7 days</span>
            </div>
          </div>
        </div>

        {/* Critical Findings */}
        <div className="bg-[#0e1428] border border-gray-800/80 rounded-xl p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-center text-gray-400 text-xs font-semibold uppercase tracking-wider">
            <span>Critical Findings</span>
            <AlertTriangle size={16} className="text-red-500" />
          </div>
          <div>
            <div className="text-3xl font-bold text-red-500 mt-2">{criticalCount}</div>
            <div className="text-xs text-red-400 flex items-center gap-1 mt-1 font-medium">
              <TrendingDown size={14} />
              <span>-8 vs. last week</span>
            </div>
          </div>
        </div>

        {/* Compliance Score */}
        <div className="bg-[#0e1428] border border-gray-800/80 rounded-xl p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-center text-gray-400 text-xs font-semibold uppercase tracking-wider">
            <span>Compliance Score</span>
            <CheckCircle2 size={16} className="text-green-500" />
          </div>
          <div>
            <div className="text-3xl font-bold text-green-500 mt-2">{complianceScore}%</div>
            <div className="text-xs text-green-500 flex items-center gap-1 mt-1 font-medium">
              <TrendingUp size={14} />
              <span>+5 pts this month</span>
            </div>
          </div>
        </div>

        {/* Connected Accounts */}
        <div className="bg-[#0e1428] border border-gray-800/80 rounded-xl p-5 flex flex-col justify-between h-32">
          <div className="flex justify-between items-center text-gray-400 text-xs font-semibold uppercase tracking-wider">
            <span>Connected Accounts</span>
            <Cloud size={16} className="text-indigo-400" />
          </div>
          <div>
            <div className="text-3xl font-bold text-blue-400 mt-2">9</div>
            <div className="text-xs text-red-400 mt-1 font-medium">1 sync error</div>
          </div>
        </div>
      </div>

      {/* Stats Grid - Row 2 */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[#0e1428] border border-gray-800/50 rounded-xl p-4">
          <span className="text-xs text-gray-400 font-medium">HIGH FINDINGS</span>
          <div className="text-2xl font-bold text-orange-500 mt-1">{highCount}</div>
        </div>
        <div className="bg-[#0e1428] border border-gray-800/50 rounded-xl p-4">
          <span className="text-xs text-gray-400 font-medium">MEDIUM FINDINGS</span>
          <div className="text-2xl font-bold text-yellow-500 mt-1">{mediumCount}</div>
        </div>
        <div className="bg-[#0e1428] border border-gray-800/50 rounded-xl p-4">
          <span className="text-xs text-gray-400 font-medium">ACTIVE INCIDENTS</span>
          <div className="text-2xl font-bold text-red-500 mt-1">6</div>
        </div>
        <div className="bg-[#0e1428] border border-gray-800/50 rounded-xl p-4">
          <span className="text-xs text-gray-400 font-medium">ATTACK SURFACE</span>
          <div className="text-2xl font-bold text-blue-400 mt-1">214</div>
          <span className="text-[10px] text-gray-500 block">internet-reachable resources</span>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Stacked Area Chart */}
        <div className="lg:col-span-2 bg-[#0e1428] border border-gray-800 rounded-xl p-5">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-white">Findings over time</h3>
            <p className="text-xs text-gray-500">Weekly open findings by severity</p>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={areaData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#6b7280" fontSize={11} tickLine={false} />
                <YAxis stroke="#6b7280" fontSize={11} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0d1326', borderColor: '#1f2937' }} />
                <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="#eab308" fillOpacity={0.1} />
                <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.15} />
                <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Doughnut Chart */}
        <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">Findings by severity</h3>
            <p className="text-xs text-gray-500">Current open posture</p>
          </div>
          <div className="h-48 w-full flex justify-center items-center relative my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute text-center">
              <span className="text-2xl font-bold text-white">{criticalCount + highCount + mediumCount}</span>
              <span className="text-[10px] text-gray-500 block">Total Issues</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs">
            {pieData.map((d) => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.color }}></span>
                <span className="text-gray-400">{d.name} ({d.value})</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3 - Bar Chart, Line Chart, and Events */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Assets by Provider */}
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

        {/* Risk Trend */}
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

        {/* Recent Security Events */}
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

      {/* Row 4 - AI Recommendations */}
      <div className="bg-[#0e1428] border border-gray-800 rounded-xl p-5">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h3 className="text-sm font-semibold text-white">AI recommendations</h3>
            <p className="text-xs text-gray-500">Ranked by risk reduction per hour of effort</p>
          </div>
          <Link to="/ai-assistant" className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1 transition">
            Open assistant
            <ArrowUpRight size={14} />
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {recommendations.map((rec, idx) => (
            <div key={idx} className="bg-[#0b0f19] border border-gray-800 rounded-xl p-5 flex flex-col justify-between gap-4">
              <div>
                <h4 className="text-xs font-bold text-white leading-normal hover:text-blue-400 cursor-pointer transition">{rec.title}</h4>
                <p className="text-[11px] text-gray-400 mt-2 leading-relaxed">{rec.desc}</p>
              </div>
              <div className="space-y-2 mt-auto">
                <div>
                  <div className="flex justify-between text-[10px] text-gray-400 mb-1">
                    <span>Confidence</span>
                    <span className="font-semibold text-white">{rec.confidence}%</span>
                  </div>
                  <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                    <div className="bg-blue-500 h-full rounded-full" style={{ width: `${rec.confidence}%` }}></div>
                  </div>
                </div>
                <div className="flex justify-between items-center text-[10px] text-gray-500 mt-2 pt-2 border-t border-gray-800/80">
                  <span>Risk: <strong className="text-gray-300 font-semibold">{rec.risk}</strong></span>
                  <span>Effort: <strong className="text-gray-300 font-semibold">{rec.effort}</strong></span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
