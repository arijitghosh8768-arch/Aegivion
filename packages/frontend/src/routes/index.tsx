import React, { useState, useEffect } from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import {
  Shield, AlertTriangle, CheckCircle2, Cloud,
  Bell, HelpCircle, Settings, Search, Brain,
  ChevronRight, RefreshCw, ArrowRight, Globe, Database
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts';
import { useAuthStore } from '@/store/auth-store';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: DashboardPage,
});

/* ─── Static mock data ─── */
const riskTrendData = [
  { day: 'May 06', score: 78 },
  { day: 'May 07', score: 72 },
  { day: 'May 08', score: 80 },
  { day: 'May 09', score: 68 },
  { day: 'May 10', score: 75 },
  { day: 'May 11', score: 60 },
  { day: 'May 12', score: 55 },
];

const threats = [
  { id: 1, title: 'IAM role over-privilege detected', env: 'AWS Production', time: '2m ago', color: '#EF4444' },
  { id: 2, title: 'Unusual API activity', env: 'Azure Environment', time: '5m ago', color: '#F59E0B' },
  { id: 3, title: 'Security group - open SSH', env: 'GCP VPC Network', time: '9m ago', color: '#F59E0B' },
  { id: 4, title: 'Root login attempt', env: 'AWS Production', time: '12m ago', color: '#3B82F6' },
];

const topRiskyAssets = [
  { name: 'S3 bucket - public access', env: 'AWS Production', severity: 'Critical', score: 90, icon: '🟠' },
  { name: 'IAM user without MFA', env: 'AWS Production', severity: 'High', score: 75, icon: '🔐' },
  { name: 'Security group - open SSH', env: 'Azure Environment', severity: 'High', score: 65, icon: '☁️' },
  { name: 'Public VM with sensitive data', env: 'GCP Project', severity: 'Medium', score: 45, icon: '💾' },
];

/* ─── Animated 360° Cloud Topology ─── */
function CloudTopology({ refreshing }: { refreshing: boolean }) {
  return (
    <div className="relative w-full h-64 flex items-center justify-center select-none">
      {/* Orbit rings */}
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="w-52 h-52 rounded-full border border-dashed border-purple-200 opacity-50"
          style={{ animation: 'spin 22s linear infinite' }} />
      </div>
      <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
        <div className="w-36 h-36 rounded-full border border-dashed border-blue-200 opacity-40"
          style={{ animation: 'spin 16s linear infinite reverse' }} />
      </div>

      {/* Center shield */}
      <div className="relative z-10 w-14 h-14 bg-gradient-to-br from-purple-600 to-indigo-600 rounded-2xl flex items-center justify-center shadow-lg shadow-purple-200">
        <Shield className="w-7 h-7 text-white" />
      </div>

      {/* AWS — top */}
      <div className="absolute top-1 left-1/2 -translate-x-1/2 flex flex-col items-center gap-1 z-10">
        <div className="w-12 h-12 bg-white rounded-2xl shadow-md flex items-center justify-center border border-gray-100">
          <span className="text-[11px] font-black text-orange-500">aws</span>
        </div>
        <span className="text-[9px] text-green-600 font-semibold bg-green-50 px-2 py-0.5 rounded-full border border-green-100">Secure · 12 Assets</span>
      </div>

      {/* Azure — left */}
      <div className="absolute left-0 top-1/2 -translate-y-1/2 flex flex-col items-center gap-1 z-10">
        <div className="w-12 h-12 bg-white rounded-2xl shadow-md flex items-center justify-center border border-gray-100">
          <span className="text-blue-600 font-black text-xl">A</span>
        </div>
        <span className="text-[9px] text-green-600 font-semibold bg-green-50 px-2 py-0.5 rounded-full border border-green-100">Secure · 10</span>
      </div>

      {/* GCP — right */}
      <div className="absolute right-0 top-1/2 -translate-y-1/2 flex flex-col items-center gap-1 z-10">
        <div className="w-12 h-12 bg-white rounded-2xl shadow-md flex items-center justify-center border border-gray-100">
          <Globe className="w-6 h-6 text-blue-400" />
        </div>
        <span className="text-[9px] text-green-600 font-semibold bg-green-50 px-2 py-0.5 rounded-full border border-green-100">Secure · 10</span>
      </div>

      {/* Bottom icons */}
      <div className="absolute bottom-8 left-1/3 z-10">
        <div className="w-10 h-10 bg-purple-100 rounded-xl flex items-center justify-center shadow-sm">
          <Database className="w-5 h-5 text-purple-500" />
        </div>
      </div>
      <div className="absolute bottom-8 right-1/3 z-10">
        <div className="w-10 h-10 bg-blue-100 rounded-xl flex items-center justify-center shadow-sm">
          <Cloud className="w-5 h-5 text-blue-500" />
        </div>
      </div>

      {/* Connecting SVG lines */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 400 256" preserveAspectRatio="xMidYMid meet">
        <line x1="200" y1="128" x2="200" y2="40" stroke="#a78bfa" strokeWidth="1.5" strokeDasharray="5 4" opacity="0.5" />
        <line x1="200" y1="128" x2="40" y2="128" stroke="#93c5fd" strokeWidth="1.5" strokeDasharray="5 4" opacity="0.5" />
        <line x1="200" y1="128" x2="360" y2="128" stroke="#6ee7b7" strokeWidth="1.5" strokeDasharray="5 4" opacity="0.5" />
        <line x1="200" y1="128" x2="145" y2="208" stroke="#c4b5fd" strokeWidth="1" strokeDasharray="4 4" opacity="0.35" />
        <line x1="200" y1="128" x2="255" y2="208" stroke="#93c5fd" strokeWidth="1" strokeDasharray="4 4" opacity="0.35" />
        {/* Animated dots on lines */}
        <circle r="3" fill="#a78bfa" opacity="0.7">
          <animateMotion dur="3s" repeatCount="indefinite" path="M200,128 L200,40" />
        </circle>
        <circle r="3" fill="#93c5fd" opacity="0.7">
          <animateMotion dur="3.5s" repeatCount="indefinite" path="M200,128 L40,128" />
        </circle>
        <circle r="3" fill="#6ee7b7" opacity="0.7">
          <animateMotion dur="4s" repeatCount="indefinite" path="M200,128 L360,128" />
        </circle>
      </svg>

      {/* Status badge */}
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 flex items-center gap-1.5 bg-green-50 border border-green-200 text-green-700 text-[10px] font-semibold px-3 py-1 rounded-full shadow-sm">
        <span className="w-1.5 h-1.5 bg-green-500 rounded-full inline-block animate-pulse" />
        All Systems Operational
      </div>
    </div>
  );
}

/* ─── Severity badge colours ─── */
const severityColor: Record<string, string> = {
  Critical: 'bg-red-100 text-red-600',
  High: 'bg-orange-100 text-orange-600',
  Medium: 'bg-blue-100 text-blue-600',
  Low: 'bg-gray-100 text-gray-500',
};

/* ─── Main Dashboard ─── */
function DashboardPage() {
  const user = useAuthStore((state: any) => state.user);
  const [findings, setFindings] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  const hour = new Date().getHours();
  const greeting = hour < 12 ? 'Good Morning' : hour < 17 ? 'Good Afternoon' : 'Good Evening';

  const fetchData = async () => {
    try {
      setRefreshing(true);
      const [fRes, aRes] = await Promise.allSettled([
        api.get('/v1/findings'),
        api.get('/v1/findings/assets'),
      ]);
      if (fRes.status === 'fulfilled') setFindings(fRes.value.data.findings || []);
      if (aRes.status === 'fulfilled') setAssets(aRes.value.data.assets || []);
    } catch (_) {}
    finally { setRefreshing(false); }
  };

  useEffect(() => { fetchData(); }, []);

  const critical = findings.filter((f: any) => f.severity === 'CRITICAL').length;
  const secScore = Math.max(0, 100 - critical * 4 - findings.filter((f: any) => f.severity === 'HIGH').length * 2) || 92;
  const totalAssets = assets.length || 32;

  const statCards = [
    { label: 'TOTAL ASSETS', value: totalAssets, sub: 'Across 3 Clouds', icon: <Database className="w-4.5 h-4.5 text-purple-500" />, bg: 'bg-purple-50' },
    { label: 'CRITICAL RISKS', value: critical || 2, sub: 'Immediate attention', icon: <AlertTriangle className="w-4.5 h-4.5 text-red-500" />, bg: 'bg-red-50' },
    { label: 'SECURITY SCORE', value: `${secScore}/100`, sub: 'Excellent', icon: <CheckCircle2 className="w-4.5 h-4.5 text-green-500" />, bg: 'bg-green-50' },
    { label: 'COMPLIANCE', value: '75%', sub: '6/8 Compliant', icon: <Shield className="w-4.5 h-4.5 text-blue-500" />, bg: 'bg-blue-50' },
    { label: 'ATTACK SURFACE', value: 'Low', sub: 'Exposure level', icon: <Globe className="w-4.5 h-4.5 text-indigo-500" />, bg: 'bg-indigo-50' },
  ];

  return (
    <div className="flex flex-col h-full overflow-hidden bg-[#F7F8FF]" style={{ fontFamily: "'Inter', sans-serif" }}>

      {/* ── Top Bar ── */}
      <header className="flex items-center justify-between px-6 py-3 bg-white border-b border-gray-100 shrink-0">
        <div>
          <h1 className="text-[15px] font-bold text-gray-900">{greeting}, {user?.first_name || 'Admin'} 👋</h1>
          <p className="text-[11px] text-gray-400 mt-0.5">Aegivion AI is actively protecting your cloud environment.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-gray-400" aria-hidden="true" />
            <input
              type="search"
              placeholder="Search assets, threats, incidents..."
              className="pl-9 pr-4 py-2 text-[11px] bg-gray-50 border border-gray-200 rounded-xl w-56 focus:outline-none focus:ring-1 focus:ring-purple-300"
            />
          </div>
          <button aria-label="Open notifications" className="relative p-2 rounded-xl bg-gray-50 hover:bg-gray-100 transition-colors">
            <Bell className="w-4 h-4 text-gray-500" aria-hidden="true" />
            <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-purple-500 rounded-full" />
          </button>
          <button aria-label="Help center" className="p-2 rounded-xl bg-gray-50 hover:bg-gray-100 transition-colors">
            <HelpCircle className="w-4 h-4 text-gray-500" aria-hidden="true" />
          </button>
          <button aria-label="Open settings" className="p-2 rounded-xl bg-gray-50 hover:bg-gray-100 transition-colors">
            <Settings className="w-4 h-4 text-gray-500" aria-hidden="true" />
          </button>
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-purple-600 to-indigo-600 flex items-center justify-center text-white text-[11px] font-bold shadow">
            {(user?.first_name?.[0] || 'A').toUpperCase()}
          </div>
        </div>
      </header>

      {/* ── Body ── */}
      <div className="flex-1 overflow-y-auto p-5">
        <div className="flex gap-4 min-h-full">

          {/* ── Center column ── */}
          <div className="flex-1 min-w-0 flex flex-col gap-4">

            {/* Stat cards */}
            <div className="grid grid-cols-5 gap-3">
              {statCards.map((c, i) => (
                <div key={i} className="bg-white rounded-2xl p-4 shadow-sm border border-gray-100 hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between mb-2">
                    <p className="text-[9px] font-bold text-gray-400 tracking-widest uppercase leading-tight">{c.label}</p>
                    <div className={`w-7 h-7 rounded-lg ${c.bg} flex items-center justify-center shrink-0`}>{c.icon}</div>
                  </div>
                  <p className="text-[22px] font-black text-gray-900 leading-tight">{c.value}</p>
                  <p className="text-[10px] text-gray-400 mt-1">{c.sub}</p>
                </div>
              ))}
            </div>

            {/* Cloud topology card */}
            <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-5">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h2 className="text-[13px] font-bold text-gray-900">Cloud Environment Overview</h2>
                  <p className="text-[10px] text-gray-400">Real-time 360° security visualization</p>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={fetchData} aria-label="Refresh data" className="p-1.5 rounded-lg bg-gray-50 hover:bg-gray-100 transition-colors">
                    <RefreshCw className={`w-3.5 h-3.5 text-gray-400 ${refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
                  </button>
                  <span className="text-[10px] font-bold text-purple-600 bg-purple-50 border border-purple-100 px-2 py-0.5 rounded-full">360°</span>
                </div>
              </div>
              <CloudTopology refreshing={refreshing} />
            </div>

            {/* Risk Trend + Top Risky Assets */}
            <div className="grid grid-cols-2 gap-4">

              {/* Risk Trend */}
              <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h3 className="text-[12px] font-bold text-gray-900">Risk Trend <span className="font-normal text-gray-400">(Last 7 Days)</span></h3>
                  </div>
                  <select className="text-[10px] border border-gray-200 rounded-lg px-2 py-1 text-gray-500 bg-gray-50 focus:outline-none cursor-pointer">
                    <option>Overall Risk</option>
                  </select>
                </div>
                <ResponsiveContainer width="100%" height={130}>
                  <AreaChart data={riskTrendData} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
                    <defs>
                      <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#8B5CF6" stopOpacity={0.18} />
                        <stop offset="95%" stopColor="#8B5CF6" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#F3F4F6" vertical={false} />
                    <XAxis dataKey="day" tick={{ fontSize: 8, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
                    <YAxis tick={{ fontSize: 8, fill: '#9CA3AF' }} tickLine={false} axisLine={false} domain={[0, 100]} />
                    <Tooltip
                      contentStyle={{ fontSize: 10, borderRadius: 10, border: '1px solid #E5E7EB', boxShadow: '0 4px 12px rgba(0,0,0,0.08)' }}
                      cursor={{ stroke: '#8B5CF6', strokeWidth: 1, strokeDasharray: '4 3' }}
                    />
                    <Area type="monotone" dataKey="score" stroke="#8B5CF6" strokeWidth={2} fill="url(#riskGrad)"
                      dot={{ r: 3, fill: '#8B5CF6', strokeWidth: 0 }}
                      activeDot={{ r: 5, fill: '#7C3AED', strokeWidth: 0 }} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Top Risky Assets */}
              <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-4">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-[12px] font-bold text-gray-900">Top Risky Assets</h3>
                  <Link to="/assets" className="text-[10px] text-purple-600 hover:text-purple-800 flex items-center gap-0.5 font-medium">
                    View All <ChevronRight className="w-3 h-3" aria-hidden="true" />
                  </Link>
                </div>
                <div className="flex flex-col gap-3">
                  {topRiskyAssets.map((a, i) => (
                    <div key={i} className="flex items-center gap-2.5 group cursor-pointer">
                      <div className="w-7 h-7 rounded-lg bg-gray-50 flex items-center justify-center text-sm shrink-0 group-hover:bg-purple-50 transition-colors">
                        {a.icon}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-[11px] font-semibold text-gray-800 truncate group-hover:text-purple-700 transition-colors">{a.name}</p>
                        <p className="text-[9px] text-gray-400">{a.env}</p>
                      </div>
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-md shrink-0 ${severityColor[a.severity]}`}>{a.severity}</span>
                      <span className="text-[11px] font-black text-gray-700 w-6 text-right shrink-0">{a.score}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* ── Right panel ── */}
          <div className="w-60 flex flex-col gap-3 shrink-0">

            {/* AI Security Insights */}
            <div className="rounded-2xl p-4 text-white shadow-lg shadow-purple-200/60"
              style={{ background: 'linear-gradient(135deg, #7C3AED 0%, #4F46E5 100%)' }}>
              <div className="flex items-start justify-between mb-2">
                <div>
                  <h3 className="text-[12px] font-bold">AI Security Insights</h3>
                  <p className="text-[9px] text-purple-200 mt-0.5">Powered by Aegivion AI</p>
                </div>
                <Brain className="w-5 h-5 text-purple-200 shrink-0" aria-hidden="true" />
              </div>
              <p className="text-[10px] text-purple-100 leading-relaxed mb-3">
                I've analyzed your environment and found{' '}
                <span className="font-bold text-white">1 critical misconfiguration</span> in{' '}
                <span className="font-bold text-yellow-300">AWS S3 bucket policy.</span>
              </p>
              <div className="mb-3">
                <p className="text-[9px] text-purple-300 mb-1.5">Risk Level</p>
                <div className="flex gap-1">
                  {[0, 1, 2, 3, 4].map(i => (
                    <div key={i} className={`h-1.5 flex-1 rounded-full ${i < 3 ? 'bg-red-400' : 'bg-purple-500 opacity-30'}`} />
                  ))}
                </div>
                <p className="text-[9px] text-red-300 mt-1 font-bold">High</p>
              </div>
              <button className="w-full flex items-center justify-center gap-1.5 bg-white text-purple-700 font-bold text-[10px] py-2 rounded-xl hover:bg-purple-50 active:scale-95 transition-all">
                View &amp; Resolve <ArrowRight className="w-3 h-3" aria-hidden="true" />
              </button>
            </div>

            {/* Live Threat Feed */}
            <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-4 flex-1">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="text-[12px] font-bold text-gray-900">Live Threat Feed</h3>
                  <p className="text-[9px] text-gray-400">Real-time security events</p>
                </div>
                <Link to="/findings" className="text-[10px] text-purple-600 hover:text-purple-800 font-medium">View All</Link>
              </div>
              <div className="flex flex-col gap-3">
                {threats.map(t => (
                  <div key={t.id} className="flex items-start gap-2 group cursor-pointer">
                    <div className="w-2 h-2 rounded-full mt-1.5 shrink-0" style={{ backgroundColor: t.color }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-[10px] font-semibold text-gray-800 leading-snug group-hover:text-purple-700 transition-colors">{t.title}</p>
                      <p className="text-[9px] text-gray-400 mt-0.5">{t.env}</p>
                    </div>
                    <span className="text-[9px] text-gray-400 shrink-0 mt-0.5">{t.time}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Ask AI */}
            <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-4">
              <div className="flex items-center justify-between mb-1.5">
                <h3 className="text-[12px] font-bold text-gray-900">Ask Aegivion AI</h3>
                <div className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
                  <span className="text-[9px] text-green-600 font-semibold">Online</span>
                </div>
              </div>
              <p className="text-[10px] text-gray-400 mb-2">How can I help you securing your cloud today?</p>
              {/* Decorative waveform */}
              <div className="flex items-end gap-0.5 mb-2 h-5">
                {[2, 5, 8, 4, 9, 3, 7, 10, 5, 3, 8, 4].map((h, i) => (
                  <div key={i} className="flex-1 rounded-full bg-purple-300 opacity-50"
                    style={{ height: `${h}px`, animation: `pulse ${1 + i * 0.1}s ease-in-out infinite alternate` }} />
                ))}
              </div>
              <Link
                to="/ai-assistant"
                className="flex items-center justify-between bg-gray-50 border border-gray-200 rounded-xl px-3 py-2 text-[10px] text-gray-400 hover:border-purple-300 hover:bg-purple-50 transition-all group"
              >
                <span>Ask anything...</span>
                <ArrowRight className="w-3 h-3 text-purple-400 group-hover:translate-x-0.5 transition-transform" aria-hidden="true" />
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
