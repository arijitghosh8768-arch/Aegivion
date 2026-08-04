
import React, { useState, useEffect } from 'react';
import { createRoute, Link } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import {
  Shield, AlertTriangle, CheckCircle2, Globe,
  Bell, HelpCircle, Settings, Search, Brain,
  ChevronRight, RefreshCw, ArrowRight, Database,
  ShieldCheck, FileCheck, Target, Users, Cloud,
  Server
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

const riskData = [
  { d: 'May 06', v: 78 }, { d: 'May 07', v: 55 }, { d: 'May 08', v: 68 },
  { d: 'May 09', v: 45 }, { d: 'May 10', v: 60 }, { d: 'May 11', v: 40 }, { d: 'May 12', v: 52 },
];
const threats = [
  { id: 1, title: 'IAM role over-privilege detected', env: 'AWS Production', time: '2m ago', dot: '#EF4444' },
  { id: 2, title: 'Unusual API activity', env: 'Azure Environment', time: '5m ago', dot: '#F59E0B' },
  { id: 3, title: 'Security group - open SSH', env: 'GCP VPC Network', time: '9m ago', dot: '#F59E0B' },
  { id: 4, title: 'Root login attempt', env: 'AWS Production', time: '12m ago', dot: '#3B82F6' },
];
const topAssets = [
  { name: 'S3 bucket - public access', env: 'AWS Production', sev: 'Critical', sevC: '#EF4444', sevBg: '#FEF2F2', score: 90 },
  { name: 'IAM user without MFA', env: 'AWS Production', sev: 'High', sevC: '#F59E0B', sevBg: '#FFFBEB', score: 75 },
  { name: 'Security group - open SSH', env: 'Azure Environment', sev: 'High', sevC: '#F59E0B', sevBg: '#FFFBEB', score: 65 },
  { name: 'Public VM with sensitive data', env: 'GCP Project', sev: 'Medium', sevC: '#3B82F6', sevBg: '#EFF6FF', score: 45 },
];

/* ─────────── CLOUD TOPOLOGY VISUALIZATION ─────────── */
function CloudTopology({ refreshing }: { refreshing: boolean }) {
  return (
    <div style={{ position: 'relative', width: '100%', height: 280, background: 'linear-gradient(180deg,#F0EEFF 0%,#F7F8FF 60%,#fff 100%)', borderRadius: 12, overflow: 'hidden' }}>

      {/* SVG base layer: orbit rings + lines + labels */}
      <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }} viewBox="0 0 580 280" preserveAspectRatio="xMidYMid meet">
        <defs>
          <linearGradient id="orb1" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#7C3AED" stopOpacity="0.08" />
            <stop offset="50%" stopColor="#6366F1" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#7C3AED" stopOpacity="0.08" />
          </linearGradient>
          <linearGradient id="orb2" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#A78BFA" stopOpacity="0.06" />
            <stop offset="50%" stopColor="#8B5CF6" stopOpacity="0.18" />
            <stop offset="100%" stopColor="#A78BFA" stopOpacity="0.06" />
          </linearGradient>
          <radialGradient id="glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#8B5CF6" stopOpacity="0.25" />
            <stop offset="100%" stopColor="#8B5CF6" stopOpacity="0" />
          </radialGradient>
          {/* Path for arc text labels */}
          <path id="topArcPath" d="M 95,140 A 195,92 0 0 1 485,140" fill="none" />
          <path id="botArcPath" d="M 95,140 A 195,92 0 0 0 485,140" fill="none" />
          <path id="leftArcPath" d="M 95,90 A 120,60 0 0 0 95,190" fill="none" />
          <path id="rightArcPath" d="M 485,90 A 120,60 0 0 1 485,190" fill="none" />
        </defs>

        {/* Glow blob */}
        <ellipse cx="290" cy="140" rx="120" ry="60" fill="url(#glow)" />

        {/* Outer orbit ellipse */}
        <ellipse cx="290" cy="140" rx="195" ry="92"
          fill="none" stroke="url(#orb1)" strokeWidth="1.5" strokeDasharray="8 5" />
        {/* Inner orbit ellipse */}
        <ellipse cx="290" cy="140" rx="120" ry="55"
          fill="none" stroke="url(#orb2)" strokeWidth="1" strokeDasharray="5 4" />

        {/* Arc text labels */}
        <text fontSize="8.5" fill="#A78BFA" letterSpacing="4" fontWeight="700" fontFamily="Inter,sans-serif">
          <textPath href="#topArcPath" startOffset="30%">IDENTITIES</textPath>
        </text>
        <text fontSize="8" fill="#93C5FD" letterSpacing="3.5" fontWeight="700" fontFamily="Inter,sans-serif">
          <textPath href="#topArcPath" startOffset="5%">NETWORK</textPath>
        </text>
        <text fontSize="8" fill="#C4B5FD" letterSpacing="3" fontWeight="700" fontFamily="Inter,sans-serif">
          <textPath href="#botArcPath" startOffset="8%">APPLICATIONS</textPath>
        </text>
        <text fontSize="8" fill="#6EE7B7" letterSpacing="3" fontWeight="700" fontFamily="Inter,sans-serif">
          <textPath href="#botArcPath" startOffset="70%">COMPUTE</textPath>
        </text>

        {/* Connecting lines from center to providers */}
        <line x1="290" y1="140" x2="290" y2="50" stroke="#C4B5FD" strokeWidth="1.2" strokeDasharray="5 3" opacity="0.7" />
        <line x1="290" y1="140" x2="95" y2="140" stroke="#93C5FD" strokeWidth="1.2" strokeDasharray="5 3" opacity="0.7" />
        <line x1="290" y1="140" x2="485" y2="140" stroke="#6EE7B7" strokeWidth="1.2" strokeDasharray="5 3" opacity="0.7" />
        <line x1="290" y1="140" x2="175" y2="215" stroke="#C4B5FD" strokeWidth="1" strokeDasharray="4 4" opacity="0.5" />
        <line x1="290" y1="140" x2="405" y2="215" stroke="#93C5FD" strokeWidth="1" strokeDasharray="4 4" opacity="0.5" />

        {/* Animated data flow dots */}
        <circle r="3.5" fill="#A78BFA" opacity="0.8">
          <animateMotion dur="2.5s" repeatCount="indefinite" path="M290,140 L290,50" />
        </circle>
        <circle r="3.5" fill="#60A5FA" opacity="0.8">
          <animateMotion dur="3s" repeatCount="indefinite" path="M290,140 L95,140" />
        </circle>
        <circle r="3.5" fill="#34D399" opacity="0.8">
          <animateMotion dur="3.5s" repeatCount="indefinite" path="M290,140 L485,140" />
        </circle>
        <circle r="2.5" fill="#C4B5FD" opacity="0.7">
          <animateMotion dur="2.8s" repeatCount="indefinite" path="M290,140 L175,215" />
        </circle>
        <circle r="2.5" fill="#93C5FD" opacity="0.7">
          <animateMotion dur="3.2s" repeatCount="indefinite" path="M290,140 L405,215" />
        </circle>

        {/* Small connection dots at intersections */}
        <circle cx="290" cy="50" r="3" fill="#A78BFA" opacity="0.4" />
        <circle cx="95" cy="140" r="3" fill="#60A5FA" opacity="0.4" />
        <circle cx="485" cy="140" r="3" fill="#34D399" opacity="0.4" />
      </svg>

      {/* AWS — top center */}
      <div style={{ position: 'absolute', top: 6, left: '50%', transform: 'translateX(-50%)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
        <div style={{ width: 52, height: 52, background: '#fff', borderRadius: 16, boxShadow: '0 8px 24px rgba(99,102,241,0.15)', border: '1px solid #F0F0FA', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ fontSize: 13, fontWeight: 900, color: '#FF9900', letterSpacing: -0.5 }}>aws</span>
        </div>
        <div style={{ fontSize: 9, color: '#10B981', fontWeight: 700, background: '#ECFDF5', border: '1px solid #D1FAE5', borderRadius: 20, padding: '2px 8px' }}>Secure · 12 Assets</div>
      </div>

      {/* Azure — left */}
      <div style={{ position: 'absolute', left: 18, top: '50%', transform: 'translateY(-50%)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
        <div style={{ width: 52, height: 52, background: '#fff', borderRadius: 16, boxShadow: '0 8px 24px rgba(99,102,241,0.15)', border: '1px solid #F0F0FA', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ fontSize: 22, fontWeight: 900, color: '#0078D4' }}>A</span>
        </div>
        <div style={{ fontSize: 9, color: '#10B981', fontWeight: 700, background: '#ECFDF5', border: '1px solid #D1FAE5', borderRadius: 20, padding: '2px 8px' }}>Secure · 10</div>
      </div>

      {/* GCP — right */}
      <div style={{ position: 'absolute', right: 18, top: '50%', transform: 'translateY(-50%)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
        <div style={{ width: 52, height: 52, background: '#fff', borderRadius: 16, boxShadow: '0 8px 24px rgba(99,102,241,0.15)', border: '1px solid #F0F0FA', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          {/* Google-style G */}
          <svg width="28" height="28" viewBox="0 0 28 28">
            <path d="M27.6 14.3c0-.9-.1-1.8-.2-2.6H14v5h7.6c-.3 1.7-1.4 3.2-3 4.2v3.5h4.8c2.8-2.6 4.2-6.4 4.2-10.1z" fill="#4285F4"/>
            <path d="M14 28c3.8 0 7-1.3 9.4-3.4l-4.8-3.5c-1.3.9-3 1.4-4.6 1.4-3.5 0-6.5-2.4-7.6-5.6H1.5v3.6C3.9 24.8 8.7 28 14 28z" fill="#34A853"/>
            <path d="M6.4 16.9c-.3-.9-.5-1.9-.5-2.9s.2-2 .5-2.9V7.5H1.5C.5 9.5 0 11.7 0 14s.5 4.5 1.5 6.5l4.9-3.6z" fill="#FBBC05"/>
            <path d="M14 5.6c2 0 3.7.7 5.1 2l3.8-3.8C20.9 1.5 17.8 0 14 0 8.7 0 3.9 3.2 1.5 7.5l4.9 3.6C7.5 8 10.5 5.6 14 5.6z" fill="#EA4335"/>
          </svg>
        </div>
        <div style={{ fontSize: 9, color: '#10B981', fontWeight: 700, background: '#ECFDF5', border: '1px solid #D1FAE5', borderRadius: 20, padding: '2px 8px' }}>Secure · 10</div>
      </div>

      {/* Center — Shield platform */}
      <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <div style={{ width: 58, height: 58, background: 'linear-gradient(135deg,#7C3AED,#4F46E5)', borderRadius: 18, display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 8px 28px rgba(124,58,237,0.5), 0 0 0 6px rgba(124,58,237,0.12)' }}>
          <Shield style={{ width: 28, height: 28, color: '#fff' }} />
        </div>
      </div>

      {/* Applications — bottom left */}
      <div style={{ position: 'absolute', bottom: 38, left: '28%', transform: 'translateX(-50%)' }}>
        <div style={{ width: 40, height: 40, borderRadius: 12, background: 'linear-gradient(135deg,#7C3AED,#6366F1)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 4px 14px rgba(124,58,237,0.3)' }}>
          <Users style={{ width: 18, height: 18, color: '#fff' }} />
        </div>
      </div>

      {/* Compute — bottom right */}
      <div style={{ position: 'absolute', bottom: 38, right: '28%', transform: 'translateX(50%)' }}>
        <div style={{ width: 40, height: 40, borderRadius: 12, background: 'linear-gradient(135deg,#4F46E5,#3B82F6)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 4px 14px rgba(79,70,229,0.3)' }}>
          <Server style={{ width: 18, height: 18, color: '#fff' }} />
        </div>
      </div>

      {/* "All Systems Operational" badge */}
      <div style={{ position: 'absolute', bottom: 10, left: '50%', transform: 'translateX(-50%)', display: 'flex', alignItems: 'center', gap: 6, background: '#fff', border: '1px solid #D1FAE5', borderRadius: 20, padding: '4px 14px', boxShadow: '0 2px 12px rgba(16,185,129,0.12)' }}>
        <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#10B981', display: 'inline-block', animation: 'pulse 2s infinite' }} />
        <span style={{ fontSize: 10, fontWeight: 700, color: '#059669' }}>All Systems Operational</span>
      </div>

      {/* Refresh + 360° controls */}
      <div style={{ position: 'absolute', top: 10, right: 10, display: 'flex', gap: 6 }}>
        <button aria-label="Refresh" style={{ width: 28, height: 28, borderRadius: 8, background: '#fff', border: '1px solid #EBEBF5', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', boxShadow: '0 1px 4px rgba(0,0,0,0.06)' }}>
          <RefreshCw style={{ width: 13, height: 13, color: '#9CA3AF' }} className={refreshing ? 'animate-spin' : ''} />
        </button>
        <div style={{ height: 28, borderRadius: 8, background: '#fff', border: '1px solid #EBEBF5', display: 'flex', alignItems: 'center', padding: '0 8px', fontSize: 10, fontWeight: 700, color: '#7C3AED', boxShadow: '0 1px 4px rgba(0,0,0,0.06)' }}>360°</div>
        <button aria-label="Expand" style={{ width: 28, height: 28, borderRadius: 8, background: '#fff', border: '1px solid #EBEBF5', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', boxShadow: '0 1px 4px rgba(0,0,0,0.06)' }}>
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M1 5V1h4M8 1h4v4M12 8v4H8M5 12H1V8" stroke="#9CA3AF" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
        </button>
      </div>
    </div>
  );
}

/* ─────────── MAIN DASHBOARD ─────────── */
function DashboardPage() {
  const user = useAuthStore((s: any) => s.user);
  const [findings, setFindings] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  const hour = new Date().getHours();
  const greeting = hour < 12 ? 'Good Morning' : hour < 17 ? 'Good Afternoon' : 'Good Evening';

  const fetchData = async () => {
    try {
      setRefreshing(true);
      const [fR, aR] = await Promise.allSettled([api.get('/v1/findings'), api.get('/v1/findings/assets')]);
      if (fR.status === 'fulfilled') setFindings(fR.value.data.findings || []);
      if (aR.status === 'fulfilled') setAssets(aR.value.data.assets || []);
    } catch (_) {} finally { setRefreshing(false); }
  };
  useEffect(() => { fetchData(); }, []);

  const critical = findings.filter((f: any) => f.severity === 'CRITICAL').length || 2;
  const secScore = Math.max(60, 100 - critical * 4 - findings.filter((f: any) => f.severity === 'HIGH').length * 2) || 92;
  const totalAssets = assets.length || 32;

  /* Stat card definitions */
  const stats = [
    {
      label: 'TOTAL ASSETS', value: totalAssets, sub: 'Across 3 Clouds',
      icon: <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 2L2 7l9 5 9-5-9-5z" fill="#6366F1" opacity="0.8"/><path d="M2 15l9 5 9-5M2 11l9 5 9-5" stroke="#6366F1" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>,
      iconBg: '#EEF2FF',
    },
    {
      label: 'CRITICAL RISKS', value: critical, sub: 'Immediate attention',
      icon: <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><circle cx="11" cy="11" r="9" stroke="#EF4444" strokeWidth="1.5"/><circle cx="11" cy="11" r="5" stroke="#EF4444" strokeWidth="1.5"/><circle cx="11" cy="11" r="1.5" fill="#EF4444"/><line x1="11" y1="2" x2="11" y2="5" stroke="#EF4444" strokeWidth="1.5" strokeLinecap="round"/><line x1="11" y1="17" x2="11" y2="20" stroke="#EF4444" strokeWidth="1.5" strokeLinecap="round"/><line x1="2" y1="11" x2="5" y2="11" stroke="#EF4444" strokeWidth="1.5" strokeLinecap="round"/><line x1="17" y1="11" x2="20" y2="11" stroke="#EF4444" strokeWidth="1.5" strokeLinecap="round"/></svg>,
      iconBg: '#FEF2F2',
    },
    {
      label: 'SECURITY SCORE', value: `${secScore}/100`, sub: 'Excellent',
      icon: <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><path d="M11 2L4 5v6c0 4.4 3 8.5 7 9.5 4-1 7-5.1 7-9.5V5L11 2z" fill="#10B981" opacity="0.2"/><path d="M11 2L4 5v6c0 4.4 3 8.5 7 9.5 4-1 7-5.1 7-9.5V5L11 2z" stroke="#10B981" strokeWidth="1.5" strokeLinejoin="round"/><path d="M7.5 11l2.5 2.5 5-5" stroke="#10B981" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>,
      iconBg: '#ECFDF5',
    },
    {
      label: 'COMPLIANCE', value: '75%', sub: '6/8 Compliant',
      icon: <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><rect x="4" y="2" width="14" height="18" rx="2" stroke="#3B82F6" strokeWidth="1.5"/><path d="M7 7h8M7 11h8M7 15h5" stroke="#3B82F6" strokeWidth="1.5" strokeLinecap="round"/></svg>,
      iconBg: '#EFF6FF',
    },
    {
      label: 'ATTACK SURFACE', value: 'Low', sub: 'Exposure level',
      icon: <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><circle cx="11" cy="11" r="9" stroke="#6366F1" strokeWidth="1.5"/><ellipse cx="11" cy="11" rx="4" ry="9" stroke="#6366F1" strokeWidth="1.2"/><line x1="2" y1="11" x2="20" y2="11" stroke="#6366F1" strokeWidth="1.2"/></svg>,
      iconBg: '#EEF2FF',
    },
  ];

  const S = {
    card: { background: '#fff', border: '1px solid #F0F0F8', borderRadius: 16, boxShadow: '0 2px 12px rgba(99,102,241,0.06)' } as React.CSSProperties,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: '#F6F7FF', fontFamily: "'Inter','Segoe UI',system-ui,sans-serif" }}>

      {/* ═══ HEADER ═══ */}
      <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 24px', background: '#fff', borderBottom: '1px solid #F0F0F8', flexShrink: 0, gap: 16 }}>
        <div style={{ flexShrink: 0 }}>
          <div style={{ fontSize: 16, fontWeight: 800, color: '#111827' }}>{greeting}, {user?.first_name || 'Admin'} 👋</div>
          <div style={{ fontSize: 11, color: '#9CA3AF', marginTop: 2 }}>Aegivion AI is actively protecting your cloud environment.</div>
        </div>
        {/* Search — centered */}
        <div style={{ flex: 1, maxWidth: 340, position: 'relative' }}>
          <Search style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, color: '#9CA3AF' }} />
          <input type="search" placeholder="Search assets, threats, incidents..."
            style={{ width: '100%', paddingLeft: 36, paddingRight: 14, paddingTop: 8, paddingBottom: 8, fontSize: 11, background: '#F8F8FF', border: '1px solid #EBEBF5', borderRadius: 12, outline: 'none', color: '#374151', boxSizing: 'border-box' }} />
        </div>
        {/* Right icons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <button aria-label="Notifications" style={{ position: 'relative', width: 36, height: 36, borderRadius: 10, background: '#F8F8FF', border: '1px solid #EBEBF5', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
            <Bell style={{ width: 16, height: 16, color: '#6B7280' }} />
            <span style={{ position: 'absolute', top: 7, right: 7, width: 8, height: 8, background: '#7C3AED', borderRadius: '50%', border: '2px solid #fff' }} />
          </button>
          <button aria-label="Help" style={{ width: 36, height: 36, borderRadius: 10, background: '#F8F8FF', border: '1px solid #EBEBF5', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
            <HelpCircle style={{ width: 16, height: 16, color: '#6B7280' }} />
          </button>
          <button aria-label="Settings" style={{ width: 36, height: 36, borderRadius: 10, background: '#F8F8FF', border: '1px solid #EBEBF5', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
            <Settings style={{ width: 16, height: 16, color: '#6B7280' }} />
          </button>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: 'linear-gradient(135deg,#7C3AED,#4F46E5)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 4px 12px rgba(124,58,237,0.4)' }}>
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M9 2l1.5 4.5H15l-3.75 2.75 1.5 4.5L9 11l-3.75 2.75 1.5-4.5L3 6.5h4.5L9 2z" fill="white"/></svg>
          </div>
        </div>
      </header>

      {/* ═══ BODY ═══ */}
      <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
        <div style={{ display: 'flex', gap: 14, minHeight: '100%' }}>

          {/* ── CENTER COLUMN ── */}
          <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>

            {/* Stat cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 10 }}>
              {stats.map((s, i) => (
                <div key={i} style={{ ...S.card, padding: '14px 14px 12px' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                    <div style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: '0.07em', textTransform: 'uppercase', color: '#9CA3AF', lineHeight: 1.3 }}>{s.label}</div>
                    <div style={{ width: 34, height: 34, borderRadius: 10, background: s.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>{s.icon}</div>
                  </div>
                  <div style={{ fontSize: 24, fontWeight: 900, color: '#111827', lineHeight: 1 }}>{s.value}</div>
                  <div style={{ fontSize: 10, color: '#9CA3AF', marginTop: 6 }}>{s.sub}</div>
                </div>
              ))}
            </div>

            {/* Cloud Topology Card */}
            <div style={{ ...S.card, padding: '14px 16px 12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 800, color: '#111827', letterSpacing: '-0.01em' }}>Cloud Environment Overview</div>
                  <div style={{ fontSize: 10, color: '#9CA3AF', marginTop: 2 }}>Real-time 360° security visualization</div>
                </div>
              </div>
              <CloudTopology refreshing={refreshing} />
            </div>

            {/* Risk Trend + Top Risky Assets */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>

              {/* Risk Trend */}
              <div style={{ ...S.card, padding: '14px 14px 10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                  <div>
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#111827' }}>Risk Trend </span>
                    <span style={{ fontSize: 11, color: '#9CA3AF' }}>(Last 7 Days)</span>
                  </div>
                  <select style={{ fontSize: 10, border: '1px solid #EBEBF5', borderRadius: 8, padding: '4px 8px', color: '#6B7280', background: '#FAFAFE', outline: 'none', cursor: 'pointer' }}>
                    <option>Overall Risk</option>
                  </select>
                </div>
                <ResponsiveContainer width="100%" height={130}>
                  <AreaChart data={riskData} margin={{ top: 4, right: 4, left: -26, bottom: 0 }}>
                    <defs>
                      <linearGradient id="rg" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#7C3AED" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#7C3AED" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#F3F4F6" vertical={false} />
                    <XAxis dataKey="d" tick={{ fontSize: 8, fill: '#9CA3AF' }} tickLine={false} axisLine={false} />
                    <YAxis tick={{ fontSize: 8, fill: '#9CA3AF' }} tickLine={false} axisLine={false} domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} />
                    <Tooltip contentStyle={{ fontSize: 10, borderRadius: 10, border: '1px solid #EBEBF5', boxShadow: '0 4px 16px rgba(0,0,0,0.08)' }} cursor={{ stroke: '#7C3AED', strokeWidth: 1, strokeDasharray: '4 3' }} />
                    <Area type="monotone" dataKey="v" stroke="#7C3AED" strokeWidth={2.5} fill="url(#rg)"
                      dot={{ r: 3.5, fill: '#7C3AED', strokeWidth: 0 }}
                      activeDot={{ r: 5, fill: '#5B21B6', strokeWidth: 0 }} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Top Risky Assets */}
              <div style={{ ...S.card, padding: '14px 14px 12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#111827' }}>Top Risky Assets</span>
                  <Link to="/assets" style={{ fontSize: 10, color: '#7C3AED', fontWeight: 600, textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 2 }}>
                    View All <ChevronRight style={{ width: 12, height: 12 }} />
                  </Link>
                </div>
                {topAssets.map((a, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: i < topAssets.length - 1 ? 12 : 0 }}>
                    <div style={{ width: 28, height: 28, borderRadius: 8, background: '#F8F8FF', border: '1px solid #EBEBF5', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14, flexShrink: 0 }}>
                      {i === 0 ? '🟠' : i === 1 ? '🔐' : i === 2 ? '☁️' : '💾'}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 11, fontWeight: 600, color: '#111827', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.name}</div>
                      <div style={{ fontSize: 9.5, color: '#9CA3AF', marginTop: 1 }}>{a.env}</div>
                    </div>
                    <span style={{ fontSize: 9, fontWeight: 700, color: a.sevC, background: a.sevBg, padding: '2px 8px', borderRadius: 6, flexShrink: 0 }}>{a.sev}</span>
                    <span style={{ fontSize: 12, fontWeight: 900, color: '#374151', width: 22, textAlign: 'right', flexShrink: 0 }}>{a.score}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── RIGHT PANEL ── */}
          <div style={{ width: 240, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>

            {/* AI Security Insights */}
            <div style={{ borderRadius: 18, padding: '16px 16px 14px', background: 'linear-gradient(145deg,#7C3AED 0%,#4F46E5 100%)', boxShadow: '0 8px 28px rgba(124,58,237,0.35)' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 10 }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>AI Security Insights</div>
                  <div style={{ fontSize: 9, color: '#C4B5FD', marginTop: 2 }}>Powered by Aegivion AI</div>
                </div>
                <Brain style={{ width: 22, height: 22, color: '#C4B5FD' }} />
              </div>
              <p style={{ fontSize: 10.5, color: '#DDD6FE', lineHeight: 1.55, marginBottom: 12 }}>
                I've analyzed your environment and found{' '}
                <strong style={{ color: '#fff' }}>1 critical misconfiguration</strong> in{' '}
                <strong style={{ color: '#FCD34D' }}>AWS S3 bucket policy.</strong>
              </p>
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 9, color: '#C4B5FD', marginBottom: 6 }}>Risk Level</div>
                <div style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
                  {[0, 1, 2, 3, 4].map(i => (
                    <div key={i} style={{ height: 5, flex: 1, borderRadius: 3, background: i < 3 ? '#F87171' : 'rgba(255,255,255,0.2)' }} />
                  ))}
                </div>
                <div style={{ fontSize: 10, color: '#FCA5A5', fontWeight: 700 }}>High</div>
              </div>
              <button style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, background: '#fff', color: '#7C3AED', fontWeight: 700, fontSize: 11, padding: '9px', borderRadius: 12, border: 'none', cursor: 'pointer', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>
                View &amp; Resolve <ArrowRight style={{ width: 13, height: 13 }} />
              </button>
            </div>

            {/* Live Threat Feed */}
            <div style={{ ...S.card, padding: '14px 14px 12px', flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#111827' }}>Live Threat Feed</div>
                <Link to="/findings" style={{ fontSize: 10, color: '#7C3AED', fontWeight: 600, textDecoration: 'none' }}>View All</Link>
              </div>
              <div style={{ fontSize: 9.5, color: '#9CA3AF', marginBottom: 12 }}>Real-time security events</div>
              {threats.map(t => (
                <div key={t.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 12 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: t.dot, marginTop: 3, flexShrink: 0, boxShadow: `0 0 6px ${t.dot}80` }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 10.5, fontWeight: 600, color: '#1F2937', lineHeight: 1.35 }}>{t.title}</div>
                    <div style={{ fontSize: 9, color: '#9CA3AF', marginTop: 2 }}>{t.env}</div>
                  </div>
                  <div style={{ fontSize: 9, color: '#9CA3AF', flexShrink: 0, marginTop: 1 }}>{t.time}</div>
                </div>
              ))}
            </div>

            {/* Ask AI */}
            <div style={{ ...S.card, padding: '14px 14px 12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#111827' }}>Ask Aegivion AI</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#4ade80', display: 'inline-block' }} />
                  <span style={{ fontSize: 9.5, color: '#10B981', fontWeight: 600 }}>Online</span>
                </div>
              </div>
              <div style={{ fontSize: 10, color: '#9CA3AF', marginBottom: 10 }}>How can I help you securing your cloud today?</div>
              {/* Waveform decoration */}
              <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 20, marginBottom: 10 }}>
                {[4, 8, 12, 7, 14, 5, 10, 16, 8, 5, 11, 7].map((h, i) => (
                  <div key={i} style={{ flex: 1, background: 'linear-gradient(to top,#7C3AED,#A78BFA)', borderRadius: 2, opacity: 0.5, height: h }} />
                ))}
              </div>
              <Link to="/ai-assistant" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#F8F8FF', border: '1px solid #EBEBF5', borderRadius: 10, padding: '8px 12px', textDecoration: 'none' }}>
                <span style={{ fontSize: 10, color: '#9CA3AF' }}>Ask anything...</span>
                <ArrowRight style={{ width: 13, height: 13, color: '#7C3AED' }} />
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

