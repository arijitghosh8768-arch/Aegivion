import React, { useState, useEffect } from 'react';
import { createRoute, Link, useNavigate } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { api } from '@/lib/api';
import {
  Shield, AlertTriangle, CheckCircle2, Globe,
  Bell, HelpCircle, Settings, Search, Brain,
  ChevronRight, RefreshCw, ArrowRight, Database,
  ShieldCheck, FileCheck, Target, Users, Cloud,
  Server
} from 'lucide-react';
import { useAuthStore } from '@/store/auth-store';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: DashboardPage,
});

const defaultThreats = [
  { id: 1, title: 'IAM role over-privilege detected', env: 'AWS Production', time: '2m ago', dot: '#EF4444' },
  { id: 2, title: 'Unusual API activity', env: 'Azure Environment', time: '5m ago', dot: '#F59E0B' },
  { id: 3, title: 'Security group - open SSH', env: 'GCP VPC Network', time: '9m ago', dot: '#F59E0B' },
  { id: 4, title: 'Root login attempt', env: 'AWS Production', time: '12m ago', dot: '#3B82F6' },
];

const defaultTopAssets = [
  { name: 'S3 bucket - public access', env: 'AWS Production', sev: 'Critical', sevC: '#EF4444', sevBg: '#FEF2F2', score: 100 },
  { name: 'IAM user without MFA', env: 'AWS Production', sev: 'High', sevC: '#F59E0B', sevBg: '#FFFBEB', score: 90 },
  { name: 'Security group - open SSH', env: 'Azure Environment', sev: 'High', sevC: '#F59E0B', sevBg: '#FFFBEB', score: 70 },
  { name: 'Public VM with sensitive data', env: 'GCP Project', sev: 'High', sevC: '#F59E0B', sevBg: '#FFFBEB', score: 70 },
];

/* ─────────── CLOUD TOPOLOGY VISUALIZATION ─────────── */
function CloudTopology({ scanning }: { scanning: boolean }) {
  const [paused, setPaused] = useState(false);

  return (
    <div className={`viz ${paused ? 'paused' : ''}`} id="vizBox" style={{ position: 'relative', borderRadius: 12, background: 'radial-gradient(120% 90% at 50% 40%,#101a35 0%,#0b1020 70%)', border: '1px solid #16203a', overflow: 'hidden' }}>
      <svg viewBox="0 0 760 430" id="vizSvg" style={{ display: 'block', width: '100%', height: 'auto' }}>
        <defs>
          <linearGradient id="gCloud" x1="0" y1="-76" x2="0" y2="-8" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#ffffff" /><stop offset="1" stopColor="#b9c3d4" />
          </linearGradient>
          <linearGradient id="gSlab" x1="0" y1="-30" x2="0" y2="40" gradientUnits="userSpaceOnUse">
            <stop offset="0" stopColor="#2a3757" /><stop offset="1" stopColor="#141d36" />
          </linearGradient>
          <linearGradient id="gShield" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#a78bfa" /><stop offset=".55" stopColor="#7c3aed" /><stop offset="1" stopColor="#4c1d95" />
          </linearGradient>
          <linearGradient id="gAzure" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#35b6f0" /><stop offset="1" stopColor="#1d4ed8" />
          </linearGradient>
          <radialGradient id="gHalo"><stop offset="0" stopColor="#7c3aed" stopOpacity=".5" /><stop offset="1" stopColor="#7c3aed" stopOpacity="0" /></radialGradient>
          <filter id="fGlow" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="6" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
          <marker id="mArrow" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#f97316" /></marker>
          {/* orbit motion paths */}
          <path id="orbitOuter" d="M50,235 a330,130 0 1,0 660,0 a330,130 0 1,0 -660,0"/>
          <path id="orbitMid"   d="M120,235 a260,102 0 1,0 520,0 a260,102 0 1,0 -520,0"/>
          <path id="orbitInner" d="M190,235 a190,74 0 1,0 380,0 a190,74 0 1,0 -380,0"/>
          <path id="orbitCore"  d="M260,235 a120,46 0 1,0 240,0 a120,46 0 1,0 -240,0"/>
        </defs>

        {/* orbital rings (dashes always flowing) */}
        <g fill="none">
          <ellipse className="ringE" cx="380" cy="235" rx="330" ry="130" stroke="rgba(99,102,241,.35)" strokeDasharray="5 7" />
          <ellipse className="ringE rev" cx="380" cy="235" rx="260" ry="102" stroke="rgba(59,130,246,.35)" strokeDasharray="1 5" />
          <ellipse className="ringE" cx="380" cy="235" rx="190" ry="74" stroke="rgba(59,130,246,.28)" strokeDasharray="3 6" />
          <ellipse className="ringE rev" cx="380" cy="235" rx="120" ry="46" stroke="rgba(139,92,246,.4)" strokeDasharray="2 5" />
          <path d="M62,225 A320,128 0 0 1 168,138" stroke="rgba(59,130,246,.7)" strokeWidth="1.6" />
          <path d="M127,318 A330,130 0 0 0 633,318" stroke="rgba(249,115,22,.25)" strokeWidth="5" />
          <path d="M127,318 A330,130 0 0 0 633,318" stroke="#f97316" strokeWidth="2.2" markerEnd="url(#mArrow)" />
        </g>

        {/* travelling light pulses (continuous rotation) */}
        <g>
          <ellipse className="pulseArc" cx="380" cy="235" rx="330" ry="130" stroke="#f97316" strokeWidth="2.5" opacity=".85" />
          <ellipse className="pulseArc p2" cx="380" cy="235" rx="260" ry="102" stroke="#60a5fa" strokeWidth="2.5" opacity=".85" />
          <ellipse className="pulseArc p3" cx="380" cy="235" rx="190" ry="74" stroke="#a78bfa" strokeWidth="2.5" opacity=".85" />
        </g>

        {/* ring labels */}
        <g fill="#64748b" fontSize="10" letterSpacing="3" fontWeight="600">
          <text x="252" y="126" transform="rotate(-21 252 126)">IDENTITIES</text>
          <text x="298" y="163" transform="rotate(-21 298 163)">NETWORK</text>
          <text x="196" y="330" transform="rotate(33 196 330)">APPLICATIONS</text>
          <text x="556" y="345" transform="rotate(-33 556 345)">COMPUTE</text>
        </g>

        {/* orbiting glowing dots */}
        <g filter="url(#fGlow)">
          <circle r="3.2" fill="#f472b6"><animateMotion dur="16s" repeatCount="indefinite"><mpath href="#orbitOuter"/></animateMotion></circle>
          <circle r="3.5" fill="#fb923c"><animateMotion dur="16s" begin="-8s" repeatCount="indefinite"><mpath href="#orbitOuter"/></animateMotion></circle>
          <circle r="3.2" fill="#60a5fa"><animateMotion dur="11s" repeatCount="indefinite" calcMode="linear" keyPoints="1;0" keyTimes="0;1"><mpath href="#orbitMid"/></animateMotion></circle>
          <circle r="3.5" fill="#f87171"><animateMotion dur="11s" begin="-5.5s" repeatCount="indefinite" calcMode="linear" keyPoints="1;0" keyTimes="0;1"><mpath href="#orbitMid"/></animateMotion></circle>
          <circle r="2.8" fill="#34d399"><animateMotion dur="8s" repeatCount="indefinite"><mpath href="#orbitInner"/></animateMotion></circle>
          <circle r="2.6" fill="#fbbf24"><animateMotion dur="6s" repeatCount="indefinite" calcMode="linear" keyPoints="1;0" keyTimes="0;1"><mpath href="#orbitCore"/></animateMotion></circle>
        </g>

        {/* central shield platform */}
        <g transform="translate(380,235)">
          <circle className="shieldGlow animate-pulse-slow" r="86" cy="-40" fill="url(#gHalo)" />
          <path d="M-96,18 L-96,30 L0,78 L0,66 Z" fill="#0b1226" />
          <path d="M96,18 L96,30 L0,78 L0,66 Z" fill="#182444" />
          <path d="M0,-30 L96,18 L0,66 L-96,18 Z" fill="url(#gSlab)" stroke="rgba(139,92,246,.4)" />
          <path d="M0,-12 L58,16 L0,44 L-58,16 Z" fill="rgba(99,102,241,.14)" stroke="rgba(139,92,246,.55)" />
          <g filter="url(#fGlow)">
            <path d="M0,-122 L37,-108 V-74 Q37,-42 0,-24 Q-37,-42 -37,-74 V-108 Z" fill="url(#gShield)" stroke="#c4b5fd" strokeWidth="1.6" />
            <path d="M0,-106 L24,-97 V-74 Q24,-52 0,-40 Q-24,-52 -24,-74 V-97 Z" fill="rgba(255,255,255,.14)" stroke="rgba(255,255,255,.75)" strokeWidth="1.4" />
          </g>
        </g>

        {/* AWS cloud (top) */}
        <g transform="translate(380,96)">
          <ellipse cy="6" rx="62" ry="10" fill="#000" opacity=".35" />
          <path d="M-56,0 L-56,10 L0,38 L0,28 Z" fill="#0b1226" /><path d="M56,0 L56,10 L0,38 L0,28 Z" fill="#182444" />
          <path d="M0,-28 L56,0 L0,28 L-56,0 Z" fill="url(#gSlab)" stroke="rgba(59,130,246,.35)" />
          <g fill="url(#gCloud)">
            <circle cx="-24" cy="-42" r="19" /><circle cx="0" cy="-52" r="25" /><circle cx="24" cy="-40" r="17" />
            <rect x="-42" y="-42" width="84" height="26" rx="13" />
          </g>
          <text y="-24" textAnchor="middle" fontSize="19" fontWeight="800" fill="#101828">aws</text>
          <path d="M-14,-20 Q0,-12 14,-21" fill="none" stroke="#f97316" strokeWidth="2.6" strokeLinecap="round" />
        </g>
        <g fontSize="10.5" textAnchor="start">
          <text x="448" y="80" fill="#4ade80" fontWeight="700">Secure</text>
          <text x="448" y="95" fill="#8b96ad">12 Assets</text>
        </g>

        {/* Azure cloud (left) */}
        <g transform="translate(140,178)">
          <ellipse cy="6" rx="60" ry="9" fill="#000" opacity=".35" />
          <path d="M-54,0 L-54,10 L0,37 L0,27 Z" fill="#0b1226" /><path d="M54,0 L54,10 L0,37 L0,27 Z" fill="#182444" />
          <path d="M0,-27 L54,0 L0,27 L-54,0 Z" fill="url(#gSlab)" stroke="rgba(59,130,246,.35)" />
          <g fill="url(#gCloud)">
            <circle cx="-23" cy="-41" r="18" /><circle cx="0" cy="-50" r="24" /><circle cx="23" cy="-39" r="16" />
            <rect x="-40" y="-41" width="80" height="25" rx="12.5" />
          </g>
          <text y="-20" textAnchor="middle" fontSize="27" fontWeight="800" fill="url(#gAzure)" transform="skewX(-6)">A</text>
        </g>
        <g fontSize="10.5" textAnchor="middle">
          <text x="96" y="262" fill="#4ade80" fontWeight="700">Secure</text>
          <text x="96" y="277" fill="#8b96ad">10 Assets</text>
        </g>

        {/* GCP cloud (right) */}
        <g transform="translate(620,178)">
          <ellipse cy="6" rx="60" ry="9" fill="#000" opacity=".35" />
          <path d="M-54,0 L-54,10 L0,37 L0,27 Z" fill="#0b1226" /><path d="M54,0 L54,10 L0,37 L0,27 Z" fill="#182444" />
          <path d="M0,-27 L54,0 L0,27 L-54,0 Z" fill="url(#gSlab)" stroke="rgba(59,130,246,.35)" />
          <g fill="url(#gCloud)">
            <circle cx="-23" cy="-41" r="18" /><circle cx="0" cy="-50" r="24" /><circle cx="23" cy="-39" r="16" />
            <rect x="-40" y="-41" width="80" height="25" rx="12.5" />
          </g>
          <g transform="translate(0,-32)" fill="none" strokeWidth="5.5">
            <circle r="10" stroke="#ea4335" strokeDasharray="15.7 47.1" transform="rotate(-90)" />
            <circle r="10" stroke="#4285f4" strokeDasharray="15.7 47.1" />
            <circle r="10" stroke="#34a853" strokeDasharray="15.7 47.1" transform="rotate(90)" />
            <circle r="10" stroke="#fbbc05" strokeDasharray="15.7 47.1" transform="rotate(180)" />
          </g>
        </g>
        <g fontSize="10.5" textAnchor="middle">
          <text x="664" y="262" fill="#4ade80" fontWeight="700">Secure</text>
          <text x="664" y="277" fill="#8b96ad">10 Assets</text>
        </g>

        {/* node badges */}
        <g transform="translate(181,301)">
          <circle r="23" fill="#6d28d9" stroke="#a78bfa" strokeWidth="1.5" filter="url(#fGlow)" />
          <g fill="none" stroke="#fff" strokeWidth="1.8" strokeLinecap="round">
            <circle cx="-3.5" cy="-4" r="3.4" /><path d="M-9.5,7c.6-3.6 3-5.6 6-5.6s5.4 2 6 5.6" />
            <circle cx="5.5" cy="-3" r="2.7" /><path d="M5.5,1.6c2.6,0 4.6,1.8 5.2,4.8" />
          </g>
        </g>
        <g transform="translate(579,301)">
          <circle r="20" fill="#1d4ed8" stroke="#60a5fa" strokeWidth="1.5" filter="url(#fGlow)" />
          <g fill="none" stroke="#fff" stroke-width="1.7" stroke-linecap="round">
            <ellipse cx="0" cy="-6" rx="7" ry="2.8" /><path d="M-7,-6v12c0,1.6 3.1,2.9 7,2.9s7-1.3 7-2.9V-6" /><path d="M-7,0c0,1.6 3.1,2.9 7,2.9s7-1.3 7-2.9" />
          </g>
        </g>
      </svg>
      <div className="status-pill animate-blink" style={{ position: 'absolute', left: '50%', bottom: 10, transform: 'translateX(-50%)', display: 'flex', alignItems: 'center', gap: 8, background: 'rgba(10,16,32,.85)', border: '1px solid rgba(34,197,94,.35)', color: '#4ade80', fontSize: '11.5px', fontWeight: 600, padding: '6px 14px', borderRadius: 999, backdropFilter: 'blur(4px)' }}>
        <i style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--green)', boxShadow: '0 0 8px var(--green)' }}></i>
        <button onClick={() => setPaused(!paused)} style={{ background: 'none', border: 'none', color: 'inherit', fontWeight: 'inherit', fontSize: 'inherit', padding: 0 }}>
          {paused ? 'Auto-rotation Paused' : 'All Systems Operational'}
        </button>
      </div>
    </div>
  );
}



/* ─────────── MAIN DASHBOARD PAGE ─────────── */
function DashboardPage() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [eventDetailOpen, setEventDetailOpen] = useState(false);

  const fetchData = async () => {
    try {
      setRefreshing(true);
      const [fR, aR] = await Promise.allSettled([api.get('/v1/findings'), api.get('/v1/findings/assets')]);
      if (fR.status === 'fulfilled') setFindings(fR.value.data.findings || []);
      if (aR.status === 'fulfilled') setAssets(aR.value.data.assets || []);
    } catch (_) {
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const triggerScan = async () => {
    setScanning(true);
    try {
      await api.post('/v1/findings/scan');
      await fetchData();
    } catch (e) {
      console.error(e);
    } finally {
      setScanning(false);
    }
  };

  const critical = findings.filter((f: any) => f.severity?.toUpperCase() === 'CRITICAL').length || 2;
  const high = findings.filter((f: any) => f.severity?.toUpperCase() === 'HIGH').length || 2;
  const medium = findings.filter((f: any) => f.severity?.toUpperCase() === 'MEDIUM').length || 2;
  const low = findings.filter((f: any) => f.severity?.toUpperCase() === 'LOW').length || 15;

  const totalFindings = findings.length || 21;
  const secScore = Math.max(10, 100 - findings.length * 10);
  const totalAssets = assets.length || 32;

  return (
    <div className="space-y-6" style={{ color: 'var(--text)' }}>
      
      {/* STATS ROW */}
      <section className="stats" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(215px,1fr))', gap: 16 }}>
        <div className="stat animate-rise" style={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="stat-top" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span className="stat-label" style={{ fontSize: '10.5px', letterSpacing: '.12em', fontWeight: 700, color: 'var(--muted)' }}>TOTAL ASSETS</span>
            <span className="stat-ic purple" style={{ width: 40, height: 40, borderRadius: 10, display: 'grid', placeItems: 'center', background: 'rgba(139,92,246,.14)', color: '#a78bfa' }}>
              <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 8l-9-5-9 5 9 5 9-5z" /><path d="M3 8v8l9 5 9-5V8" /><path d="M12 13v8" /></svg>
            </span>
          </div>
          <div className="stat-value" style={{ fontSize: 26, fontWeight: 800, marginTop: 2 }}>{totalAssets}</div>
          <div className="stat-foot" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 4, gap: 8 }}>
            <span className="t-blue" style={{ color: '#60a5fa', fontSize: '11.5px' }}>Across 3 Clouds</span>
            <svg width="92" height="26" viewBox="0 0 92 26"><polyline points="2,14 14,12 26,16 38,10 50,14 62,9 74,13 86,11 90,12" fill="none" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round" /></svg>
          </div>
        </div>

        <div className="stat animate-rise" style={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="stat-top" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span className="stat-label" style={{ fontSize: '10.5px', letterSpacing: '.12em', fontWeight: 700, color: 'var(--muted)' }}>CRITICAL RISKS</span>
            <span className="stat-ic red" style={{ width: 40, height: 40, borderRadius: 10, display: 'grid', placeItems: 'center', background: 'rgba(239,68,68,.13)', color: '#f87171' }}>
              <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="7" /><circle cx="12" cy="12" r="2.5" /><path d="M12 2v4M12 18v4M2 12h4M18 12h4" /></svg>
            </span>
          </div>
          <div className="stat-value" style={{ fontSize: 26, fontWeight: 800, marginTop: 2 }}>{critical}</div>
          <div className="stat-foot" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 4, gap: 8 }}>
            <span className="t-red" style={{ color: 'var(--red)', fontSize: '11.5px' }}>Immediate attention</span>
            <svg width="92" height="26" viewBox="0 0 92 26"><polyline points="2,16 14,15 26,18 38,14 50,17 62,12 74,16 86,14 90,15" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" /></svg>
          </div>
        </div>

        <div className="stat animate-rise" style={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="stat-top" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span className="stat-label" style={{ fontSize: '10.5px', letterSpacing: '.12em', fontWeight: 700, color: 'var(--muted)' }}>SECURITY SCORE</span>
            <span className="stat-ic green" style={{ width: 40, height: 40, borderRadius: 10, display: 'grid', placeItems: 'center', background: 'rgba(34,197,94,.13)', color: '#4ade80' }}>
              <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 3.5v5c0 5-3.4 9.4-8 11.5-4.6-2.1-8-6.5-8-11.5v-5L12 2z" /><path d="M9 12l2.2 2.2L15.5 10" /></svg>
            </span>
          </div>
          <div className="stat-value" style={{ fontSize: 26, fontWeight: 800, marginTop: 2 }}>{secScore} <small style={{ fontSize: 14, color: 'var(--muted)', fontWeight: 600 }}>/100</small></div>
          <div className="stat-foot" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 4, gap: 8 }}>
            <span className="t-green" style={{ color: 'var(--green)', fontSize: '11.5px' }}>Excellent</span>
            <svg width="92" height="26" viewBox="0 0 92 26"><polyline points="2,15 14,13 26,16 38,11 50,14 62,10 74,13 86,9 90,10" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" /></svg>
          </div>
        </div>

        <div className="stat animate-rise" style={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="stat-top" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span className="stat-label" style={{ fontSize: '10.5px', letterSpacing: '.12em', fontWeight: 700, color: 'var(--muted)' }}>COMPLIANCE</span>
            <span className="stat-ic blue" style={{ width: 40, height: 40, borderRadius: 10, display: 'grid', placeItems: 'center', background: 'rgba(59,130,246,.13)', color: '#60a5fa' }}>
              <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="4" width="14" height="17" rx="2" /><path d="M9 4a3 3 0 0 1 6 0" /><path d="M9 11h6M9 15h6" /></svg>
            </span>
          </div>
          <div className="stat-value" style={{ fontSize: 26, fontWeight: 800, marginTop: 2 }}>75<small style={{ fontSize: 14, color: 'var(--muted)', fontWeight: 600 }}>%</small></div>
          <div className="stat-foot" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 4, gap: 8 }}>
            <span className="t-blue" style={{ color: '#60a5fa', fontSize: '11.5px' }}>6/8 Compliant</span>
            <svg width="92" height="26" viewBox="0 0 92 26"><polyline points="2,14 14,15 26,12 38,15 50,11 62,14 74,10 86,13 90,11" fill="none" stroke="#3b82f6" stroke-width="2" stroke-linecap="round" /></svg>
          </div>
        </div>

        <div className="stat animate-rise" style={{ background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="stat-top" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span className="stat-label" style={{ fontSize: '10.5px', letterSpacing: '.12em', fontWeight: 700, color: 'var(--muted)' }}>ATTACK SURFACE</span>
            <span className="stat-ic purple" style={{ width: 40, height: 40, borderRadius: 10, display: 'grid', placeItems: 'center', background: 'rgba(139,92,246,.14)', color: '#a78bfa' }}>
              <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9" /><path d="M3 12h18" /><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z" /></svg>
            </span>
          </div>
          <div className="stat-value" style={{ fontSize: 26, fontWeight: 800, marginTop: 2 }}>Low</div>
          <div className="stat-foot" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 4, gap: 8 }}>
            <span className="t-muted" style={{ color: 'var(--muted)', fontSize: '11.5px' }}>Exposure level</span>
            <svg width="92" height="26" viewBox="0 0 92 26"><polyline points="2,15 14,14 26,17 38,13 50,16 62,12 74,15 86,13 90,14" fill="none" stroke="#8b5cf6" stroke-width="2" stroke-linecap="round" /></svg>
          </div>
        </div>
      </section>

      {/* DUAL PANELS */}
      <section className="grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(12,1fr)', gap: 16 }}>
        
        {/* CLOUD ENVIRONMENT OVERVIEW */}
        <div className="panel s6" style={{ gridColumn: 'span 6', background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="panel-h" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, marginBottom: 12 }}>
            <div>
              <h3 style={{ fontSize: 12, fontWeight: 700, letterSpacing: '.09em', color: 'var(--text)' }}>CLOUD ENVIRONMENT OVERVIEW</h3>
              <p style={{ fontSize: '11.5px', color: 'var(--muted)', marginTop: 3 }}>Real-time 360° security visualization</p>
            </div>
            <div className="tools" style={{ display: 'flex', gap: 8 }}>
              <button onClick={fetchData} className="tool-btn" title="Refresh" style={{ width: 32, height: 32, borderRadius: 8, border: '1px solid var(--border)', background: 'transparent', color: 'var(--muted)', display: 'grid', placeItems: 'center', transition: '.18s' }}>
                <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
              </button>
              <button onClick={triggerScan} disabled={scanning} className={`tool-btn pill ${scanning ? 'on' : ''}`} style={{ width: 'auto', padding: '0 10px', fontSize: 11, fontWeight: 700, borderRadius: 8, border: '1px solid var(--border)', background: scanning ? 'rgba(99,102,241,.16)' : 'transparent', color: scanning ? '#a5b4fc' : 'var(--muted)', borderColor: scanning ? 'rgba(99,102,241,.5)' : 'var(--border)' }}>
                {scanning ? 'Scanning...' : '360°'}
              </button>
            </div>
          </div>
          <CloudTopology scanning={scanning || refreshing} />
        </div>

        {/* FINDINGS SEVERITY BREAKDOWN */}
        <div className="panel s3" style={{ gridColumn: 'span 3', background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="panel-h" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, marginBottom: 12 }}>
            <div>
              <h3 style={{ fontSize: 12, fontWeight: 700, letterSpacing: '.09em', color: 'var(--text)' }}>FINDINGS SEVERITY</h3>
              <p style={{ fontSize: '11.5px', color: 'var(--muted)', marginTop: 3 }}>Proportion of open vulnerabilities</p>
            </div>
          </div>
          <div className="donut-row" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 18 }}>
            <div className="donut" style={{ position: 'relative', width: 130, margin: '4px auto' }}>
              <svg width="130" height="130" viewBox="0 0 150 150">
                <g fill="none" stroke-width="17" transform="rotate(-90 75 75)">
                  <circle cx="75" cy="75" r="57" stroke="#ef4444" stroke-dasharray="34.1 358.1" />
                  <circle cx="75" cy="75" r="57" stroke="#f97316" stroke-dasharray="34.1 358.1" transform="rotate(34.3 75 75)" />
                  <circle cx="75" cy="75" r="57" stroke="#f59e0b" stroke-dasharray="34.1 358.1" transform="rotate(68.6 75 75)" />
                  <circle cx="75" cy="75" r="57" stroke="#3b82f6" stroke-dasharray="256 358.1" transform="rotate(102.9 75 75)" />
                </g>
              </svg>
              <div className="ctr" style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <b style={{ fontSize: 24, fontWeight: 800, color: 'var(--text)' }}>{totalFindings}</b>
                <span style={{ fontSize: 11, color: 'var(--muted)' }}>Total</span>
              </div>
            </div>
            <ul className="legend" style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 8, padding: 0 }}>
              <li style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, listStyle: 'none' }}><i style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }}></i>Critical ({critical}) <span style={{ marginLeft: 'auto', color: 'var(--muted)' }}>9.5%</span></li>
              <li style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, listStyle: 'none' }}><i style={{ width: 8, height: 8, borderRadius: '50%', background: '#f97316' }}></i>High ({high}) <span style={{ marginLeft: 'auto', color: 'var(--muted)' }}>9.5%</span></li>
              <li style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, listStyle: 'none' }}><i style={{ width: 8, height: 8, borderRadius: '50%', background: '#f59e0b' }}></i>Medium ({medium}) <span style={{ marginLeft: 'auto', color: 'var(--muted)' }}>9.5%</span></li>
              <li style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, listStyle: 'none' }}><i style={{ width: 8, height: 8, borderRadius: '50%', background: '#3b82f6' }}></i>Low ({low}) <span style={{ marginLeft: 'auto', color: 'var(--muted)' }}>71.4%</span></li>
            </ul>
          </div>
        </div>

        {/* AI SECURITY INSIGHTS */}
        <div className="panel s3" style={{ gridColumn: 'span 3', background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="panel-h" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, marginBottom: 12 }}>
            <div>
              <h3 style={{ fontSize: 12, fontWeight: 700, letterSpacing: '.09em', color: 'var(--text)' }}>AI INSIGHTS</h3>
            </div>
            <span style={{ color: '#a78bfa' }}>
              <Brain size={22} />
            </span>
          </div>
          <div className="powered" style={{ color: '#a5b4fc', fontSize: '11.5px', fontWeight: 600, marginBottom: 10 }}>Powered by Aegivion AI</div>
          <p className="insight-txt" style={{ fontSize: '12.5px', lineHeight: 1.65, color: 'var(--muted)' }}>I've analyzed your environment and found <span className="hot" style={{ color: '#f87171', fontWeight: 600 }}>1 critical misconfiguration</span> in AWS S3 bucket policy.</p>
          <div className="risk-lbl" style={{ fontSize: '11.5px', color: 'var(--muted)', margin: '14px 0 8px' }}>Risk Level</div>
          <div className="risk-row" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <b style={{ color: 'var(--red)', fontSize: 13 }}>High</b>
            <div className="segs" style={{ display: 'flex', gap: 6, flex: 1 }}>
              <i className="on" style={{ height: 5, flex: 1, borderRadius: 4, background: 'linear-gradient(90deg,#ef4444,#f97316)', boxShadow: '0 0 8px rgba(239,68,68,.5)' }}></i>
              <i className="on" style={{ height: 5, flex: 1, borderRadius: 4, background: 'linear-gradient(90deg,#ef4444,#f97316)', boxShadow: '0 0 8px rgba(239,68,68,.5)' }}></i>
              <i className="on" style={{ height: 5, flex: 1, borderRadius: 4, background: 'linear-gradient(90deg,#ef4444,#f97316)', boxShadow: '0 0 8px rgba(239,68,68,.5)' }}></i>
              <i style={{ height: 5, flex: 1, borderRadius: 4, background: '#2b3650' }}></i>
              <i style={{ height: 5, flex: 1, borderRadius: 4, background: '#2b3650' }}></i>
            </div>
          </div>
          <Link to="/ai-assistant">
            <button className="btn-primary" style={{ marginTop: 16, width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, border: 'none', background: 'linear-gradient(90deg,#6366f1,#7c3aed)', color: '#fff', fontWeight: 700, fontSize: 13, padding: 11, borderRadius: 10, transition: '.2s', boxShadow: '0 8px 20px rgba(99,102,241,.35)' }}>
              View &amp; Resolve <ArrowRight size={15} />
            </button>
          </Link>
        </div>

      </section>

      {/* SECOND GRID BLOCK */}
      <section className="grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(12,1fr)', gap: 16 }}>
        
        {/* RECENT SECURITY EVENTS */}
        <div className="panel s6" style={{ gridColumn: 'span 6', background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="panel-h" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, marginBottom: 12 }}>
            <div>
              <h3 style={{ fontSize: 12, fontWeight: 700, letterSpacing: '.09em', color: 'var(--text)' }}>RECENT SECURITY EVENTS</h3>
              <p style={{ fontSize: '11.5px', color: 'var(--muted)', marginTop: 3 }}>Last 3 hours</p>
            </div>
            <Link to="/findings" className="link" style={{ color: 'var(--accent)', fontSize: 12, fontWeight: 600, textDecoration: 'none' }}>View All</Link>
          </div>
          <div className="events" style={{ display: 'flex', flexDirection: 'column' }}>
            <div className="event" onClick={() => setEventDetailOpen(!eventDetailOpen)} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '9px 2px', borderRadius: 8, cursor: 'pointer' }}>
              <i className="dot" style={{ width: 7, height: 7, borderRadius: '50%', flex: 'none', background: '#ef4444', boxShadow: '0 0 7px #ef4444' }}></i>
              <span className="sev critical" style={{ fontSize: 11, fontWeight: 700, color: '#fff', padding: '4px 0', width: 74, textAlign: 'center', borderRadius: 6, flex: 'none', background: '#b91c1c' }}>Critical</span>
              <span className="time" style={{ color: 'var(--muted)', fontSize: 12, width: 72, flex: 'none' }}>15m ago</span>
              <span className="desc" style={{ fontSize: '12.5px', flex: 1, minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>Bucket policy changed on customer-exports</span>
              <button className="chev" title="Expand" style={{ background: 'none', border: 'none', color: 'var(--muted)', padding: 4 }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 9l6 6 6-6" /></svg>
              </button>
            </div>
            <div className={`event-detail ${eventDetailOpen ? 'open' : ''}`} style={{ display: eventDetailOpen ? 'block' : 'none', fontSize: '11.5px', color: 'var(--muted)', padding: '2px 0 8px 96px' }}>
              ↳ Policy now allows <b style={{ color: '#f87171' }}>s3:GetObject *</b> for principal "AWS:*" — review recommended. Correlated with GuardDuty finding INC-236.
            </div>

            {defaultThreats.slice(1).map((t) => (
              <div key={t.id} className="event" style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '9px 2px', borderRadius: 8 }}>
                <i className="dot" style={{ width: 7, height: 7, borderRadius: '50%', flex: 'none', background: t.dot, boxShadow: `0 0 7px ${t.dot}` }}></i>
                <span className="sev high" style={{ fontSize: 11, fontWeight: 700, color: '#fff', padding: '4px 0', width: 74, textAlign: 'center', borderRadius: 6, flex: 'none', background: t.dot === '#EF4444' ? '#b91c1c' : '#c2570a' }}>High</span>
                <span className="time" style={{ color: 'var(--muted)', fontSize: 12, width: 72, flex: 'none' }}>{t.time}</span>
                <span className="desc" style={{ fontSize: '12.5px', flex: 1, minWidth: 0, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.title}</span>
              </div>
            ))}
          </div>
        </div>

        {/* RISKY ASSETS */}
        <div className="panel s6" style={{ gridColumn: 'span 6', background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 18px', boxShadow: 'var(--shadow)' }}>
          <div className="panel-h" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, marginBottom: 12 }}>
            <div>
              <h3 style={{ fontSize: 12, fontWeight: 700, letterSpacing: '.09em', color: 'var(--text)' }}>TOP RISKY ASSETS</h3>
            </div>
            <Link to="/assets" className="link" style={{ color: 'var(--accent)', fontSize: 12, fontWeight: 600, textDecoration: 'none' }}>View All</Link>
          </div>
          <table className="tbl" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, textAlign: 'left', padding: '8px 8px', borderBottom: '1px solid var(--border)' }}>Asset / Issue</th>
                <th style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, textAlign: 'left', padding: '8px 8px', borderBottom: '1px solid var(--border)' }}>Severity</th>
                <th style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, textAlign: 'left', padding: '8px 8px', borderBottom: '1px solid var(--border)' }}>Risk Score</th>
                <th style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600, textAlign: 'left', padding: '8px 8px', borderBottom: '1px solid var(--border)' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {defaultTopAssets.map((asset, index) => (
                <tr key={index}>
                  <td style={{ fontSize: '12.5px', padding: '10px 8px', borderBottom: '1px solid var(--border)', verticalAlign: 'middle' }}>
                    <div style={{ fontWeight: 600 }}>{asset.name}</div>
                    <div style={{ fontSize: 10, color: 'var(--muted)' }}>{asset.env}</div>
                  </td>
                  <td style={{ fontSize: '12.5px', padding: '10px 8px', borderBottom: '1px solid var(--border)', verticalAlign: 'middle' }}>
                    <span className="sev critical" style={{ fontSize: 11, fontWeight: 700, color: '#fff', padding: '3px 8px', borderRadius: 6, background: asset.sev === 'Critical' ? '#b91c1c' : '#c2570a' }}>{asset.sev}</span>
                  </td>
                  <td style={{ fontSize: '12.5px', padding: '10px 8px', borderBottom: '1px solid var(--border)', verticalAlign: 'middle', color: 'var(--muted)' }}>{asset.score}</td>
                  <td style={{ fontSize: '12.5px', padding: '10px 8px', borderBottom: '1px solid var(--border)', verticalAlign: 'middle' }}>
                    <button className="eye-btn" title="View details" style={{ width: 30, height: 30, borderRadius: 8, border: '1px solid var(--border)', background: 'transparent', color: 'var(--muted)', display: 'grid', placeItems: 'center', transition: '.18s' }}>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7z" /><circle cx="12" cy="12" r="3" /></svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

      </section>

    </div>
  );
}


