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
  const [angle, setAngle] = useState(-90);
  const [paused, setPaused] = useState(false);
  const [dimensions, setDimensions] = useState({ w: 0, cx: 0, cy: 0, rx: 0, ry: 0 });
  const containerRef = React.useRef<HTMLDivElement>(null);

  const cloudSVG = `
    <svg class="cloud-svg" viewBox="0 0 72 48" style="width:100%; height:100%; filter:drop-shadow(0 6px 14px rgba(0,0,0,.45))">
      <g fill="url(#cg)">
        <circle cx="24" cy="30" r="13"/>
        <circle cx="37" cy="19" r="15"/>
        <circle cx="51" cy="30" r="12"/>
        <rect x="21" y="27" width="32" height="16" rx="8"/>
      </g>
    </svg>`;

  const awsLogo = `
    <span class="logo aws" style="position:absolute; left:50%; top:56%; transform:translate(-50%,-50%); line-height:1; color:#232f3e; font-weight:800; font-size:1.05rem; letter-spacing:.5px">aws
      <svg class="smile" viewBox="0 0 60 12" style="position:absolute; left:50%; transform:translateX(-50%); bottom:-7px; width:36px; height:8px">
        <path d="M3 3 C 18 11, 40 11, 52 4" fill="none" stroke="#ff9900" strokeWidth="3.5" strokeLinecap="round"/>
        <path d="M52 4 l-7 -1.5 M52 4 l-4.5 5" fill="none" stroke="#ff9900" strokeWidth="3" strokeLinecap="round"/>
      </svg>
    </span>`;

  const azureLogo = `<span class="logo azure" style="position:absolute; left:50%; top:56%; transform:translate(-50%,-50%); line-height:1; color:#0078d4; font-weight:800; font-size:1.3rem">A</span>`;

  const googleLogo = `
    <span class="logo gcp" style="position:absolute; left:50%; top:56%; transform:translate(-50%,-50%); line-height:1">
      <svg viewBox="0 0 48 48" style="width:24px; height:24px; display:block">
        <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
        <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
        <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/>
        <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
      </svg>
    </span>`;

  const iconSVG = {
    identities: `<svg viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round">
        <circle cx="9" cy="8" r="3.2"/><path d="M3.5 19c.6-3.4 2.8-5 5.5-5s4.9 1.6 5.5 5"/>
        <circle cx="16.5" cy="9" r="2.6"/><path d="M15.5 14.2c2.3.2 4.2 1.7 4.8 4.8"/></svg>`,
    compute: `<svg viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round">
        <ellipse cx="12" cy="5.5" rx="7" ry="3"/><path d="M5 5.5v13c0 1.7 3.1 3 7 3s7-1.3 7-3v-13"/>
        <path d="M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/></svg>`
  };

  const nodesData = [
    { kind: 'cloud', logo: awsLogo, assets: 12, base: -90 },
    { kind: 'cloud', logo: googleLogo, assets: 10, base: 30 },
    { kind: 'cloud', logo: azureLogo, assets: 10, base: 150 }
  ];

  const handleResize = () => {
    if (containerRef.current) {
      const r = containerRef.current.getBoundingClientRect();
      const w = r.width;
      const h = 380; // Fixed stage height inside panel layout
      const cx = w / 2;
      const cy = h * 0.52;
      const rx = Math.min(w * 0.36, 350);
      const ry = rx * 0.44;
      setDimensions({ w, cx, cy, rx, ry });
    }
  };

  useEffect(() => {
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    if (paused) return;
    const SPEED = 14; // degrees per second
    let lastTime = performance.now();
    let frameId: number;

    const tick = (now: number) => {
      const dt = (now - lastTime) / 1000;
      lastTime = now;
      setAngle(prev => (prev + dt * SPEED) % 360);
      frameId = requestAnimationFrame(tick);
    };

    frameId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frameId);
  }, [paused]);

  const resetRotation = () => {
    setAngle(0);
  };

  return (
    <div 
      className="viz-container" 
      style={{ 
        position: 'relative', 
        borderRadius: 20, 
        background: 'var(--panel)', 
        border: '1px solid rgba(99,102,241,.25)', 
        padding: '20px 24px', 
        boxShadow: 'var(--shadow)' 
      }}
    >
      <svg width="0" height="0" style={{ position: 'absolute' }}>
        <defs>
          <linearGradient id="cg" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#ffffff"/><stop offset="1" stopColor="#c7d2e6"/>
          </linearGradient>
          <linearGradient id="sg" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#a78bfa"/><stop offset="1" stopColor="#6d28d9"/>
          </linearGradient>
          <linearGradient id="rg" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#ff7a1a"/><stop offset=".5" stopColor="#ffb067"/><stop offset="1" stopColor="#ff7a1a"/>
          </linearGradient>
        </defs>
      </svg>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h3 style={{ fontSize: 13, fontWeight: 800, color: 'var(--text)', letterSpacing: '1px' }}>CLOUD ENVIRONMENT OVERVIEW</h3>
          <p style={{ fontSize: '11.5px', color: 'var(--muted)', marginTop: 2 }}>Real-time 360° security visualization — AWS · Azure · GCP on one linked orbit</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button 
            onClick={resetRotation}
            style={{ width: 28, height: 28, borderRadius: '50%', background: 'rgba(30,40,70,.6)', border: '1px solid rgba(99,102,241,.3)', color: '#aeb6d0', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }} 
            title="Reset rotation"
          >
            ↻
          </button>
          <div style={{ background: 'rgba(30,40,70,.6)', border: '1px solid rgba(99,102,241,.3)', padding: '4px 10px', borderRadius: 12, fontSize: 10, fontWeight: 700, color: '#a5b4fc' }}>
            {Math.round(((angle) % 360 + 360) % 360)}°
          </div>
        </div>
      </div>

      <div 
        ref={containerRef}
        onMouseEnter={() => setPaused(true)}
        onMouseLeave={() => setPaused(false)}
        className="stage" 
        style={{ 
          position: 'relative', 
          height: 380, 
          borderRadius: 16, 
          overflow: 'hidden', 
          background: 'radial-gradient(ellipse at 50% 45%, #10173a 0%, #060a1c 75%)', 
          border: '1px solid rgba(99,102,241,.15)' 
        }}
      >
        <svg style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', zIndex: 10, pointerEvents: 'none' }}>
          <ellipse 
            cx={dimensions.cx} 
            cy={dimensions.cy} 
            rx={dimensions.rx} 
            ry={dimensions.ry} 
            fill="none" 
            stroke="url(#rg)" 
            strokeWidth="2.5" 
            style={{ filter: 'drop-shadow(0 0 6px rgba(255,122,26,.65))' }}
          />
          <ellipse 
            cx={dimensions.cx} 
            cy={dimensions.cy} 
            rx={dimensions.rx} 
            ry={dimensions.ry} 
            fill="none" 
            stroke="#ffd9b0" 
            strokeWidth="2" 
            strokeLinecap="round" 
            strokeDasharray="4 22" 
            style={{ 
              opacity: 0.8,
              animation: paused ? 'none' : 'flow 5s linear infinite',
            }}
          />
        </svg>

        <span className="ring-label" style={{ position: 'absolute', color: 'rgba(160,168,192,.45)', fontSize: '.72rem', fontWeight: 700, letterSpacing: '3px', pointerEvents: 'none', left: '15%', top: '19%', transform: 'rotate(-24deg)' }}>IDENTITIES</span>
        <span className="ring-label" style={{ position: 'absolute', color: 'rgba(160,168,192,.45)', fontSize: '.72rem', fontWeight: 700, letterSpacing: '3px', pointerEvents: 'none', left: '35%', top: '31%', transform: 'rotate(-14deg)' }}>NETWORK</span>
        <span className="ring-label" style={{ position: 'absolute', color: 'rgba(160,168,192,.45)', fontSize: '.72rem', fontWeight: 700, letterSpacing: '3px', pointerEvents: 'none', left: '17%', bottom: '13%', transform: 'rotate(24deg)' }}>APPLICATIONS</span>
        <span className="ring-label" style={{ position: 'absolute', color: 'rgba(160,168,192,.45)', fontSize: '.72rem', fontWeight: 700, letterSpacing: '3px', pointerEvents: 'none', right: '13%', bottom: '15%', transform: 'rotate(-24deg)' }}>COMPUTE</span>

        <div className="core" style={{ position: 'absolute', left: '50%', top: '52%', transform: 'translate(-50%,-50%)', zIndex: 100, width: 220, height: 230, pointerEvents: 'none' }}>
          <div 
            className="core-platform" 
            style={{ 
              position: 'absolute', left: '50%', bottom: 0, transform: 'translateX(-50%)', width: 190, height: 100, 
              background: 'linear-gradient(160deg,#1c2749 0%,#0c1226 70%)', clipPath: 'polygon(50% 0,100% 50%,50% 100%,0 50%)',
              boxShadow: '0 18px 40px rgba(0,0,0,.6)' 
            }}
          />
          <svg 
            className="core-shield" 
            viewBox="0 0 100 120" 
            style={{ 
              position: 'absolute', left: '50%', top: 0, transform: 'translateX(-50%)', width: 96, height: 112,
              animation: 'pulseShield 2.4s ease-in-out infinite' 
            }}
          >
            <path d="M50 4 L92 22 v34 c0 30 -18 48 -42 60 C26 104 8 86 8 56 V22 Z" fill="url(#sg)" stroke="#c4b5fd" strokeWidth="3"/>
            <path d="M50 22 L76 33 v22 c0 20 -12 33 -26 41 -14 -8 -26 -21 -26 -41 V33 Z" fill="rgba(255,255,255,.14)" stroke="#e9d5ff" strokeWidth="2"/>
          </svg>
        </div>

        {nodesData.map((d, i) => {
          const a = ((angle + d.base) * Math.PI) / 180;
          const x = dimensions.cx + dimensions.rx * Math.cos(a);
          const y = dimensions.cy + dimensions.ry * Math.sin(a);
          const depth = (Math.sin(a) + 1) / 2;
          const s = 0.68 + 0.45 * depth;
          const isLeft = x > dimensions.w - 150;

          return (
            <div
              key={i}
              className="node"
              style={{
                position: 'absolute',
                left: x,
                top: y,
                zIndex: 100 + Math.round(50 * Math.sin(a)),
                transform: `translate(-50%,-50%) scale(${s})`,
                filter: `brightness(${0.78 + 0.32 * depth})`,
                pointerEvents: 'none',
                transition: 'none'
              }}
            >
              <div className="node-inner" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                <div className="cloud-wrap" style={{ position: 'relative', width: 92, height: 62 }}>
                  <div dangerouslySetInnerHTML={{ __html: cloudSVG }} style={{ width: '100%', height: '100%' }} />
                  <div dangerouslySetInnerHTML={{ __html: d.logo || '' }} />
                  <div 
                    className={`badge ${isLeft ? 'left' : ''}`}
                    style={{
                      position: 'absolute',
                      left: isLeft ? 'auto' : 'calc(100% + 10px)',
                      right: isLeft ? 'calc(100% + 10px)' : 'auto',
                      top: '24%',
                      whiteSpace: 'nowrap',
                      textAlign: isLeft ? 'right' : 'left'
                    }}
                  >
                    <div className="sec" style={{ color: 'var(--green)', fontWeight: 700, fontSize: '.8rem', textShadow: '0 0 8px rgba(34,197,94,.5)' }}>Secure</div>
                    <div className="ast" style={{ color: 'var(--muted)', fontSize: '.72rem', marginTop: 2 }}>{d.assets} Assets</div>
                  </div>
                </div>
                <div 
                  className="node-platform" 
                  style={{ 
                    width: 96, height: 52, marginTop: -14, position: 'relative',
                    background: 'linear-gradient(160deg,#1d2a52 0%,#0b1124 75%)',
                    clipPath: 'polygon(50% 0,100% 50%,50% 100%,0 50%)',
                    boxShadow: '0 10px 24px rgba(0,0,0,.55)' 
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>

      <div className="status-footer" style={{ textAlign: 'center', marginTop: 22 }}>
        <div className="status-pill animate-blink" style={{ display: 'inline-block', background: 'rgba(16,185,129,.12)', color: 'var(--green)', padding: '10px 32px', borderRadius: 25, fontWeight: 700, fontSize: '.9rem', border: '1px solid rgba(16,185,129,.35)' }}>
          {paused ? 'Auto-rotation Paused' : 'All Systems Operational'}
        </div>
      </div>
    </div>
  );
}




/* ─────────── MAIN DASHBOARD PAGE ─────────── */
function DashboardPage() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState<any[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [trend, setTrend] = useState<any>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [eventDetailOpen, setEventDetailOpen] = useState(false);

  const fetchData = async () => {
    try {
      setRefreshing(true);
      const [fR, aR, tR] = await Promise.allSettled([
        api.get('/v1/findings'), 
        api.get('/v1/findings/assets'),
        api.get('/v1/history/risk-telemetry/trend')
      ]);
      if (fR.status === 'fulfilled') setFindings(fR.value.data.findings || []);
      if (aR.status === 'fulfilled') setAssets(aR.value.data.assets || []);
      if (tR.status === 'fulfilled') setTrend(tR.value.data);
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
            <span className="stat-label" style={{ fontSize: '10.5px', letterSpacing: '.12em', fontWeight: 700, color: 'var(--muted)' }}>SECURITY RISK</span>
            <span className="stat-ic green" style={{ width: 40, height: 40, borderRadius: 10, display: 'grid', placeItems: 'center', background: 'rgba(34,197,94,.13)', color: '#4ade80' }}>
              <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l8 3.5v5c0 5-3.4 9.4-8 11.5-4.6-2.1-8-6.5-8-11.5v-5L12 2z" /><path d="M9 12l2.2 2.2L15.5 10" /></svg>
            </span>
          </div>
          <div className="stat-value" style={{ fontSize: 26, fontWeight: 800, marginTop: 2 }}>{trend?.overall_risk?.change > 0 ? '+' : ''}{trend?.overall_risk?.change || 0} <small style={{ fontSize: 14, color: 'var(--muted)', fontWeight: 600 }}>Diff</small></div>
          <div className="stat-foot" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 4, gap: 8 }}>
            <span className="t-green" style={{ color: trend?.overall_risk?.direction === 'INCREASING' ? 'var(--red)' : 'var(--green)', fontSize: '11.5px' }}>
              Trend: {trend?.overall_risk?.direction || 'STABLE'}
            </span>
            <svg width="92" height="26" viewBox="0 0 92 26"><polyline points="2,15 14,13 26,16 38,11 50,14 62,10 74,13 86,9 90,10" fill="none" stroke={trend?.overall_risk?.direction === 'INCREASING' ? '#ef4444' : '#22c55e'} stroke-width="2" stroke-linecap="round" /></svg>
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


