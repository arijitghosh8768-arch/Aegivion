import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useLocation } from '@tanstack/react-router';
import { useAuthStore } from '@/store/auth-store';
import { useUIStore } from '@/store/ui-store';
import {
  Shield, LayoutDashboard, BrainCircuit, Cloud, AlertTriangle,
  Database, Users, BarChart3, FileText, Zap, Settings, LogOut,
  ChevronLeft, Bell, HelpCircle, Sun, Moon
} from 'lucide-react';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/ai-assistant', label: 'AI Copilot', icon: BrainCircuit },
  { to: '/cloud-accounts', label: 'Cloud Topology', icon: Cloud },
  { to: '/findings', label: 'Threats', icon: AlertTriangle },
  { to: '/assets', label: 'Assets', icon: Database },
  { to: '/identities', label: 'Identities', icon: Users },
  { to: '/compliance', label: 'Compliance', icon: BarChart3 },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/incidents', label: 'Automation', icon: Zap },
  { to: '/settings', label: 'Settings', icon: Settings },
];

function SparkLine() {
  const pts = [26, 24, 27, 20, 22, 16, 19, 13, 15, 9, 10, 4];
  const max = 30; const w = 150; const h = 34;
  const xs = pts.map((_, i) => (i / (pts.length - 1)) * w);
  const ys = pts.map(v => h - (v / max) * (h - 2) - 1);
  let d = `M ${xs[0]} ${ys[0]}`;
  for (let i = 1; i < pts.length; i++) {
    const cx2 = (xs[i - 1] + xs[i]) / 2;
    d += ` C ${cx2} ${ys[i - 1]}, ${cx2} ${ys[i]}, ${xs[i]} ${ys[i]}`;
  }
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} style={{ marginTop: 8 }}>
      <path d={d} fill="none" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const user = useAuthStore((s: any) => s.user);
  const logout = useAuthStore((s: any) => s.logout);
  const { isCollapsed, toggleSidebar } = useUIStore();
  const [menuOpen, setMenuOpen] = useState(false);
  const [openPop, setOpenPop] = useState<'bell' | 'help' | null>(null);
  const [badge, setBadge] = useState(3);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const popoverRef = useRef<HTMLDivElement>(null);


  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        setOpenPop(null);
      }
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  useEffect(() => {
    const savedTheme = localStorage.getItem('aegivion-theme') as 'dark' | 'light' || 'dark';
    setTheme(savedTheme);
    document.body.className = savedTheme;
  }, []);



  const toggleTheme = (newTheme: 'dark' | 'light') => {
    setTheme(newTheme);
    localStorage.setItem('aegivion-theme', newTheme);
    document.body.className = newTheme;
    // Dispatch custom event to notify other components (e.g. topology, charts) to redraw
    window.dispatchEvent(new Event('themechange'));
  };


  const handleLogout = () => {
    logout();
    navigate({ to: '/login' });
  };

  const initials = user
    ? (`${user.first_name?.[0] || ''}${user.last_name?.[0] || ''}`).toUpperCase() || 'AU'
    : 'AD';
  const userRole = user?.role || 'Super Admin';
  const isActive = (to: string) => to === '/' ? location.pathname === '/' : location.pathname.startsWith(to);

  // Security Posture gauge setup
  const [gaugeValue, setGaugeValue] = useState(0);
  const TOTAL_LEN = 282.74;
  const TARGET = 92;

  useEffect(() => {
    const timer = setTimeout(() => {
      setGaugeValue(TARGET);
    }, 300);
    return () => clearTimeout(timer);
  }, []);

  const dashOffset = (TOTAL_LEN * (1 - gaugeValue / 100)).toFixed(2);

  return (
    <div className="app min-h-screen flex w-full" style={{ background: 'var(--bg)', color: 'var(--text)' }}>
      {/* ============ SIDEBAR ============ */}
      <aside
        className="sidebar flex-shrink-0"
        style={{
          width: isCollapsed ? 76 : 252,
          minWidth: isCollapsed ? 76 : 252,
          background: 'var(--side)',
          borderRight: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
          padding: '18px 14px 16px',
          position: 'sticky',
          top: 0,
          height: '100vh',
          overflowY: 'auto',
          transition: 'width 0.2s, min-width 0.2s',
        }}
      >
        <div className="brand" style={{ display: 'flex', alignItems: 'center', gap: 11, padding: '2px 6px 16px' }}>
          <div
            className="brand-logo"
            style={{
              width: 42,
              height: 42,
              borderRadius: 12,
              background: 'linear-gradient(135deg,#6366f1,#7c3aed)',
              display: 'grid',
              placeItems: 'center',
              boxShadow: '0 6px 18px rgba(99,102,241,.4)',
              flex: 'none',
              cursor: 'pointer'
            }}
            onClick={toggleSidebar}
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2l8 3.5v5c0 5-3.4 9.4-8 11.5-4.6-2.1-8-6.5-8-11.5v-5L12 2z" />
              <path d="M12 8v5" />
              <circle cx="12" cy="15.5" r="0.5" fill="#fff" />
            </svg>
          </div>
          {!isCollapsed && (
            <div>
              <h1 style={{ fontSize: 17, fontWeight: 800, letterSpacing: '.2px', color: 'var(--text)' }}>Aegivion</h1>
              <span style={{ fontSize: 10.5, color: 'var(--muted)' }}>Cloud Security Platform</span>
            </div>
          )}
        </div>

        {!isCollapsed && <div className="nav-label" style={{ fontSize: 10, letterSpacing: '.14em', color: 'var(--faint)', fontWeight: 700, padding: '6px 10px 6px' }}>SECURITY CENTER</div>}
        
        <nav className="nav" style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.to);
            return (
              <Link
                key={item.to}
                to={item.to}
                className={active ? 'active' : ''}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 11,
                  padding: '10px 12px',
                  borderRadius: 10,
                  fontWeight: 500,
                  fontSize: '13.5px',
                  transition: '.18s',
                  border: '1px solid transparent',
                  textDecoration: 'none',
                  color: active ? '#fff' : 'var(--muted)',
                  background: active ? 'linear-gradient(90deg,#6366f1,#7c3aed)' : 'transparent',
                  boxShadow: active ? '0 6px 18px rgba(99,102,241,.35)' : 'none',
                }}
              >
                <Icon style={{ width: 17, height: 17, flex: 'none' }} />
                {!isCollapsed && <span>{item.label}</span>}
              </Link>
            );
          })}
        </nav>

        {!isCollapsed && (
          <div className="posture" style={{ marginTop: 14, background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 14, padding: '16px 14px', textAlign: 'center' }}>
            <h4 style={{ fontSize: 10.5, letterSpacing: '.12em', color: 'var(--muted)', fontWeight: 700, marginBottom: 8 }}>SECURITY POSTURE</h4>
            <div className="gauge-wrap" style={{ position: 'relative', width: 132, margin: '0 auto' }}>
              <svg width="132" height="120" viewBox="0 0 150 136">
                <defs>
                  <linearGradient id="gGauge" x1="0" y1="1" x2="1" y2="0">
                    <stop offset="0" stopColor="#7c3aed" />
                    <stop offset=".5" stopColor="#3b82f6" />
                    <stop offset="1" stopColor="#22c55e" />
                  </linearGradient>
                </defs>
                <path d="M32.57 117.43 A60 60 0 1 1 117.43 117.43" fill="none" stroke="#233052" strokeWidth="10" strokeLinecap="round" />
                <path
                  id="gaugeVal"
                  d="M32.57 117.43 A60 60 0 1 1 117.43 117.43"
                  fill="none"
                  stroke="url(#gGauge)"
                  strokeWidth="10"
                  strokeLinecap="round"
                  strokeDasharray={`${TOTAL_LEN}`}
                  strokeDashoffset={dashOffset}
                  style={{ transition: 'stroke-dashoffset 1.4s cubic-bezier(.22,.8,.32,1)' }}
                />
              </svg>
              <div className="gauge-num" style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                <b id="gaugeNum" style={{ fontSize: 30, fontWeight: 800, color: 'var(--text)' }}>{Math.round(gaugeValue)}</b>
                <span style={{ fontSize: 11, color: 'var(--muted)', marginTop: -2 }}>/100</span>
              </div>
            </div>
            <div className="exc" style={{ color: 'var(--green)', fontWeight: 700, marginTop: 6 }}>Excellent</div>
            <div className="delta" style={{ color: 'var(--green)', fontSize: 11, marginTop: 6 }}>+7.2% vs last week</div>
            <SparkLine />
          </div>
        )}

        <div className="user-card" style={{ marginTop: 'auto', display: 'flex', alignItems: 'center', gap: 10, background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 12, padding: '9px 10px', position: 'relative' }}>
          <div
            onClick={() => setMenuOpen(!menuOpen)}
            style={{
              width: 36,
              height: 36,
              borderRadius: '50%',
              background: 'linear-gradient(135deg,#6366f1,#8b5cf6)',
              color: '#fff',
              fontWeight: 700,
              fontSize: 13,
              display: 'grid',
              placeItems: 'center',
              cursor: 'pointer'
            }}
          >
            {initials}
          </div>
          {!isCollapsed && (
            <div style={{ flex: 1, minWidth: 0 }}>
              <b style={{ display: 'block', fontSize: 12.5, fontWeight: 600, color: 'var(--text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {user ? `${user.first_name || 'Admin'} ${user.last_name || 'User'}`.trim() : 'Admin User'}
              </b>
              <span style={{ fontSize: 11, color: 'var(--muted)' }}>{userRole}</span>
            </div>
          )}
          <i className="online" style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', width: 8, height: 8, borderRadius: '50%', background: 'var(--green)', boxShadow: '0 0 8px var(--green)' }} />

          {menuOpen && (
            <div style={{ position: 'absolute', bottom: 56, left: 10, right: 10, background: 'var(--panel2)', border: '1px solid var(--border)', borderRadius: 12, boxShadow: 'var(--shadow)', zIndex: 50 }}>
              <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border)' }}>
                <div style={{ fontSize: 10, color: 'var(--muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user?.email || 'admin@aegivion.io'}</div>
              </div>
              <button
                onClick={handleLogout}
                style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', fontSize: 11, color: 'var(--red)', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left' }}
              >
                <LogOut style={{ width: 12, height: 12 }} /> Sign out
              </button>
            </div>
          )}
        </div>
      </aside>

      {/* ============ MAIN CONTENT AREA ============ */}
      <main className="main flex-1 min-w-0" style={{ display: 'flex', flexDirection: 'column', overflowY: 'auto' }}>
        {/* Top Header Bar */}
        <div className="topbar" style={{ display: 'flex', alignItems: 'center', gap: 18, padding: '20px 24px 10px', background: 'var(--bg)', borderBottom: '1px solid var(--border)' }}>
          <div className="greet" style={{ flex: 1, minWidth: 0 }}>
            <h2 style={{ fontSize: 19, fontWeight: 800, color: 'var(--text)' }}>Good Morning, {user?.first_name || 'Admin'} 👋</h2>
            <p style={{ color: 'var(--muted)', fontSize: 12.5, marginTop: 3 }}>Aegivion AI is actively protecting your cloud environment.</p>
          </div>
          
          <div className="top-actions" ref={popoverRef} style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 9 }}>
            {/* Notifications Group */}
            <div style={{ position: 'relative', display: 'inline-block' }}>
              <button 
                onClick={() => {
                  setOpenPop(openPop === 'bell' ? null : 'bell');
                  if (openPop !== 'bell') setBadge(0);
                }} 
                className="icon-btn" 
                title="Notifications" 
                style={{ width: 38, height: 38, borderRadius: '50%', border: '1px solid var(--border)', background: 'transparent', color: 'var(--muted)', display: 'grid', placeItems: 'center', position: 'relative' }}
              >
                <Bell style={{ width: 17, height: 17 }} />
                {badge > 0 && (
                  <span className="badge" style={{ position: 'absolute', top: -4, right: -4, width: 17, height: 17, borderRadius: '50%', background: 'var(--accent)', color: '#fff', fontSize: 10, fontWeight: 700, display: 'grid', placeItems: 'center' }}>
                    {badge}
                  </span>
                )}
              </button>
              {openPop === 'bell' && (
                <div 
                  className="popover open" 
                  style={{ 
                    position: 'absolute', right: 0, top: 'calc(100% + 12px)', width: 310, 
                    background: 'var(--panel2)', border: '1px solid var(--border)', borderRadius: 14, 
                    boxShadow: '0 18px 50px rgba(0,0,0,.45)', zIndex: 900, overflow: 'hidden' 
                  }}
                >
                  <h3 style={{ fontSize: '11px', letterSpacing: '1.2px', padding: '13px 16px 10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)', fontWeight: 700 }}>NOTIFICATIONS</h3>
                  <div style={{ display: 'flex', gap: 12, padding: '12px 16px', alignItems: 'flex-start', borderBottom: '1px solid var(--border)' }}>
                    <span style={{ width: 9, height: 9, borderRadius: '50%', marginTop: 5, flex: 'none', background: '#ef4444' }} />
                    <div>
                      <div style={{ fontSize: '11.5px', fontWeight: 700, color: 'var(--text)' }}>Critical misconfiguration</div>
                      <div style={{ fontSize: '10.5px', color: 'var(--muted)', marginTop: 3 }}>AWS S3 bucket policy exposed · 2m ago</div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 12, padding: '12px 16px', alignItems: 'flex-start', borderBottom: '1px solid var(--border)' }}>
                    <span style={{ width: 9, height: 9, borderRadius: '50%', marginTop: 5, flex: 'none', background: '#3b82f6' }} />
                    <div>
                      <div style={{ fontSize: '11.5px', fontWeight: 700, color: 'var(--text)' }}>New asset discovered</div>
                      <div style={{ fontSize: '10.5px', color: 'var(--muted)', marginTop: 3 }}>GCP compute instance · 1h ago</div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 12, padding: '12px 16px', alignItems: 'flex-start' }}>
                    <span style={{ width: 9, height: 9, borderRadius: '50%', marginTop: 5, flex: 'none', background: '#22c55e' }} />
                    <div>
                      <div style={{ fontSize: '11.5px', fontWeight: 700, color: 'var(--text)' }}>Compliance report ready</div>
                      <div style={{ fontSize: '10.5px', color: 'var(--muted)', marginTop: 3 }}>6/8 controls compliant · 3h ago</div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Quick Help Group */}
            <div style={{ position: 'relative', display: 'inline-block' }}>
              <button 
                onClick={() => setOpenPop(openPop === 'help' ? null : 'help')} 
                className="icon-btn" 
                title="Help" 
                style={{ width: 38, height: 38, borderRadius: '50%', border: '1px solid var(--border)', background: 'transparent', color: 'var(--muted)', display: 'grid', placeItems: 'center' }}
              >
                <HelpCircle style={{ width: 17, height: 17 }} />
              </button>
              {openPop === 'help' && (
                <div 
                  className="popover open" 
                  style={{ 
                    position: 'absolute', right: 0, top: 'calc(100% + 12px)', width: 310, 
                    background: 'var(--panel2)', border: '1px solid var(--border)', borderRadius: 14, 
                    boxShadow: '0 18px 50px rgba(0,0,0,.45)', zIndex: 900, overflow: 'hidden' 
                  }}
                >
                  <h3 style={{ fontSize: '11px', letterSpacing: '1.2px', padding: '13px 16px 10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)', fontWeight: 700 }}>QUICK HELP</h3>
                  <ul style={{ padding: '12px 18px 16px', fontSize: '11.5px', color: 'var(--muted)', margin: 0, listStyleType: 'disc' }}>
                    <li style={{ marginBottom: 6 }}><b>Hover</b> the orbit to pause rotation.</li>
                    <li style={{ marginBottom: 6 }}><b>↻</b> resets the orbit position.</li>
                    <li style={{ marginBottom: 6 }}><b>🌙 / ☀</b> toggles dark / light theme.</li>
                    <li style={{ marginBottom: 6 }}><b>🔔</b> opens live security alerts.</li>
                  </ul>
                </div>
              )}
            </div>

            {/* Theme Toggle Button */}
            {theme === 'dark' ? (
              <button onClick={() => toggleTheme('light')} className="icon-btn" title="Light mode" style={{ width: 38, height: 38, borderRadius: '50%', border: '1px solid var(--border)', background: 'transparent', color: 'var(--muted)', display: 'grid', placeItems: 'center' }}>
                <Sun style={{ width: 17, height: 17 }} />
              </button>
            ) : (
              <button onClick={() => toggleTheme('dark')} className="icon-btn" title="Dark mode" style={{ width: 38, height: 38, borderRadius: '50%', border: '1px solid var(--border)', background: 'transparent', color: 'var(--muted)', display: 'grid', placeItems: 'center' }}>
                <Moon style={{ width: 16, height: 16 }} />
              </button>
            )}
          </div>
        </div>

        {/* Children routers */}
        <div style={{ flex: 1, padding: '16px 24px' }}>
          {children}
        </div>
      </main>
    </div>
  );
}


