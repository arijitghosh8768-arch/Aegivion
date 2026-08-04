
import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from '@tanstack/react-router';
import { useAuthStore } from '@/store/auth-store';
import {
  Shield, LayoutDashboard, BrainCircuit, Cloud, AlertTriangle,
  Database, Users, BarChart3, FileText, Zap, Settings, LogOut
} from 'lucide-react';

const navItems = [
  { to: '/', label: 'Command Center', icon: LayoutDashboard },
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
  const pts = [2, 8, 5, 12, 9, 15, 14];
  const max = 16; const w = 110; const h = 22;
  const xs = pts.map((_, i) => (i / (pts.length - 1)) * w);
  const ys = pts.map(v => h - (v / max) * (h - 2) - 1);
  let d = `M ${xs[0]} ${ys[0]}`;
  for (let i = 1; i < pts.length; i++) {
    const cx2 = (xs[i - 1] + xs[i]) / 2;
    d += ` C ${cx2} ${ys[i - 1]}, ${cx2} ${ys[i]}, ${xs[i]} ${ys[i]}`;
  }
  const fill = d + ` L ${xs[pts.length - 1]} ${h} L ${xs[0]} ${h} Z`;
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`}>
      <defs>
        <linearGradient id="spkFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#34d399" stopOpacity="0.25" />
          <stop offset="100%" stopColor="#34d399" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={fill} fill="url(#spkFill)" />
      <path d={d} fill="none" stroke="#34d399" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const user = useAuthStore((s: any) => s.user);
  const logout = useAuthStore((s: any) => s.logout);
  const [menuOpen, setMenuOpen] = useState(false);

  const handleLogout = () => { logout(); navigate({ to: '/login' }); };
  const initials = user
    ? (`${user.first_name?.[0] || ''}${user.last_name?.[0] || ''}`).toUpperCase() || 'AU'
    : 'AU';
  const userRole = user?.role || 'viewer';
  const isActive = (to: string) => to === '/' ? location.pathname === '/' : location.pathname.startsWith(to);

  const r = 22; const score = 0.92;
  const arc = 2 * Math.PI * r * score;
  const full = 2 * Math.PI * r;

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', fontFamily: "'Inter','Segoe UI',system-ui,sans-serif", background: '#F6F7FF' }}>

      {/* ── SIDEBAR ── */}
      <aside style={{ width: 200, flexShrink: 0, background: '#fff', borderRight: '1px solid #EBEBF5', display: 'flex', flexDirection: 'column', height: '100%', boxShadow: '1px 0 12px rgba(99,102,241,0.05)' }}>

        {/* Logo */}
        <div style={{ padding: '18px 18px 14px', borderBottom: '1px solid #EBEBF5' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: 10, background: 'linear-gradient(135deg,#7C3AED,#4F46E5)', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 4px 12px rgba(124,58,237,0.35)' }}>
              <Shield style={{ width: 16, height: 16, color: '#fff' }} />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 900, color: '#111827', lineHeight: 1.2 }}>Aegivion</div>
              <div style={{ fontSize: 8.5, color: '#9CA3AF', lineHeight: 1.2, marginTop: 1 }}>Autonomous Cloud Security Copilot</div>
            </div>
          </div>
        </div>

        {/* Nav items */}
        <nav style={{ flex: 1, padding: '10px 10px', overflowY: 'auto' }}>
          {navItems.map(item => {
            const Icon = item.icon;
            const on = isActive(item.to);
            return (
              <Link key={item.to} to={item.to}
                style={{
                  display: 'flex', alignItems: 'center', gap: 9,
                  padding: '8px 12px', borderRadius: 12, fontSize: 11.5,
                  fontWeight: on ? 600 : 500,
                  color: on ? '#fff' : '#6B7280',
                  background: on ? 'linear-gradient(135deg,#7C3AED,#6366F1)' : 'transparent',
                  boxShadow: on ? '0 4px 14px rgba(124,58,237,0.28)' : 'none',
                  marginBottom: 2, textDecoration: 'none',
                  transition: 'all 0.15s',
                }}
              >
                <Icon style={{ width: 14, height: 14, flexShrink: 0 }} />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Security Posture */}
        <div style={{ padding: '0 12px 12px' }}>
          <div style={{ background: '#FAFAFF', border: '1px solid #EBEBF5', borderRadius: 16, padding: '12px 12px 8px' }}>
            <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: '#9CA3AF', marginBottom: 10 }}>Security Posture</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
              <div style={{ position: 'relative', width: 56, height: 56, flexShrink: 0 }}>
                <svg width="56" height="56" viewBox="0 0 56 56" style={{ transform: 'rotate(-90deg)' }}>
                  <circle cx="28" cy="28" r={r} fill="none" stroke="#EBEBF5" strokeWidth="5" />
                  <circle cx="28" cy="28" r={r} fill="none" stroke="url(#pg)" strokeWidth="5"
                    strokeLinecap="round" strokeDasharray={`${arc} ${full}`} />
                  <defs>
                    <linearGradient id="pg" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#7C3AED" />
                      <stop offset="100%" stopColor="#6366F1" />
                    </linearGradient>
                  </defs>
                </svg>
                <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <span style={{ fontSize: 15, fontWeight: 900, color: '#111827' }}>92</span>
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#374151' }}>/100</div>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#10B981', marginTop: 1 }}>Excellent</div>
                <div style={{ fontSize: 9, color: '#10B981', marginTop: 2 }}>+7.2% vs last week</div>
              </div>
            </div>
            <SparkLine />
          </div>
        </div>

        {/* User profile */}
        <div style={{ borderTop: '1px solid #EBEBF5', padding: '10px 10px', position: 'relative' }}>
          <button onClick={() => setMenuOpen(!menuOpen)}
            style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 9, padding: '8px 10px', borderRadius: 12, background: 'none', border: 'none', cursor: 'pointer', transition: 'background 0.15s' }}
            onMouseEnter={e => (e.currentTarget.style.background = '#F9FAFB')}
            onMouseLeave={e => (e.currentTarget.style.background = 'none')}
          >
            <div style={{ width: 30, height: 30, borderRadius: '50%', background: 'linear-gradient(135deg,#7C3AED,#4F46E5)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 700, color: '#fff', flexShrink: 0 }}>
              {initials}
            </div>
            <div style={{ flex: 1, textAlign: 'left', minWidth: 0 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#111827', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {user ? `${user.first_name || 'Admin'} ${user.last_name || 'User'}`.trim() : 'Admin User'}
              </div>
              <div style={{ fontSize: 9, color: '#9CA3AF', textTransform: 'capitalize' }}>
                {userRole === 'admin' ? 'Super Admin' : userRole}
              </div>
            </div>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#4ade80', flexShrink: 0 }} />
          </button>
          {menuOpen && (
            <div style={{ position: 'absolute', bottom: 56, left: 10, right: 10, background: '#fff', border: '1px solid #E5E7EB', borderRadius: 12, boxShadow: '0 8px 24px rgba(0,0,0,0.1)', zIndex: 50 }}>
              <div style={{ padding: '8px 12px', borderBottom: '1px solid #F3F4F6' }}>
                <div style={{ fontSize: 10, color: '#6B7280', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{user?.email || 'admin@aegivion.io'}</div>
              </div>
              <button onClick={handleLogout}
                style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', fontSize: 10, color: '#EF4444', background: 'none', border: 'none', cursor: 'pointer' }}
                onMouseEnter={e => (e.currentTarget.style.background = '#FFF5F5')}
                onMouseLeave={e => (e.currentTarget.style.background = 'none')}
              >
                <LogOut style={{ width: 12, height: 12 }} />Sign out
              </button>
            </div>
          )}
        </div>
      </aside>

      {/* ── MAIN ── */}
      <main style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {children}
      </main>
    </div>
  );
}

