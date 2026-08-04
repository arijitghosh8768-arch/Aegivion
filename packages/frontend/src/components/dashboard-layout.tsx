import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from '@tanstack/react-router';
import { useAuthStore } from '@/store/auth-store';
import {
  Shield, LayoutDashboard, Settings as SettingsIcon,
  AlertTriangle, Database, BrainCircuit, BarChart3,
  FileText, Users, Network, Zap, LogOut, TrendingUp
} from 'lucide-react';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const user = useAuthStore((state: any) => state.user);
  const logout = useAuthStore((state: any) => state.logout);
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate({ to: '/login' });
  };

  const userRole = user?.role || 'viewer';
  const userInitials = user
    ? `${user.first_name?.[0] || ''}${user.last_name?.[0] || ''}`.toUpperCase() || 'AU'
    : 'AU';

  const navItems = [
    { to: '/', label: 'Command Center', icon: LayoutDashboard },
    { to: '/ai-assistant', label: 'AI Copilot', icon: BrainCircuit },
    { to: '/cloud-accounts', label: 'Cloud Topology', icon: Network },
    { to: '/findings', label: 'Threats', icon: AlertTriangle },
    { to: '/assets', label: 'Assets', icon: Database },
    { to: '/compliance', label: 'Compliance', icon: BarChart3 },
    { to: '/reports', label: 'Reports', icon: FileText },
    { to: '/incidents', label: 'Automation', icon: Zap },
    { to: '/settings', label: 'Settings', icon: SettingsIcon },
  ];

  const isActive = (to: string) => {
    if (to === '/') return location.pathname === '/';
    return location.pathname.startsWith(to);
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[#F7F8FF]" style={{ fontFamily: "'Inter', sans-serif" }}>

      {/* â”€â”€â”€ Sidebar â”€â”€â”€ */}
      <aside className="w-52 shrink-0 bg-white border-r border-gray-100 flex flex-col h-full shadow-sm">

        {/* Logo */}
        <div className="px-5 py-4 border-b border-gray-100">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 bg-gradient-to-br from-purple-600 to-indigo-600 rounded-xl flex items-center justify-center shadow-md shadow-purple-200">
              <Shield className="w-4 h-4 text-white" aria-hidden="true" />
            </div>
            <div>
              <p className="text-[13px] font-black text-gray-900 leading-tight">Aegivion</p>
              <p className="text-[9px] text-gray-400 leading-tight">Autonomous Cloud Security</p>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto" aria-label="Main navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.to);
            return (
              <Link
                key={item.to}
                to={item.to}
                className={`flex items-center gap-2.5 px-3 py-2 rounded-xl text-[11px] font-medium transition-all ${
                  active
                    ? 'bg-purple-600 text-white shadow-md shadow-purple-200'
                    : 'text-gray-500 hover:bg-gray-50 hover:text-gray-900'
                }`}
              >
                <Icon className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Security Posture Score */}
        <div className="px-4 pb-3">
          <div className="bg-gray-50 rounded-2xl p-3 border border-gray-100">
            <p className="text-[9px] font-bold text-gray-400 uppercase tracking-widest mb-2">Security Posture</p>
            {/* Circular score indicator */}
            <div className="flex items-center gap-3">
              <div className="relative w-14 h-14 shrink-0">
                <svg className="w-14 h-14 -rotate-90" viewBox="0 0 56 56">
                  <circle cx="28" cy="28" r="22" fill="none" stroke="#E5E7EB" strokeWidth="5" />
                  <circle
                    cx="28" cy="28" r="22" fill="none"
                    stroke="url(#scoreGrad)" strokeWidth="5"
                    strokeLinecap="round"
                    strokeDasharray={`${2 * Math.PI * 22 * 0.92} ${2 * Math.PI * 22}`}
                  />
                  <defs>
                    <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#8B5CF6" />
                      <stop offset="100%" stopColor="#6366F1" />
                    </linearGradient>
                  </defs>
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-[13px] font-black text-gray-900">92</span>
                </div>
              </div>
              <div>
                <p className="text-[10px] font-bold text-gray-800">/100</p>
                <p className="text-[10px] text-green-600 font-semibold">Excellent</p>
                <p className="text-[9px] text-green-500 mt-0.5">+7.2% vs last week</p>
              </div>
            </div>
            {/* Mini trend line */}
            <div className="mt-2 flex items-end gap-0.5 h-4">
              {[40, 55, 45, 60, 58, 70, 75].map((v, i) => (
                <div key={i} className="flex-1 bg-gradient-to-t from-green-400 to-green-300 rounded-sm opacity-70"
                  style={{ height: `${(v / 75) * 100}%` }} />
              ))}
            </div>
          </div>
        </div>

        {/* User profile */}
        <div className="px-3 pb-3 border-t border-gray-100 pt-3 relative">
          <button
            onClick={() => setUserMenuOpen(!userMenuOpen)}
            aria-label={`User menu for ${user?.first_name || 'Admin'}`}
            className="w-full flex items-center gap-2.5 p-2 rounded-xl hover:bg-gray-50 transition-colors"
          >
            <div className="w-7 h-7 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center text-white text-[10px] font-bold shrink-0">
              {userInitials}
            </div>
            <div className="flex-1 min-w-0 text-left">
              <p className="text-[11px] font-semibold text-gray-800 truncate">{user?.first_name || 'Admin'} {user?.last_name || 'User'}</p>
              <p className="text-[9px] text-gray-400 capitalize">{userRole === 'admin' ? 'Super Admin' : userRole}</p>
            </div>
            <span className="w-2 h-2 bg-green-400 rounded-full shrink-0" />
          </button>

          {/* User dropdown */}
          {userMenuOpen && (
            <div className="absolute bottom-14 left-3 right-3 bg-white border border-gray-200 rounded-xl shadow-lg py-1 z-50">
              <div className="px-3 py-2 border-b border-gray-100">
                <p className="text-[10px] font-semibold text-gray-800 truncate">{user?.email || 'admin@aegivion.io'}</p>
              </div>
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-2 px-3 py-2 text-[10px] text-red-500 hover:bg-red-50 transition-colors"
              >
                <LogOut className="w-3 h-3" aria-hidden="true" />
                Sign out
              </button>
            </div>
          )}
        </div>
      </aside>

      {/* â”€â”€â”€ Main content â”€â”€â”€ */}
      <main className="flex-1 overflow-hidden flex flex-col">
        {children}
      </main>
    </div>
  );
}
