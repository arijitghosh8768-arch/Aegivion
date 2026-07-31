import React, { useState } from 'react';
import { Link } from '@tanstack/react-router';
import { 
  Shield, 
  LayoutDashboard, 
  Settings as SettingsIcon, 
  Menu, 
  X,
  AlertTriangle,
  Database,
  BrainCircuit,
  BarChart3,
  Search,
  Bell,
  Moon,
  Sun,
  ChevronDown,
  Terminal,
  FileText
} from 'lucide-react';

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [isGrayscale, setIsGrayscale] = useState(false);
  const [isLightMode, setIsLightMode] = useState(false);

  const toggleGrayscale = () => {
    setIsGrayscale(!isGrayscale);
    if (!isGrayscale) {
      document.documentElement.classList.add('grayscale-mode');
    } else {
      document.documentElement.classList.remove('grayscale-mode');
    }
  };

  const toggleLightMode = () => {
    setIsLightMode(!isLightMode);
    if (!isLightMode) {
      document.documentElement.classList.add('light-mode');
    } else {
      document.documentElement.classList.remove('light-mode');
    }
  };

  const tabs = [
    { to: '/', name: 'Dashboard', icon: LayoutDashboard },
    { to: '/cloud-accounts', name: 'Cloud Accounts', icon: Shield },
    { to: '/assets', name: 'Assets', icon: Database },
    { to: '/findings', name: 'Findings', icon: AlertTriangle, badge: '23' },
    { to: '/incidents', name: 'Incidents', icon: Terminal, badge: '6' },
    { to: '/compliance', name: 'Compliance', icon: BarChart3 },
    { to: '/ai-assistant', name: 'AI Assistant', icon: BrainCircuit },
    { to: '/reports', name: 'Reports', icon: FileText },
    { to: '/settings', name: 'Settings', icon: SettingsIcon },
  ];

  return (
    <div className="flex h-screen bg-[#0b0f19] text-gray-100 font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 z-40 w-64 bg-[#0d1326] border-r border-gray-800 transform transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:flex lg:flex-col justify-between
        ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <div>
          <div className="h-16 flex items-center px-6 gap-3 border-b border-gray-800">
            <Shield className="w-6 h-6 text-blue-500 animate-pulse shrink-0" />
            <div>
              <span className="text-sm font-bold tracking-wider text-white block">Aegivion</span>
              <span className="text-[10px] text-gray-500 block">Cloud Security Platform</span>
            </div>
          </div>
          
          <nav className="px-4 py-6 space-y-1">
            <span className="text-[9px] font-bold text-gray-500 tracking-wider uppercase px-4 block mb-2">Overview</span>
            {tabs.slice(0, 3).map((tab) => {
              const Icon = tab.icon;
              return (
                <Link
                  key={tab.to}
                  to={tab.to}
                  activeProps={{ className: 'bg-blue-600/10 text-blue-400 border-l-2 border-blue-500' }}
                  inactiveProps={{ className: 'text-gray-400 hover:bg-gray-800/30 hover:text-white' }}
                  className="w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all"
                >
                  <Icon size={14} />
                  {tab.name}
                </Link>
              );
            })}

            <span className="text-[9px] font-bold text-gray-500 tracking-wider uppercase px-4 block pt-4 pb-2">Security Operations</span>
            {tabs.slice(3, 6).map((tab) => {
              const Icon = tab.icon;
              return (
                <Link
                  key={tab.to}
                  to={tab.to}
                  activeProps={{ className: 'bg-blue-600/10 text-blue-400 border-l-2 border-blue-500' }}
                  inactiveProps={{ className: 'text-gray-400 hover:bg-gray-800/30 hover:text-white' }}
                  className="w-full flex items-center justify-between px-4 py-2 rounded-lg text-xs font-medium transition-all"
                >
                  <div className="flex items-center gap-3">
                    <Icon size={14} />
                    {tab.name}
                  </div>
                  {tab.badge && (
                    <span className="text-[9px] font-bold text-red-500 px-1">{tab.badge}</span>
                  )}
                </Link>
              );
            })}

            <span className="text-[9px] font-bold text-gray-500 tracking-wider uppercase px-4 block pt-4 pb-2">Intelligence</span>
            {tabs.slice(6).map((tab) => {
              const Icon = tab.icon;
              return (
                <Link
                  key={tab.to}
                  to={tab.to}
                  activeProps={{ className: 'bg-blue-600/10 text-blue-400 border-l-2 border-blue-500' }}
                  inactiveProps={{ className: 'text-gray-400 hover:bg-gray-800/30 hover:text-white' }}
                  className="w-full flex items-center gap-3 px-4 py-2 rounded-lg text-xs font-medium transition-all"
                >
                  <Icon size={14} />
                  {tab.name}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Posture Score Display at Sidebar Bottom */}
        <div className="p-4 border-t border-gray-800/80">
          <div className="bg-[#0b0f19]/80 border border-gray-850 rounded-xl p-3">
            <span className="text-[10px] text-gray-500 font-semibold block uppercase">Posture score</span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-extrabold text-white">87</span>
              <span className="text-[10px] text-green-500 font-medium">+5 vs last month</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Pane */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Global Top Nav bar */}
        <header className="h-14 bg-[#0d1326] border-b border-gray-800 px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-4 flex-1">
            <button 
              className="p-1.5 rounded bg-gray-800 border border-gray-700 text-white lg:hidden"
              onClick={() => setSidebarOpen(!sidebarOpen)}
            >
              {sidebarOpen ? <X size={16} /> : <Menu size={16} />}
            </button>

            {/* Dropdown selector */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 bg-[#0b0f19] border border-gray-800 rounded-lg text-xs font-semibold hover:border-gray-700 cursor-pointer transition select-none">
              <Shield size={12} className="text-blue-500" />
              <span>Aegivion Global</span>
              <ChevronDown size={12} className="text-gray-500" />
            </div>

            {/* Search Input */}
            <div className="relative max-w-md w-full hidden md:block">
              <Search className="absolute left-3 top-2.5 text-gray-600" size={12} />
              <input 
                type="text"
                placeholder="Search assets, findings, incidents..."
                className="w-full bg-[#0b0f19] border border-gray-850 rounded-lg pl-8 pr-4 py-1.5 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-gray-800 transition"
              />
            </div>
          </div>

          <div className="flex items-center gap-4">
            <button className="relative p-1.5 text-gray-400 hover:text-white transition">
              <Bell size={16} />
              <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
            </button>
            <button 
              onClick={toggleGrayscale}
              className={`p-1.5 rounded-lg transition ${isGrayscale ? 'bg-white text-black' : 'text-gray-400 hover:text-white'}`}
              title="Toggle Grayscale Mode"
            >
              <Moon size={16} />
            </button>
            <button 
              onClick={toggleLightMode}
              className={`p-1.5 rounded-lg transition ${isLightMode ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white hover:bg-gray-800/30'}`}
              title="Toggle Light/Dark Mode"
            >
              {isLightMode ? <Sun size={16} /> : <Sun className="rotate-45" size={16} />}
            </button>
            <div className="w-8 h-8 rounded-full bg-blue-600/20 text-blue-400 flex items-center justify-center font-bold text-xs select-none cursor-pointer">
              RO
            </div>
          </div>
        </header>

        {/* View content panel */}
        <main className="flex-1 overflow-y-auto p-6 lg:p-8 bg-[#0b0f19]">
          {children}
        </main>
      </div>
    </div>
  );
}
