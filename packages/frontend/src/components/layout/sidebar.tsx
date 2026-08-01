"use client";

import { Link, useLocation } from "@tanstack/react-router";
import { cn } from "@/lib/utils";
import { 
  LayoutDashboard, Cloud, ShieldAlert, FileWarning, 
  Siren, Scale, Bot, FileText, Settings, ChevronLeft 
} from "lucide-react";
import { useUIStore } from "@/store/ui-store";

const menuItems = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Cloud Accounts", href: "/cloud-accounts", icon: Cloud },
  { name: "Assets", href: "/assets", icon: ShieldAlert },
  { name: "Findings", href: "/findings", icon: FileWarning },
  { name: "Incidents", href: "/incidents", icon: Siren },
  { name: "Compliance", href: "/compliance", icon: Scale },
  { name: "AI Assistant", href: "/ai", icon: Bot },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
];

export function Sidebar() {
  const pathname = useLocation().pathname;
  const { isCollapsed, toggleSidebar } = useUIStore();

  return (
    <aside className={cn(
      "fixed left-0 top-0 z-40 h-screen border-r border-surface-border bg-[#1E293B] transition-all duration-300",
      isCollapsed ? "w-16" : "w-64"
    )}>
      <div className="flex h-16 items-center justify-between border-b border-surface-border px-4">
        {!isCollapsed && <span className="text-xl font-bold text-blue-500">Aegivion</span>}
        <button
          onClick={toggleSidebar}
          aria-label={isCollapsed ? "Expand navigation sidebar" : "Collapse navigation sidebar"}
          title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="h-8 w-8 text-slate-300 hover:text-white flex items-center justify-center"
        >
          <ChevronLeft className={cn("h-4 w-4 transition-transform", isCollapsed && "rotate-180")} aria-hidden="true" />
        </button>
      </div>

      <nav className="flex flex-col gap-1 p-2">
        {menuItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.name}
              to={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive 
                  ? "bg-blue-600/10 text-blue-400" 
                  : "text-slate-400 hover:bg-slate-800 hover:text-slate-100"
              )}
            >
              <item.icon className="h-5 w-5 flex-shrink-0" />
              {!isCollapsed && <span>{item.name}</span>}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
