"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion } from "framer-motion";
import { ShieldCheck, ChevronsLeft, ChevronsRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { NAV_SECTIONS } from "@/components/layout/nav";
import { useAppStore } from "@/lib/store";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

const SPARK = [52, 58, 55, 63, 68, 66, 74, 79, 77, 85, 88, 92];

export function Sidebar({ mobileOpen, onCloseMobile }: { mobileOpen: boolean; onCloseMobile: () => void }) {
  const pathname = usePathname();
  const collapsed = useAppStore((s) => s.sidebarCollapsed);
  const toggle = useAppStore((s) => s.toggleSidebar);
  const user = useAppStore((s) => s.user);
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 0);
    return () => clearTimeout(t);
  }, []);
  const displayName = mounted && user ? user.name : "Admin User";
  const displayRole = mounted && user ? user.role : "Super Admin";

  const body = (
    <div
      className={cn(
        "relative flex h-full flex-col overflow-hidden bg-card/85 backdrop-blur-xl transition-[width] duration-300",
        collapsed ? "w-[68px]" : "w-[216px]"
      )}
      style={{ boxShadow: "8px 0 30px -18px rgba(20,24,50,0.14)" }}
    >
      {/* Brand */}
      <div className={cn("relative flex h-14 shrink-0 items-center gap-2.5 px-4", collapsed && "justify-center px-0")}>
        <div className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-brand-gradient shadow-soft">
          <ShieldCheck className="h-[18px] w-[18px] text-white" strokeWidth={2.2} />
          <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full border-2 border-card bg-success" />
        </div>
        {!collapsed && (
          <div className="min-w-0 flex-1 leading-tight">
            <div className="text-[15px] font-bold tracking-tight text-foreground">Aegivion</div>
            <div className="truncate text-[8px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              Autonomous Cloud Security Copilot
            </div>
          </div>
        )}
        {/* Collapse toggle in brand row */}
        <button
          onClick={toggle}
          className={cn(
            "flex h-7 w-7 shrink-0 cursor-pointer items-center justify-center rounded-lg text-muted-foreground transition hover:bg-muted hover:text-foreground",
            collapsed ? "absolute right-1.5 top-1.5" : "hidden"
          )}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronsRight className="h-4 w-4" /> : <ChevronsLeft className="h-4 w-4" />}
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2.5 pb-1 pt-1">
        {NAV_SECTIONS.map((section) => {
          const isAdmin = displayRole.toLowerCase().includes("admin");
          if (section.label === "Admin" && !isAdmin) return null;
          
          const filteredItems = section.items.filter(item => {
            if (item.title === "Cloud Accounts" && !isAdmin) return false;
            return true;
          });
          
          if (filteredItems.length === 0) return null;

          return (
          <div key={section.label} className="mb-2">
            {!collapsed && (
              <div className="mb-1 px-2 text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground/80">
                {section.label}
              </div>
            )}
            <div className="space-y-0.5">
              {filteredItems.map((item) => {
                const active = pathname === item.href;
                const Icon = item.icon;
                const link = (
                  <Link
                    href={item.href}
                    onClick={onCloseMobile}
                    className={cn(
                      "group relative flex items-center gap-2.5 rounded-lg px-2.5 py-[7px] text-[12.5px] font-medium transition-colors duration-200",
                      collapsed && "justify-center px-0",
                      active ? "text-primary" : "text-muted-foreground hover:bg-muted/70 hover:text-foreground"
                    )}
                  >
                    {active && (
                      <motion.span
                        layoutId="nav-pill"
                        className="absolute inset-0 rounded-lg border border-primary/15 bg-primary/10"
                        transition={{ type: "spring", stiffness: 400, damping: 32 }}
                      />
                    )}
                    {active && (
                      <motion.span
                        layoutId="nav-bar"
                        className="absolute left-0 top-1/2 h-4 w-[3px] -translate-y-1/2 rounded-full bg-brand-gradient"
                      />
                    )}
                    <Icon
                      className={cn("relative z-10 h-4 w-4 shrink-0", active && "text-primary")}
                      strokeWidth={active ? 2.2 : 1.9}
                    />
                    {!collapsed && <span className="relative z-10 flex-1 truncate">{item.title}</span>}
                    {!collapsed && item.badge && (
                      <span className="relative z-10 rounded-full bg-destructive/12 px-1.5 py-0.5 text-[9.5px] font-bold text-destructive">
                        {item.badge}
                      </span>
                    )}
                  </Link>
                );

                if (!collapsed) return <div key={item.href}>{link}</div>;

                return (
                  <Tooltip key={item.href}>
                    <TooltipTrigger asChild>{link}</TooltipTrigger>
                    <TooltipContent side="right">
                      {item.title}
                      {item.badge ? ` (${item.badge})` : ""}
                    </TooltipContent>
                  </Tooltip>
                );
              })}
            </div>
          </div>
        )})}
      </nav>

      {/* Security Posture widget — compact */}
      {!collapsed && (
        <div className="mx-2.5 mb-2 rounded-xl border border-border/80 bg-gradient-to-b from-muted/60 to-muted/20 p-3">
          <div className="mb-2 text-[9px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
            Security Posture
          </div>
          <div className="flex items-center gap-3">
            <div className="relative h-[84px] w-[84px] shrink-0">
              <svg width="84" height="84" viewBox="0 0 84 84" className="-rotate-90">
                <defs>
                  <linearGradient id="posture-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#22c55e" />
                    <stop offset="55%" stopColor="#4f7cf7" />
                    <stop offset="100%" stopColor="#6d5df6" />
                  </linearGradient>
                </defs>
                <circle cx="42" cy="42" r="35" fill="none" stroke="var(--border)" strokeWidth="7" />
                <motion.circle
                  cx="42"
                  cy="42"
                  r="35"
                  fill="none"
                  stroke="url(#posture-grad)"
                  strokeWidth="7"
                  strokeLinecap="round"
                  strokeDasharray={2 * Math.PI * 35}
                  initial={{ strokeDashoffset: 2 * Math.PI * 35 }}
                  animate={{ strokeDashoffset: 2 * Math.PI * 35 * (1 - 92 / 100) }}
                  transition={{ duration: 1.6, ease: [0.22, 1, 0.36, 1] }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-[22px] font-bold leading-none tracking-tight">92</span>
                <span className="text-[8.5px] font-medium text-muted-foreground">/ 100</span>
              </div>
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-[12px] font-bold text-success">Excellent</div>
              <div className="text-[10px] font-medium text-success">+7.2% vs last week</div>
              <svg width="100%" height="20" viewBox="0 0 100 20" preserveAspectRatio="none" className="mt-1.5 block">
                {(() => {
                  const min = Math.min(...SPARK);
                  const max = Math.max(...SPARK);
                  const range = max - min || 1;
                  const pts = SPARK.map(
                    (v, i) => `${(i / (SPARK.length - 1)) * 100},${20 - ((v - min) / range) * 17 - 1.5}`
                  );
                  return (
                    <>
                      <polygon points={`0,20 ${pts.join(" ")} 100,20`} fill="rgba(34,197,94,0.18)" />
                      <polyline
                        points={pts.join(" ")}
                        fill="none"
                        stroke="#22c55e"
                        strokeWidth="1.6"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </>
                  );
                })()}
              </svg>
            </div>
          </div>
        </div>
      )}

      {/* Profile */}
      <div className={cn("flex shrink-0 items-center gap-2.5 border-t border-border/70 py-2.5", collapsed ? "justify-center px-0" : "px-3.5")}>
        <div className="relative shrink-0">
          <Avatar className="h-8 w-8">
            {user?.avatar && <AvatarImage src={user.avatar} alt={displayName} />}
            <AvatarFallback className="bg-brand-gradient text-[11px] font-bold text-white">
              {displayName.slice(0, 2).toUpperCase()}
            </AvatarFallback>
          </Avatar>
          <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-card bg-success" />
        </div>
        {!collapsed && (
          <div className="min-w-0 flex-1 leading-tight">
            <div className="truncate text-[12px] font-semibold">{displayName}</div>
            <div className="truncate text-[10px] text-muted-foreground">{displayRole}</div>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <TooltipProvider delayDuration={200}>
      {/* Desktop */}
      <div className="relative z-30 hidden shrink-0 lg:block">{body}</div>
      {/* Mobile drawer */}
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onCloseMobile} />
          <motion.div
            initial={{ x: -280 }}
            animate={{ x: 0 }}
            transition={{ type: "spring", stiffness: 380, damping: 34 }}
            className="absolute inset-y-0 left-0"
          >
            {body}
          </motion.div>
        </div>
      )}
    </TooltipProvider>
  );
}
