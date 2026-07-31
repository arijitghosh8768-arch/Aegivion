"use client";

import { Bell, Moon, Sun, Search, User } from "lucide-react";
import { useAuthStore } from "@/store/auth-store";

export function TopNav() {
  const user = useAuthStore((state) => state.user);

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b border-surface-border bg-[#1E293B] px-6">
      <div className="relative w-full max-w-sm flex items-center">
        <Search className="absolute left-2.5 h-4 w-4 text-slate-400" />
        <input
          type="search"
          placeholder="Search assets, findings..."
          className="w-full pl-8 pr-3 py-1.5 rounded bg-[#0F172A] border border-[#334155] text-sm text-slate-100 placeholder-slate-400 focus:outline-none"
        />
      </div>

      <div className="ml-auto flex items-center gap-2">
        <button className="relative p-2 text-slate-400 hover:text-white">
          <Bell className="h-5 w-5" />
          <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-red-600" />
        </button>
        
        <button className="flex items-center gap-2 p-2 text-slate-300 hover:text-white">
          <div className="h-8 w-8 rounded-full bg-blue-600 flex items-center justify-center text-white">
            <User className="h-4 w-4" />
          </div>
          <span className="hidden md:inline text-sm font-medium">{user?.name || "Admin"}</span>
        </button>
      </div>
    </header>
  );
}
