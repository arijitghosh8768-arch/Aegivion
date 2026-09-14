"use client";

import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useEffect, useState } from "react";
import {
  Menu,
  Search,
  Bell,
  Sun,
  Moon,
  CircleHelp,
  Check,
  LogOut,
  Bot,
  Settings,
  CheckCheck,
} from "lucide-react";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

export function Topbar({ onOpenMobile }: { onOpenMobile: () => void }) {
  const router = useRouter();
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 0);
    return () => clearTimeout(t);
  }, []);

  const { user, logout, workspaceId, workspaces, setWorkspace, notifications, markAllRead, markRead, setCommandOpen, appearance, setAppearance } =
    useAppStore();
  const unread = notifications.filter((n) => !n.read).length;
  const workspace = workspaces.find((w) => w.id === workspaceId) ?? workspaces[0];

  return (
    <header className="relative z-20 flex h-16 shrink-0 items-center gap-3 border-b border-border/70 bg-card/60 px-4 backdrop-blur-xl lg:px-7">
      <button
        onClick={onOpenMobile}
        className="flex h-9 w-9 items-center justify-center rounded-xl text-muted-foreground transition hover:bg-muted hover:text-foreground lg:hidden"
        aria-label="Open menu"
      >
        <Menu className="h-5 w-5" />
      </button>

      {/* Greeting */}
      <div className="min-w-0 leading-tight">
        <div className="truncate text-[15px] font-bold tracking-tight">
          Good Morning, {(mounted && user ? user.name.split(" ")[0] : "Admin")} 👏
        </div>
        <div className="hidden truncate text-[11px] text-muted-foreground sm:block">
          Aegivion AI is actively protecting your cloud environment.
        </div>
      </div>

      <div className="flex-1" />

      {/* Search */}
      <button
        onClick={() => setCommandOpen(true)}
        className="flex h-9 w-52 items-center gap-2 rounded-full border border-border bg-muted/50 px-4 text-sm text-muted-foreground transition hover:border-primary/40 hover:bg-muted md:w-64 lg:w-80"
      >
        <Search className="h-4 w-4 shrink-0" />
        <span className="flex-1 truncate text-left text-[12.5px]">Search assets, threats, incidents...</span>
        <kbd className="hidden rounded-md border border-border bg-card px-1.5 py-0.5 text-[10px] font-semibold sm:block">⌘K</kbd>
      </button>

      {/* Workspace selector */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button className="hidden h-9 cursor-pointer items-center gap-2 rounded-full border border-border bg-card/70 px-3.5 text-[12.5px] font-medium transition hover:bg-muted lg:flex">
            <span className="h-2 w-2 rounded-full bg-brand-gradient" />
            <span className="max-w-[130px] truncate">{workspace.name}</span>
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-64">
          <DropdownMenuLabel>Workspaces</DropdownMenuLabel>
          {workspaces.map((w) => (
            <DropdownMenuItem key={w.id} onClick={() => setWorkspace(w.id)}>
              <span className="flex-1">
                <span className="block">{w.name}</span>
                <span className="block text-[11px] text-muted-foreground">
                  {w.plan} · {w.region}
                </span>
              </span>
              {w.id === workspaceId && <Check className="h-4 w-4 text-primary" />}
            </DropdownMenuItem>
          ))}
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Help */}
      <button
        onClick={() => setCommandOpen(true)}
        className="hidden h-9 w-9 cursor-pointer items-center justify-center rounded-full text-muted-foreground transition hover:bg-muted hover:text-foreground sm:flex"
        aria-label="Help"
      >
        <CircleHelp className="h-[18px] w-[18px]" />
      </button>

      {/* Theme */}
      <button
        onClick={() => {
          const next = theme === "dark" ? "light" : "dark";
          setTheme(next);
          setAppearance({ themeMode: next === "dark" ? "dark" : "light" });
        }}
        className="flex h-9 w-9 cursor-pointer items-center justify-center rounded-full text-muted-foreground transition hover:bg-muted hover:text-foreground"
        aria-label="Toggle theme"
      >
        {mounted && (theme === "dark" || appearance.themeMode === "dark") ? (
          <Sun className="h-[18px] w-[18px]" />
        ) : (
          <Moon className="h-[18px] w-[18px]" />
        )}
      </button>

      {/* Notifications */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button className="relative flex h-9 w-9 cursor-pointer items-center justify-center rounded-full text-muted-foreground transition hover:bg-muted hover:text-foreground">
            <Bell className="h-[18px] w-[18px]" />
            {unread > 0 && (
              <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-brand-purple px-1 text-[9px] font-bold text-white">
                {unread}
              </span>
            )}
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-[360px] p-0">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <span className="text-sm font-semibold">Notifications</span>
            <button
              onClick={markAllRead}
              className="flex cursor-pointer items-center gap-1 text-[11px] font-medium text-primary hover:underline"
            >
              <CheckCheck className="h-3.5 w-3.5" /> Mark all read
            </button>
          </div>
          <div className="max-h-[340px] overflow-y-auto p-1.5">
            {notifications.slice(0, 8).map((n) => (
              <button
                key={n.id}
                onClick={() => markRead(n.id)}
                className={cn(
                  "flex w-full cursor-pointer flex-col gap-0.5 rounded-xl px-3 py-2.5 text-left transition hover:bg-muted/70",
                  !n.read && "bg-primary/[0.04]"
                )}
              >
                <div className="flex items-center gap-2">
                  {!n.read && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />}
                  <span className="text-[12.5px] font-semibold leading-tight">{n.title}</span>
                  <span className="ml-auto shrink-0 text-[10px] text-muted-foreground">{n.time}</span>
                </div>
                <span className="line-clamp-2 pl-3.5 text-[11.5px] leading-snug text-muted-foreground">{n.body}</span>
              </button>
            ))}
          </div>
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Profile */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button className="flex cursor-pointer items-center rounded-full p-0.5 transition hover:opacity-85">
            <Avatar className="h-8 w-8">
              {mounted && user?.avatar && <AvatarImage src={user.avatar} alt={user.name} />}
              <AvatarFallback className="bg-brand-gradient text-[11px] font-bold text-white">
                {(mounted && user ? user.name : "Admin User").slice(0, 2).toUpperCase()}
              </AvatarFallback>
            </Avatar>
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel>
            <span className="block text-[13px] font-semibold text-foreground">{(mounted && user ? user.name : "Admin User")}</span>
            <span className="block text-[11px] font-normal text-muted-foreground">{(mounted && user ? user.role : "Super Admin")}</span>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => router.push("/ai-copilot")}>
            <Bot /> AI Copilot
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => router.push("/settings")}>
            <Settings /> Settings
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            onClick={() => {
              logout();
              router.push("/login");
            }}
          >
            <LogOut /> Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  );
}
