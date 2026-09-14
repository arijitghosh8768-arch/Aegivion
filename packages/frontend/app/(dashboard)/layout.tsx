"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { X, TriangleAlert, Loader2 } from "lucide-react";
import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import { CommandMenu } from "@/components/layout/command-menu";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAppStore } from "@/lib/store";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const user = useAppStore((s) => s.user);
  const hydrated = useAppStore((s) => s.hydrated);
  const collapsed = useAppStore((s) => s.sidebarCollapsed);
  const router = useRouter();

  // Auth gate: only redirect once the persisted session has been rehydrated.
  // Without this, every refresh redirects to /login before the saved user loads,
  // and the topbar/sidebar can appear missing after navigation.
  useEffect(() => {
    if (hydrated && !user) {
      router.replace("/login");
    }
  }, [hydrated, user, router]);

  // Safety fallback: if rehydration never fires (storage unavailable), never deadlock.
  useEffect(() => {
    const t = setTimeout(() => {
      if (!hydrated) useAppStore.setState({ hydrated: true });
    }, 2000);
    return () => clearTimeout(t);
  }, [hydrated]);

  if (!hydrated) {
    return (
      <div className="flex h-dvh items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3">
          <span className="flex h-12 w-12 items-center justify-center rounded-2xl bg-brand-gradient shadow-soft">
            <Loader2 className="h-6 w-6 animate-spin text-white" />
          </span>
          <p className="text-[12px] font-medium text-muted-foreground">Loading your secure workspace…</p>
        </div>
      </div>
    );
  }

  return (
    <TooltipProvider delayDuration={200}>
      <div className="relative flex h-dvh overflow-hidden bg-background">
        {/* Ambient background */}
        <div className="pointer-events-none absolute inset-0 z-0">
          <div className="absolute -top-40 left-1/4 h-[480px] w-[480px] rounded-full bg-brand-purple/12 blur-[120px]" />
          <div className="absolute -bottom-40 right-1/5 h-[420px] w-[420px] rounded-full bg-brand-blue/12 blur-[120px]" />
          <div className="absolute inset-0 bg-grid opacity-40 [mask-image:radial-gradient(ellipse_at_top,black,transparent_65%)]" />
        </div>

        <Sidebar mobileOpen={mobileOpen} onCloseMobile={() => setMobileOpen(false)} />
        <div className="relative z-10 flex min-w-0 flex-1 flex-col">
          <Topbar onOpenMobile={() => setMobileOpen(true)} />
          <main className="flex-1 overflow-y-auto">
            <div className="mx-auto max-w-[1440px] px-4 py-4 lg:px-6">{children}</div>
          </main>
        </div>

        {/* Floating issues pill (bottom-left, over the sidebar edge) */}
        <div
          className="pointer-events-none absolute bottom-5 z-40 hidden transition-all duration-300 lg:block"
          style={{ left: collapsed ? 88 : 236 }}
        >
          <Link
            href="/remediation"
            className="pointer-events-auto flex items-center gap-2 rounded-full bg-destructive py-1 pl-1 pr-2.5 text-white shadow-lift transition hover:brightness-110"
          >
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-white/20">
              <TriangleAlert className="h-3.5 w-3.5" />
            </span>
            <span className="text-[11.5px] font-semibold">2 Issues</span>
            <X className="h-3.5 w-3.5 opacity-80" />
          </Link>
        </div>

        <CommandMenu />
      </div>
    </TooltipProvider>
  );
}
