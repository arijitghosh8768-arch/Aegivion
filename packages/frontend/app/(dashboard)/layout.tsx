"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
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
  const pathname = usePathname();

  const fetchOrgSettings = useAppStore((s) => s.fetchOrgSettings);

  // Auth gate: only redirect once the persisted session has been rehydrated.
  // Without this, every refresh redirects to /login before the saved user loads,
  // and the topbar/sidebar can appear missing after navigation.
  useEffect(() => {
    if (hydrated && !user) {
      router.replace("/login");
    } else if (hydrated && user) {
      const isAdmin = user.role.toLowerCase().includes("admin");
      if ((pathname.startsWith("/settings") || pathname === "/cloud-accounts") && !isAdmin) {
        router.replace("/");
      }
      // Assuming user has a default org_id "org-1" for demo purposes
      fetchOrgSettings("org-1");
    }
  }, [hydrated, user, router, pathname, fetchOrgSettings]);

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



        <CommandMenu />
      </div>
    </TooltipProvider>
  );
}
