"use client";

import Link from "next/link";
import { Shield, ArrowLeft } from "lucide-react";
import { AuthBackground } from "@/components/auth/auth-background";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative flex min-h-dvh flex-col overflow-hidden bg-background">
      <AuthBackground />
      <header className="relative z-10 flex h-16 items-center justify-between px-6 lg:px-10">
        <Link href="/" className="flex items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-gradient shadow-soft">
            <Shield className="h-5 w-5 text-white" />
          </span>
          <span className="text-[16px] font-bold tracking-tight">
            Aegivion<span className="text-gradient">.</span>
          </span>
        </Link>
        <Link
          href="/"
          className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12px] font-medium text-muted-foreground transition hover:bg-muted hover:text-foreground"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to app
        </Link>
      </header>
      <main className="relative z-10 flex flex-1 items-center justify-center px-4 py-10">{children}</main>
      <footer className="relative z-10 pb-6 text-center text-[11px] text-muted-foreground">
        © 2026 Aegivion Security Inc. · SOC 2 Type II · ISO 27001 · GDPR-ready
      </footer>
    </div>
  );
}
