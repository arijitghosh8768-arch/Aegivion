"use client";

import { useState } from "react";
import Link from "next/link";
import { motion } from "framer-motion";
import { ArrowLeft, Loader2, MailCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    setLoading(true);
    setTimeout(() => {
      setLoading(false);
      setSent(true);
    }, 900);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
      className="w-full max-w-[420px]"
    >
      <div className="rounded-3xl border border-border/80 bg-card/80 p-8 shadow-lift backdrop-blur-2xl">
        <Link
          href="/login"
          className="mb-6 inline-flex items-center gap-1.5 text-[12px] font-semibold text-muted-foreground transition hover:text-foreground"
        >
          <ArrowLeft className="h-3.5 w-3.5" /> Back to sign in
        </Link>

        {sent ? (
          <div className="py-6 text-center">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-success/12">
              <MailCheck className="h-7 w-7 text-success" />
            </div>
            <h1 className="text-[20px] font-bold tracking-tight">Check your inbox</h1>
            <p className="mx-auto mt-2 max-w-xs text-[13px] leading-relaxed text-muted-foreground">
              We sent a password-reset link to <span className="font-semibold text-foreground">{email}</span>. The link
              expires in 30 minutes.
            </p>
            <Button variant="outline" className="mt-6 w-full" onClick={() => setSent(false)}>
              Use a different email
            </Button>
          </div>
        ) : (
          <>
            <h1 className="text-[22px] font-bold tracking-tight">Reset your password</h1>
            <p className="mt-1 text-[13px] text-muted-foreground">
              Enter your work email and we&apos;ll send you a secure reset link.
            </p>
            <form onSubmit={submit} className="mt-6 space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="email">Work email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
              <Button type="submit" size="lg" variant="gradient" className="w-full" disabled={loading}>
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" /> Sending link…
                  </>
                ) : (
                  "Send reset link"
                )}
              </Button>
            </form>
          </>
        )}
      </div>
    </motion.div>
  );
}
