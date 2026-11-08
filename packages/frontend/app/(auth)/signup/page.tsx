"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { Loader2, Check, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAppStore } from "@/lib/store";

const PERKS = [
  "14-day Enterprise trial — no card required",
  "Connect unlimited AWS, Azure & GCP accounts",
  "AI auto-remediation with rollback",
];

export default function SignupPage() {
  const router = useRouter();
  const login = useAppStore((s) => s.login);
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState("");
  const [orgName, setOrgName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    if (!name || !email || !orgName) {
      setErrorMsg("Please complete all required fields.");
      return;
    }
    if (password.length < 8) {
      setErrorMsg("Password must be at least 8 characters long.");
      return;
    }

    setLoading(true);
    try {
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || "https://aegivion.onrender.com";
      const res = await fetch(`${baseUrl}/api/v1/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: name,
          organization_name: orgName,
          email,
          password,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to create workspace.");
      }

      // Store JWT token and refresh token
      if (data.token) {
        localStorage.setItem("aegivion_token", data.token);
      }
      if (data.refresh_token) {
        localStorage.setItem("aegivion_refresh_token", data.refresh_token);
      }

      // Update local state store
      login({
        name: data.user.name || name,
        email: data.user.email,
        role: data.user.role || "organization_admin",
        company: data.user.organization_name || orgName,
      });

      // Redirect to onboarding or main dashboard
      router.push("/");
    } catch (err: any) {
      setErrorMsg(err.message || "An unexpected error occurred during signup.");
      setLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
      className="w-full max-w-[440px]"
    >
      <div className="rounded-3xl border border-border/80 bg-card/80 p-8 shadow-lift backdrop-blur-2xl">
        <div className="mb-7 text-center">
          <h1 className="text-[22px] font-bold tracking-tight">Create your workspace</h1>
          <p className="mt-1 text-[13px] text-muted-foreground">
            Start securing your cloud in under 5 minutes
          </p>
        </div>

        <ul className="mb-6 space-y-1.5">
          {PERKS.map((p) => (
            <li key={p} className="flex items-center gap-2 text-[12.5px] text-muted-foreground">
              <span className="flex h-4 w-4 items-center justify-center rounded-full bg-success/15">
                <Check className="h-2.5 w-2.5 text-success" />
              </span>
              {p}
            </li>
          ))}
        </ul>

        {errorMsg && (
          <div className="mb-4 flex items-center gap-2 rounded-xl border border-destructive/20 bg-destructive/10 p-3 text-xs text-destructive">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="name">Full name</Label>
            <Input id="name" placeholder="Alex Rivera" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="orgName">Organization / Company name</Label>
            <Input id="orgName" placeholder="Acme Cybersecurity" value={orgName} onChange={(e) => setOrgName(e.target.value)} required />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="email">Work email</Label>
            <Input
              id="email"
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              placeholder="8+ characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <Button type="submit" size="lg" variant="gradient" className="w-full" disabled={loading}>
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Creating workspace…
              </>
            ) : (
              "Create workspace"
            )}
          </Button>
        </form>

        <p className="mt-5 text-center text-[12.5px] text-muted-foreground">
          Already have an account?{" "}
          <Link href="/login" className="font-semibold text-primary hover:underline">
            Sign in
          </Link>
        </p>
      </div>
      <p className="mt-4 text-center text-[11px] text-muted-foreground">
        By signing up you agree to the Terms of Service and Privacy Policy.
      </p>
    </motion.div>
  );
}
