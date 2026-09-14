"use client";

import { useEffect, useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { motion } from "framer-motion";
import { useGoogleLogin } from "@react-oauth/google";
import { Loader2, ShieldCheck, Mail, CheckCircle2, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAppStore } from "@/lib/store";

function InviteAcceptanceContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token");
  const login = useAppStore((s) => s.login);

  const [status, setStatus] = useState<"loading" | "valid" | "expired" | "accepted" | "error" | "wrong_account" | "success">("loading");
  const [inviteDetails, setInviteDetails] = useState<{ email: string; role: string; organization_name: string } | null>(null);
  const [errorMessage, setErrorMessage] = useState("");

  useEffect(() => {
    if (!token) {
      setStatus("error");
      setErrorMessage("No invitation token provided.");
      return;
    }

    // Simulate API validation
    const validateToken = async () => {
      try {
        const res = await fetch(`http://localhost:8000/api/v1/invitations/${token}`);
        if (res.ok) {
          const json = await res.json();
          setInviteDetails(json.data);
          setStatus("valid");
        } else {
          const err = await res.json();
          if (err.detail && err.detail.includes("expired")) {
            setStatus("expired");
          } else if (err.detail && err.detail.includes("already")) {
            setStatus("accepted");
          } else {
            setStatus("error");
            setErrorMessage(err.detail || "Invalid invitation token.");
          }
        }
      } catch (e) {
        // Fallback for demo if backend is offline
        setStatus("valid");
        setInviteDetails({
          email: "demo@company.com",
          role: "Security Analyst",
          organization_name: "ABC Technologies",
        });
      }
    };
    
    validateToken();
  }, [token]);

  const handleGoogleLogin = useGoogleLogin({
    onSuccess: async (tokenResponse) => {
      setStatus("loading");
      try {
        const userInfo = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
          headers: { Authorization: `Bearer ${tokenResponse.access_token}` },
        }).then((res) => res.json());

        // Here we simulate the logic: if Google email doesn't match invite email
        if (inviteDetails && userInfo.email.toLowerCase() !== inviteDetails.email.toLowerCase()) {
          setStatus("wrong_account");
          return;
        }

        if (inviteDetails) {
          login({
            name: userInfo.name || "New User",
            email: userInfo.email,
            role: inviteDetails.role,
            company: inviteDetails.organization_name,
          });
          setStatus("success");
        }
      } catch (err) {
        setStatus("error");
        setErrorMessage("Failed to authenticate with Google.");
      }
    },
    onError: (err) => {
      console.error("Google Login Error:", err);
      // Fallback for development demo
      if (inviteDetails) {
        login({
          name: "New User",
          email: inviteDetails.email,
          role: inviteDetails.role,
          company: inviteDetails.organization_name,
        });
        setStatus("success");
      } else {
        setStatus("error");
        setErrorMessage("Google Login was cancelled or failed.");
      }
    }
  });

  if (status === "loading") {
    return (
      <div className="flex flex-col items-center justify-center space-y-4">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Validating invitation...</p>
      </div>
    );
  }

  if (status === "expired") {
    return (
      <div className="w-full max-w-[420px] rounded-3xl border border-border/80 bg-card/80 p-8 text-center shadow-lift backdrop-blur-2xl">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <h1 className="mb-2 text-[20px] font-bold">Invitation expired</h1>
        <p className="mb-6 text-[13.5px] text-muted-foreground">
          This invitation is no longer valid. Ask your organization administrator to send you a new invitation.
        </p>
        <Button variant="outline" className="w-full" onClick={() => router.push("/login")}>
          Back to Login
        </Button>
      </div>
    );
  }

  if (status === "accepted") {
    return (
      <div className="w-full max-w-[420px] rounded-3xl border border-border/80 bg-card/80 p-8 text-center shadow-lift backdrop-blur-2xl">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-success/10">
          <CheckCircle2 className="h-6 w-6 text-success" />
        </div>
        <h1 className="mb-2 text-[20px] font-bold">Invitation already accepted</h1>
        <p className="mb-6 text-[13.5px] text-muted-foreground">
          This invitation has already been used. You can proceed directly to your dashboard.
        </p>
        <Button variant="gradient" className="w-full" onClick={() => router.push("/")}>
          Go to Dashboard
        </Button>
      </div>
    );
  }

  if (status === "error") {
    return (
      <div className="w-full max-w-[420px] rounded-3xl border border-border/80 bg-card/80 p-8 text-center shadow-lift backdrop-blur-2xl">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <h1 className="mb-2 text-[20px] font-bold">Invalid invitation</h1>
        <p className="mb-6 text-[13.5px] text-muted-foreground">
          {errorMessage || "This invitation link is invalid or malformed."}
        </p>
        <Button variant="outline" className="w-full" onClick={() => router.push("/login")}>
          Back to Login
        </Button>
      </div>
    );
  }

  if (status === "wrong_account") {
    return (
      <div className="w-full max-w-[420px] rounded-3xl border border-border/80 bg-card/80 p-8 text-center shadow-lift backdrop-blur-2xl">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-destructive/10">
          <AlertTriangle className="h-6 w-6 text-destructive" />
        </div>
        <h1 className="mb-2 text-[20px] font-bold">Email doesn't match</h1>
        <p className="mb-4 text-[13.5px] text-muted-foreground">
          This invitation was issued for: <strong>{inviteDetails?.email}</strong>
        </p>
        <p className="mb-6 text-[13.5px] text-muted-foreground">
          You're currently signed in as a different account. Please sign in with the invited account.
        </p>
        <Button variant="outline" className="w-full" onClick={() => setStatus("valid")}>
          Sign out & try again
        </Button>
      </div>
    );
  }

  if (status === "success" && inviteDetails) {
    return (
      <div className="w-full max-w-[420px] rounded-3xl border border-border/80 bg-card/80 p-8 text-center shadow-lift backdrop-blur-2xl">
        <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-success/10">
          <CheckCircle2 className="h-7 w-7 text-success" />
        </div>
        <h1 className="mb-2 text-[20px] font-bold">Welcome to {inviteDetails.organization_name}</h1>
        <p className="mb-6 text-[13.5px] text-muted-foreground">
          Your account has been added as: <strong>{inviteDetails.role}</strong>
        </p>
        <Button variant="gradient" className="w-full" onClick={() => router.push("/")}>
          Open Dashboard
        </Button>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
      className="w-full max-w-[420px]"
    >
      <div className="rounded-3xl border border-border/80 bg-card/80 p-8 shadow-lift backdrop-blur-2xl">
        <div className="mb-7 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-brand-gradient shadow-soft">
            <Mail className="h-6 w-6 text-white" />
          </div>
          <h1 className="text-[22px] font-bold tracking-tight">You've been invited to Aegivion</h1>
          <p className="mt-2 text-[13.5px] text-muted-foreground leading-relaxed">
            An administrator from <strong className="text-foreground">{inviteDetails?.organization_name}</strong> invited you to join their security workspace.
          </p>
        </div>

        <div className="mb-8 rounded-xl border border-border bg-muted/40 p-4">
          <div className="flex justify-between py-1 border-b border-border/50 pb-2 mb-2">
            <span className="text-[12.5px] text-muted-foreground">Role</span>
            <span className="text-[12.5px] font-semibold">{inviteDetails?.role}</span>
          </div>
          <div className="flex justify-between py-1">
            <span className="text-[12.5px] text-muted-foreground">Email</span>
            <span className="text-[12.5px] font-semibold text-primary">{inviteDetails?.email}</span>
          </div>
        </div>

        <Button type="button" variant="outline" size="lg" onClick={() => handleGoogleLogin()} className="w-full flex items-center justify-center gap-2">
          <svg width="16" height="16" viewBox="0 0 48 48" className="shrink-0">
            <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
            <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
            <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
            <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
          </svg>
          Continue with Google
        </Button>
      </div>
    </motion.div>
  );
}

export default function InviteAcceptancePage() {
  return (
    <Suspense fallback={
      <div className="flex flex-col items-center justify-center space-y-4">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Loading invitation...</p>
      </div>
    }>
      <InviteAcceptanceContent />
    </Suspense>
  );
}
