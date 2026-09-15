"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useGoogleLogin } from "@react-oauth/google";
import { Eye, EyeOff, Loader2, ArrowLeft, Shield, CheckCircle2, AlertCircle, Info } from "lucide-react";
import { useAppStore } from "@/lib/store";

export default function LoginPage() {
  const router = useRouter();
  const login = useAppStore((s) => s.login);
  
  const [currentRole, setCurrentRole] = useState<'super' | 'org' | 'employee'>('org');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState("admin@aegivion.com");
  const [password, setPassword] = useState("password123");
  const [remember, setRemember] = useState(true);
  
  const [alertType, setAlertType] = useState<'error' | 'success' | 'info' | null>(null);
  const [alertMsg, setAlertMsg] = useState("");

  const showAlert = (type: 'error' | 'success' | 'info', msg: string) => {
    setAlertType(type);
    setAlertMsg(msg);
    if (type !== 'error') {
      setTimeout(() => setAlertType(null), 4000);
    }
  };

  const doGoogleLogin = useGoogleLogin({
    onSuccess: async (tokenResponse) => {
      setLoading(true);
      showAlert("info", "Google identity verified · Checking allowlist...");
      try {
        const res = await fetch((process.env.NEXT_PUBLIC_API_URL || "https://aegivion.onrender.com") + "/api/v1/auth/google", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ access_token: tokenResponse.access_token }),
        });

        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail || "Authentication failed");
        }

        const data = await res.json();
        
        login({
          name: data.user.name || "Employee",
          email: data.user.email,
          role: data.user.role,
          company: data.user.organization_id,
        });
        
        localStorage.setItem("aegivion_token", data.token);
        
        showAlert("success", "Allowlist check passed · Loading workspace...");
        setTimeout(() => {
          router.push(data.user.role === "superadmin" || data.user.role === "Super Admin" ? "/admin" : "/");
        }, 1000);
      } catch (err: any) {
        showAlert("error", err.message || "Failed to authenticate with Google.");
        setLoading(false);
      }
    },
    onError: (err) => {
      console.error("Google Login Error:", err);
      setLoading(false);
      showAlert("error", "Google authentication failed or was cancelled.");
    }
  });

  const doLogin = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setAlertType(null);
    if (!email) {
      showAlert('error', 'Please enter your email address');
      return;
    }
    if (!password) {
      showAlert('error', 'Please enter your password');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch((process.env.NEXT_PUBLIC_API_URL || "https://aegivion.onrender.com") + "/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || "Invalid credentials");
      }

      const data = await res.json();
      
      login({
        name: data.user.name || "Admin User",
        email: data.user.email,
        role: data.user.role,
        company: data.user.organization_id,
      });
      
      localStorage.setItem("aegivion_token", data.token);
      showAlert('success', `Signed in successfully · Redirecting to dashboard...`);

      setTimeout(() => {
        router.push(data.user.role === "superadmin" || data.user.role === "Super Admin" ? "/admin" : "/");
      }, 1000);
    } catch (err: any) {
      showAlert('error', err.message || "Failed to log in.");
      setLoading(false);
    }
  };

  const handleRoleChange = (role: 'super' | 'org' | 'employee') => {
    setCurrentRole(role);
    setAlertType(null);
    if (role === 'super') {
      setEmail('superadmin@aegivion.com');
    } else if (role === 'org') {
      setEmail('admin@aegivion.com');
    } else {
      setEmail('');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 p-5 font-sans">
      <div className="w-full max-w-[480px] bg-white rounded-2xl p-10 shadow-[0_10px_40px_rgba(0,0,0,0.08)] relative">
        <Link href="/" className="absolute top-6 right-6 flex items-center gap-1.5 text-[13px] text-slate-500 hover:text-indigo-500 transition-colors">
          <ArrowLeft className="w-3.5 h-3.5" /> Back to app
        </Link>

        <div className="text-center mb-7">
          <div className="w-14 h-14 bg-gradient-to-br from-indigo-500 to-purple-400 rounded-2xl flex items-center justify-center mx-auto mb-5 shadow-[0_8px_24px_rgba(99,102,241,0.25)]">
            <Shield className="w-7 h-7 text-white" strokeWidth={2.5} />
          </div>
          <h2 className="text-[26px] font-bold tracking-tight mb-1.5 text-slate-900">
            {currentRole === 'super' ? 'Super Admin Portal' : currentRole === 'org' ? 'Welcome back' : 'Employee Sign In'}
          </h2>
          <p className="text-sm text-slate-500">
            {currentRole === 'super' ? 'Manage organizations & global settings' : currentRole === 'org' ? 'Sign in to your security workspace' : 'Access your organization workspace via SSO'}
          </p>
        </div>

        {/* Role Tabs */}
        <div className="flex gap-1.5 p-1 bg-slate-100 rounded-xl mb-6">
          <button onClick={() => handleRoleChange('super')} className={`flex-1 py-2.5 px-2 rounded-lg text-[13px] font-semibold flex items-center justify-center gap-1.5 transition-all ${currentRole === 'super' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500 hover:text-slate-900'}`}>
            <span className="w-2 h-2 rounded-full bg-red-600"></span>Super Admin
          </button>
          <button onClick={() => handleRoleChange('org')} className={`flex-1 py-2.5 px-2 rounded-lg text-[13px] font-semibold flex items-center justify-center gap-1.5 transition-all ${currentRole === 'org' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500 hover:text-slate-900'}`}>
            <span className="w-2 h-2 rounded-full bg-amber-500"></span>Org Admin
          </button>
          <button onClick={() => handleRoleChange('employee')} className={`flex-1 py-2.5 px-2 rounded-lg text-[13px] font-semibold flex items-center justify-center gap-1.5 transition-all ${currentRole === 'employee' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500 hover:text-slate-900'}`}>
            <span className="w-2 h-2 rounded-full bg-blue-600"></span>Employee
          </button>
        </div>

        {/* Alert */}
        {alertType && (
          <div className={`p-2.5 px-3.5 rounded-lg text-[13px] mb-4 flex items-center gap-2 animate-in slide-in-from-top-2 ${
            alertType === 'error' ? 'bg-red-50 text-red-500 border border-red-200' :
            alertType === 'success' ? 'bg-green-50 text-green-500 border border-green-200' :
            'bg-blue-50 text-blue-500 border border-blue-200'
          }`}>
            {alertType === 'error' && <AlertCircle className="w-4 h-4 shrink-0" />}
            {alertType === 'success' && <CheckCircle2 className="w-4 h-4 shrink-0" />}
            {alertType === 'info' && <Info className="w-4 h-4 shrink-0" />}
            <span>{alertMsg}</span>
          </div>
        )}

        {/* Password Form (Admins) */}
        {currentRole !== 'employee' && (
          <form onSubmit={doLogin}>
            <div className="mb-4.5 space-y-1.5">
              <div className="flex justify-between items-center text-[13px] font-semibold text-slate-900">
                <label>{currentRole === 'super' ? 'Admin ID' : 'Work email'}</label>
                <button type="button" onClick={() => showAlert('info', 'Password reset link sent')} className="text-indigo-500 text-xs font-medium hover:underline">Forgot password?</button>
              </div>
              <input 
                type="email" 
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={`w-full p-3 border rounded-lg text-sm outline-none transition-all ${alertType === 'error' && !email ? 'border-red-500 focus:ring-4 focus:ring-red-500/10' : 'border-slate-200 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-500/10'}`}
                placeholder={currentRole === 'super' ? "superadmin@aegivion.com" : "admin@aegivion.com"}
              />
            </div>

            <div className="mb-4.5 mt-4 space-y-1.5">
              <div className="flex justify-between items-center text-[13px] font-semibold text-slate-900">
                <label>Password</label>
              </div>
              <div className="relative">
                <input 
                  type={showPw ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={`w-full p-3 pr-10 border rounded-lg text-sm outline-none transition-all ${alertType === 'error' && !password ? 'border-red-500 focus:ring-4 focus:ring-red-500/10' : 'border-slate-200 focus:border-indigo-500 focus:ring-4 focus:ring-indigo-500/10'}`}
                  placeholder="Enter your password"
                />
                <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2 mb-5 mt-4 cursor-pointer" onClick={() => setRemember(!remember)}>
              <div className={`w-4 h-4 border-2 rounded flex items-center justify-center transition-colors ${remember ? 'bg-indigo-500 border-indigo-500' : 'border-slate-300'}`}>
                {remember && <svg className="w-2.5 h-2.5 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>}
              </div>
              <span className="text-[13px] text-slate-500 select-none">Remember me for 30 days</span>
            </div>

            <button type="submit" disabled={loading} className="w-full p-3.5 bg-gradient-to-br from-indigo-500 to-purple-400 text-white rounded-xl text-sm font-semibold hover:-translate-y-px hover:shadow-[0_6px_20px_rgba(99,102,241,0.4)] transition-all flex items-center justify-center gap-2 disabled:opacity-70 disabled:hover:translate-y-0 disabled:hover:shadow-none">
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : (currentRole === 'super' ? 'Sign in as Super Admin' : 'Sign in to Aegivion')}
            </button>
          </form>
        )}

        {/* Employee SSO Form */}
        {currentRole === 'employee' && (
          <div>
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 mb-5">
              <div className="text-xs font-bold uppercase tracking-wide text-slate-500 mb-2.5 flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5" /> How employee login works
              </div>
              <div className="flex flex-col gap-2">
                <div className="flex items-start gap-2.5 text-[13px] text-slate-900 leading-snug">
                  <div className="w-5 h-5 rounded-full bg-indigo-500 text-white flex items-center justify-center text-[11px] font-bold shrink-0 mt-px">1</div>
                  <div>Sign in with your corporate <strong>Google</strong> or <strong>Microsoft</strong> account</div>
                </div>
                <div className="flex items-start gap-2.5 text-[13px] text-slate-900 leading-snug">
                  <div className="w-5 h-5 rounded-full bg-indigo-500 text-white flex items-center justify-center text-[11px] font-bold shrink-0 mt-px">2</div>
                  <div>We verify your email against your organization's <strong>allowlist</strong></div>
                </div>
                <div className="flex items-start gap-2.5 text-[13px] text-slate-900 leading-snug">
                  <div className="w-5 h-5 rounded-full bg-indigo-500 text-white flex items-center justify-center text-[11px] font-bold shrink-0 mt-px">3</div>
                  <div>If approved, you get instant access to your org workspace</div>
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-3 mb-6">
              <button onClick={() => doGoogleLogin()} disabled={loading} className="w-full p-3.5 bg-white border-2 border-slate-200 hover:border-indigo-300 hover:bg-indigo-50/50 rounded-xl text-[15px] font-semibold flex items-center gap-3.5 transition-all text-left group disabled:opacity-70">
                <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center shrink-0">
                  <svg viewBox="0 0 24 24" className="w-[22px] h-[22px]">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                  </svg>
                </div>
                <div className="flex-1">
                  <span className="block text-sm font-semibold text-slate-900">Continue with Google</span>
                  <span className="block text-xs text-slate-500 font-normal mt-0.5">Sign in with your Google Workspace account</span>
                </div>
                {loading ? <Loader2 className="w-5 h-5 animate-spin text-indigo-500" /> : <svg className="w-[18px] h-[18px] text-slate-400 group-hover:text-indigo-500 group-hover:translate-x-1 transition-all" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>}
              </button>

              <button onClick={() => showAlert('info', 'Microsoft SSO is coming soon')} className="w-full p-3.5 bg-white border-2 border-slate-200 hover:border-indigo-300 hover:bg-indigo-50/50 rounded-xl text-[15px] font-semibold flex items-center gap-3.5 transition-all text-left group">
                <div className="w-10 h-10 rounded-lg bg-sky-50 flex items-center justify-center shrink-0">
                  <svg viewBox="0 0 24 24" className="w-[22px] h-[22px]">
                    <rect x="1" y="1" width="10" height="10" fill="#F25022"/>
                    <rect x="13" y="1" width="10" height="10" fill="#7FBA00"/>
                    <rect x="1" y="13" width="10" height="10" fill="#00A4EF"/>
                    <rect x="13" y="13" width="10" height="10" fill="#FFB900"/>
                  </svg>
                </div>
                <div className="flex-1">
                  <span className="block text-sm font-semibold text-slate-900">Continue with Microsoft</span>
                  <span className="block text-xs text-slate-500 font-normal mt-0.5">Sign in with your Microsoft 365 account</span>
                </div>
                <svg className="w-[18px] h-[18px] text-slate-400 group-hover:text-indigo-500 group-hover:translate-x-1 transition-all" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
              </button>
            </div>

            <div className="p-3 bg-amber-50 border border-amber-300 rounded-xl text-xs text-amber-900 flex items-start gap-2.5 leading-relaxed mt-4">
              <Info className="w-4 h-4 shrink-0 mt-px" />
              <span>Access is granted only to emails on your organization's <strong>allowlist</strong>. Contact your Org Admin to be added.</span>
            </div>
          </div>
        )}

        <div className="text-center mt-6 text-[13px] text-slate-500">
          New to Aegivion? <a href="#" onClick={(e) => { e.preventDefault(); showAlert('info', 'Contact your organization admin to get started'); }} className="text-indigo-500 font-semibold hover:underline">Request access</a>
        </div>
      </div>
    </div>
  );
}
