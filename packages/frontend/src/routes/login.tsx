import React, { useState, useEffect } from 'react';
import { createRoute, useNavigate } from '@tanstack/react-router';
import { Route as rootRoute } from './__root';
import { useAuthStore } from '@/store/auth-store';
import { api } from '@/lib/api';
import { Shield, KeyRound, Mail, AlertCircle, Loader2 } from 'lucide-react';

export const Route = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: LoginPage,
});

// Tell TypeScript that window.google exists after the GSI script loads
declare global {
  interface Window {
    google?: any;
    google_auth_initialized?: boolean;
  }
}

const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID as string;

function LoginPage() {
  const navigate = useNavigate();
  const loginAction = useAuthStore((state: any) => state.login);
  const isAuthenticated = useAuthStore((state: any) => state.isAuthenticated);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);

  // If already authenticated, redirect to dashboard
  useEffect(() => {
    if (isAuthenticated) {
      navigate({ to: '/' });
    }
  }, [isAuthenticated, navigate]);

  // -------------------------------------------------------------------------
  // Render Google Button on Mount
  // -------------------------------------------------------------------------
  useEffect(() => {
    const initializeGoogle = () => {
      if (!window.google) return;
      if (window.google_auth_initialized) return;
      if (!GOOGLE_CLIENT_ID || GOOGLE_CLIENT_ID.includes('YOUR_GOOGLE_CLIENT_ID')) return;

      window.google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        callback: async (response: { credential: string }) => {
          setError(null);
          setIsGoogleLoading(true);
          try {
            const res = await api.post('/v1/auth/google', {
              id_token: response.credential,
            });
            if (res.data.success) {
              loginAction(res.data.user, res.data.token);
              navigate({ to: '/' });
            } else {
              setError('Google login failed. Please try again.');
            }
          } catch (err: any) {
            setError(
              err.response?.data?.detail ||
                'Google login failed. Please try again.'
            );
          } finally {
            setIsGoogleLoading(false);
          }
        },
      });
      window.google_auth_initialized = true;

      // Render the official Google Sign-In button in the div container
      const buttonDiv = document.getElementById('google-signin-btn');
      if (buttonDiv) {
        window.google.accounts.id.renderButton(buttonDiv, {
          theme: 'outline',
          size: 'large',
          width: buttonDiv.clientWidth || 382,
          logo_alignment: 'center',
        });
      }
    };

    // If Google script has already loaded
    if (window.google) {
      initializeGoogle();
      return;
    } else {
      // Wait for the script to load
      const interval = setInterval(() => {
        if (window.google) {
          initializeGoogle();
          clearInterval(interval);
        }
      }, 500);
      return () => clearInterval(interval);
    }
  }, []);

  // -------------------------------------------------------------------------
  // Email / Password handler
  // -------------------------------------------------------------------------
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const response = await api.post('/v1/auth/login', { email, password });
      if (response.data.success) {
        loginAction(response.data.user, response.data.token);
        navigate({ to: '/' });
      } else {
        setError('Login failed. Please check your credentials.');
      }
    } catch (err: any) {
      setError(
        err.response?.data?.detail ||
          'Unable to connect to security backend. Please try again.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4">
      <div className="w-full max-w-md bg-[#0d1326] border border-gray-800 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        {/* Glassmorphism gradient effects */}
        <div className="absolute -top-10 -left-10 w-40 h-40 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-10 -right-10 w-40 h-40 bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-xl bg-blue-600/10 flex items-center justify-center mb-4 border border-blue-500/30">
            <Shield className="w-6 h-6 text-blue-500 animate-pulse" />
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white">Aegivion Security Center</h1>
          <p className="text-gray-400 text-xs mt-1.5 text-center">
            Sign in to access your cloud security control plane.
          </p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-950/30 border border-red-500/30 rounded-xl flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
            <span className="text-xs text-red-400 font-medium">{error}</span>
          </div>
        )}

        {/* ---- Google Sign-In Button Container ---- */}
        <div className="w-full mb-5 flex justify-center min-h-[44px]">
          {isGoogleLoading ? (
            <div className="w-full flex items-center justify-center gap-3 bg-white text-gray-800 font-semibold py-2.5 rounded-xl text-sm border border-gray-200">
              <Loader2 className="w-4 h-4 animate-spin text-gray-600" aria-hidden="true" />
              <span>Signing in...</span>
            </div>
          ) : (
            <div id="google-signin-btn" className="w-full" />
          )}
        </div>

        {/* ---- Divider ---- */}
        <div className="flex items-center gap-3 mb-5">
          <div className="flex-1 h-px bg-gray-800" />
          <span className="text-[11px] text-gray-500 font-medium">or sign in with email</span>
          <div className="flex-1 h-px bg-gray-800" />
        </div>

        {/* ---- Email / Password Form ---- */}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-gray-400 uppercase tracking-wider block">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-3 w-4 h-4 text-gray-500" aria-hidden="true" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@aegivion.com"
                className="w-full bg-[#0b0f19] border border-gray-800 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-all"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-gray-400 uppercase tracking-wider block">
              Password
            </label>
            <div className="relative">
              <KeyRound className="absolute left-3.5 top-3 w-4 h-4 text-gray-500" aria-hidden="true" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-[#0b0f19] border border-gray-800 rounded-xl pl-10 pr-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500 transition-all"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-600/50 text-white py-2.5 rounded-xl text-sm font-semibold transition-all shadow-lg shadow-blue-500/20 active:scale-[0.98]"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                <span>Authenticating...</span>
              </>
            ) : (
              <span>Sign In</span>
            )}
          </button>
        </form>

        <div className="mt-6 pt-6 border-t border-gray-800/60 text-center">
          <p className="text-[11px] text-gray-500">
            For development, use <code className="text-gray-400 font-mono">admin@aegivion.com</code> with password <code className="text-gray-400 font-mono">Admin123!</code>
          </p>
        </div>
      </div>
    </div>
  );
}
