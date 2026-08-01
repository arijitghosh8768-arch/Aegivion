import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User { id: string; email: string; name: string; role: string; }

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (user: User, token: string) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set: any) => ({
      user: null as User | null,
      token: null as string | null,
      isAuthenticated: false as boolean,
      login: (user: User, token: string) => {
        if (typeof document !== 'undefined') {
          document.cookie = `auth-token=${token}; path=/; max-age=86400; SameSite=Lax`;
        }
        set({ user, token, isAuthenticated: true });
      },
      logout: () => {
        if (typeof document !== 'undefined') {
          document.cookie = 'auth-token=; path=/; max-age=0';
        }
        set({ user: null, token: null, isAuthenticated: false });
      },
    }),
    { name: 'aegivion-auth' }
  )
);
