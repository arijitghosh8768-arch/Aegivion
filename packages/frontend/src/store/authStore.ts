import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { User, Organization, AuthState } from '../types';

interface RegisterData {
  email: string;
  first_name: string;
  last_name: string;
  password?: string;
  organization_name?: string;
}

interface AuthStore extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  register: (userData: RegisterData) => Promise<void>;
  logout: () => void;
  refreshTokenAction: () => Promise<void>;
  setUser: (user: User) => void;
  setOrganization: (org: Organization) => void;
  clearError: () => void;
}

export const useAuthStore = create<AuthStore>()(
  persist(
    (set, get) => ({
      user: null,
      organization: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      login: async (email: string, password: str) => {
        set({ isLoading: true, error: null });
        try {
          // Mock login API fetch. In production, replace with: await fetch('/auth/login')
          await new Promise((resolve) => setTimeout(resolve, 800));
          
          const mockUser: User = {
            id: "u-1234",
            email: email,
            first_name: "John",
            last_name: "Doe",
            role: "admin",
            organization_id: "org-5678",
            status: "active"
          };
          
          const mockOrg: Organization = {
            id: "org-5678",
            name: "Aegivion Demo Corp",
            slug: "aegivion-demo",
            subscription_plan: "free"
          };

          set({
            user: mockUser,
            organization: mockOrg,
            accessToken: "mock-access-token-jwt-here",
            refreshToken: "mock-refresh-token-jwt-here",
            isAuthenticated: true,
            isLoading: false,
          });
        } catch (error: any) {
          set({ 
            error: error.message || 'Login failed',
            isLoading: false,
            isAuthenticated: false,
          });
          throw error;
        }
      },

      register: async (userData: RegisterData) => {
        set({ isLoading: true, error: null });
        try {
          // Mock register API fetch
          await new Promise((resolve) => setTimeout(resolve, 800));
          
          const mockUser: User = {
            id: "u-1234",
            email: userData.email,
            first_name: userData.first_name,
            last_name: userData.last_name,
            role: "admin",
            organization_id: "org-5678",
            status: "active"
          };

          set({
            user: mockUser,
            accessToken: "mock-access-token-jwt-here",
            refreshToken: "mock-refresh-token-jwt-here",
            isAuthenticated: true,
            isLoading: false,
          });
        } catch (error: any) {
          set({ 
            error: error.message || 'Registration failed',
            isLoading: false,
          });
          throw error;
        }
      },

      logout: () => {
        set({
          user: null,
          organization: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
          isLoading: false,
          error: null,
        });
      },

      refreshTokenAction: async () => {
        const { refreshToken } = get();
        if (!refreshToken) {
          get().logout();
          return;
        }
        try {
          // Mock refresh token request
          set({ accessToken: "new-mock-access-token-jwt-here" });
        } catch (error) {
          get().logout();
        }
      },

      setUser: (user: User) => set({ user }),
      setOrganization: (organization: Organization) => set({ organization }),
      clearError: () => set({ error: null }),
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        organization: state.organization,
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);
