export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: 'admin' | 'analyst' | 'viewer';
  organization_id: string;
  status: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  subscription_plan: 'free' | 'pro' | 'business' | 'enterprise';
}

export interface AuthState {
  user: User | null;
  organization: Organization | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}
