"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { NotificationItem, ProviderId } from "@/lib/types";
import { INITIAL_NOTIFICATIONS } from "@/lib/data/notifications";

/* Resolved once persisted session state has been rehydrated from localStorage.
   The auth gate must wait for this, otherwise a refresh redirects to /login
   before the saved user is restored. */

export type AccentColor = "purple" | "blue" | "emerald" | "indigo";
export type CornerRadius = "compact" | "default" | "large";

export interface AppUser {
  name: string;
  email: string;
  role: string;
  company: string;
  username: string;
  avatar: string; // data URL or empty
  phone: string;
  jobRole: string;
  department: string;
  country: string;
  timezone: string;
  language: string;
}

export interface OrgSettings {
  workspaceName: string;
  companyName: string;
  logo: string;
  primaryCloud: ProviderId;
  region: string;
  securityPolicy: string;
  requireExceptionApproval: boolean;
  autoSuppressNonProd: boolean;
}

export interface NotifPrefs {
  emailAlerts: boolean;
  criticalFindings: boolean;
  dailySummary: boolean;
  weeklyReport: boolean;
  cloudConnectionAlerts: boolean;
  aiRecommendations: boolean;
  browserNotifications: boolean;
}

export interface CloudPrefs {
  defaultCloud: ProviderId;
  defaultRegion: string;
  preferredDashboard: string;
  autoRefresh: boolean;
  autoScan: boolean;
}

export interface AppearancePrefs {
  themeMode: "system" | "light" | "dark";
  accent: AccentColor;
  radius: CornerRadius;
  compactMode: boolean;
  animations: boolean;
  reducedMotion: boolean;
  highContrast: boolean;
  largeText: boolean;
}

export const DEFAULT_PROFILE: AppUser = {
  name: "Admin User",
  email: "admin@acme.com",
  role: "Super Admin",
  company: "Acme Corp",
  username: "admin",
  avatar: "",
  phone: "+1 (555) 010-2030",
  jobRole: "Security Architect",
  department: "Platform Security",
  country: "United States",
  timezone: "America/New_York",
  language: "English (US)",
};

export const DEFAULT_ORG: OrgSettings = {
  workspaceName: "Acme Corp — Production",
  companyName: "Acme Corp",
  logo: "",
  primaryCloud: "aws",
  region: "us-east-1",
  securityPolicy: "SOC 2 · PCI DSS · HIPAA",
  requireExceptionApproval: true,
  autoSuppressNonProd: false,
};

export const DEFAULT_NOTIF: NotifPrefs = {
  emailAlerts: true,
  criticalFindings: true,
  dailySummary: true,
  weeklyReport: true,
  cloudConnectionAlerts: true,
  aiRecommendations: false,
  browserNotifications: true,
};

export const DEFAULT_CLOUD: CloudPrefs = {
  defaultCloud: "aws",
  defaultRegion: "us-east-1 (N. Virginia)",
  preferredDashboard: "Command Center",
  autoRefresh: true,
  autoScan: true,
};

export const DEFAULT_APPEARANCE: AppearancePrefs = {
  themeMode: "system",
  accent: "purple",
  radius: "default",
  compactMode: false,
  animations: true,
  reducedMotion: false,
  highContrast: false,
  largeText: false,
};

interface AppState {
  user: AppUser | null;
  login: (user: Partial<AppUser>) => void;
  logout: () => void;
  updateUser: (patch: Partial<AppUser>) => void;
  workspaceId: string;
  workspaces: { id: string; name: string; plan: string; region: string }[];
  setWorkspace: (id: string) => void;
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  commandOpen: boolean;
  setCommandOpen: (open: boolean) => void;
  notifications: NotificationItem[];
  pushNotification: (n: NotificationItem) => void;
  markAllRead: () => void;
  markRead: (id: string) => void;
  hydrated: boolean;
  unreadCount: number;
  connectedClouds: ProviderId[];
  connectCloud: (p: ProviderId) => void;
  disconnectCloud: (p: ProviderId) => void;
  disconnectAllClouds: () => void;
  org: OrgSettings;
  setOrg: (patch: Partial<OrgSettings>) => void;
  fetchOrgSettings: (orgId: string) => Promise<void>;
  notifPrefs: NotifPrefs;
  setNotifPrefs: (patch: Partial<NotifPrefs>) => void;
  cloudPrefs: CloudPrefs;
  setCloudPrefs: (patch: Partial<CloudPrefs>) => void;
  appearance: AppearancePrefs;
  setAppearance: (patch: Partial<AppearancePrefs>) => void;
}

export const useAppStore = create<AppState>()(
  persist(
    (set, get) => ({
      user: null,
      login: (user) => set({ user: { ...DEFAULT_PROFILE, ...user } }),
      logout: () => set({ user: null }),
      updateUser: (patch) => {
        const current = get().user ?? DEFAULT_PROFILE;
        set({ user: { ...current, ...patch } });
      },
      workspaceId: "ws-1",
      workspaces: [
        { id: "ws-1", name: "Acme Corp — Production", plan: "Enterprise", region: "Global" },
        { id: "ws-2", name: "Acme Corp — Staging", plan: "Pro", region: "US-East" },
        { id: "ws-3", name: "Acme Labs", plan: "Free", region: "EU-West" },
      ],
      setWorkspace: (workspaceId) => set({ workspaceId }),
      sidebarCollapsed: false,
      toggleSidebar: () => set({ sidebarCollapsed: !get().sidebarCollapsed }),
      commandOpen: false,
      setCommandOpen: (commandOpen) => set({ commandOpen }),
      notifications: INITIAL_NOTIFICATIONS,
      pushNotification: (n) => {
        const notifications = [n, ...get().notifications].slice(0, 40);
        set({ notifications, unreadCount: notifications.filter((x) => !x.read).length });
      },
      markAllRead: () => {
        const notifications = get().notifications.map((n) => ({ ...n, read: true }));
        set({ notifications, unreadCount: 0 });
      },
      markRead: (id) => {
        const notifications = get().notifications.map((n) => (n.id === id ? { ...n, read: true } : n));
        set({ notifications, unreadCount: notifications.filter((x) => !x.read).length });
      },
      hydrated: false,
      unreadCount: INITIAL_NOTIFICATIONS.filter((n) => !n.read).length,
      connectedClouds: ["aws", "azure", "gcp"],
      connectCloud: (p) =>
        set((s) => (s.connectedClouds.includes(p) ? s : { connectedClouds: [...s.connectedClouds, p] })),
      disconnectCloud: (p) =>
        set((s) => ({ connectedClouds: s.connectedClouds.filter((x) => x !== p) })),
      disconnectAllClouds: () => set({ connectedClouds: [] }),
      org: DEFAULT_ORG,
      setOrg: (patch) => set((s) => ({ org: { ...s.org, ...patch } })),
      fetchOrgSettings: async (orgId) => {
        try {
          const baseUrl = process.env.NEXT_PUBLIC_API_URL || "https://aegivion.onrender.com";
          const res = await fetch(`${baseUrl}/api/v1/orgs/${orgId}/settings`);
          if (res.ok) {
            const json = await res.json();
            if (json.success && json.data) {
              set((s) => ({
                org: {
                  ...s.org,
                  requireExceptionApproval: json.data.security_policy?.require_exception_approval ?? s.org.requireExceptionApproval,
                  autoSuppressNonProd: json.data.security_policy?.auto_suppress_non_prod ?? s.org.autoSuppressNonProd,
                },
                connectedClouds: json.data.enabled_cloud_providers || ["aws"],
              }));
            }
          }
        } catch (e) {
          console.error("Failed to fetch org settings", e);
        }
      },
      notifPrefs: DEFAULT_NOTIF,
      setNotifPrefs: (patch) => set((s) => ({ notifPrefs: { ...s.notifPrefs, ...patch } })),
      cloudPrefs: DEFAULT_CLOUD,
      setCloudPrefs: (patch) => set((s) => ({ cloudPrefs: { ...s.cloudPrefs, ...patch } })),
      appearance: DEFAULT_APPEARANCE,
      setAppearance: (patch) => set((s) => ({ appearance: { ...s.appearance, ...patch } })),
    }),
    {
      name: "aegivion-store",
      partialize: (s) => ({
        user: s.user,
        workspaceId: s.workspaceId,
        sidebarCollapsed: s.sidebarCollapsed,
        connectedClouds: s.connectedClouds,
        org: s.org,
        notifPrefs: s.notifPrefs,
        cloudPrefs: s.cloudPrefs,
        appearance: s.appearance,
      }),
      onRehydrateStorage: () => () => {
        useAppStore.setState({ hydrated: true });
      },
    }
  )
);
