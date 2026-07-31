# Aegivion Next.js 15 Enterprise Blueprint

This blueprint outlines the production-ready Next.js 15 + Tailwind + Recharts frontend codebase structure for the Aegivion platform. 

---

## 📂 Codebase Structure

```text
aegivion-ui/
├── src/
│   ├── app/
│   │   ├── (dashboard)/
│   │   │   ├── layout.tsx
│   │   │   └── page.tsx
│   │   │   ├── ai/
│   │   │   │   └── page.tsx
│   │   │   ├── findings/
│   │   │   └── settings/
│   │   ├── (auth)/
│   │   │   └── login/
│   │   │       └── page.tsx
│   │   ├── globals.css
│   │   └── layout.tsx
│   ├── components/
│   │   ├── layout/
│   │   │   ├── sidebar.tsx
│   │   │   └── top-nav.tsx
│   │   ├── dashboard/
│   │   │   ├── widgets.tsx
│   │   │   └── recent-incidents.tsx
│   │   └── charts/
│   │       └── findings-chart.tsx
│   ├── lib/
│   │   ├── api.ts
│   │   └── utils.ts
│   └── store/
│       ├── auth-store.ts
│       └── ui-store.ts
├── tailwind.config.ts
└── package.json
```

---

## 📦 Step 1: Dependencies & Configuration

Run the following commands to initialize the Next.js workspace:
```bash
npx create-next-app@latest aegivion-ui --typescript --tailwind --eslint --app --src-dir --import-alias "@/*"
cd aegivion-ui
npm install zustand axios @tanstack/react-query react-hook-form @hookform/resolvers zod recharts sonner next-themes lucide-react
npx shadcn@latest init
```

### `tailwind.config.ts` (Design Tokens)
```typescript
import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        brand: {
          primary: "#2563EB",
          success: "#16A34A",
          warning: "#F59E0B",
          danger: "#DC2626",
        },
        surface: {
          background: "#0F172A",
          card: "#1E293B",
          border: "#334155",
        },
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        card: { DEFAULT: "hsl(var(--card))", foreground: "hsl(var(--card-foreground))" },
        primary: { DEFAULT: "hsl(var(--primary))", foreground: "hsl(var(--primary-foreground))" },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};
export default config;
```

### `src/app/globals.css`
```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 0 0% 100%;
    --foreground: 222.2 84% 4.9%;
    --card: 0 0% 100%;
    --card-foreground: 222.2 84% 4.9%;
    --primary: 221.2 83.2% 53.3%;
    --primary-foreground: 210 40% 98%;
    --border: 214.3 31.8% 91.4%;
    --radius: 0.5rem;
  }

  .dark {
    --background: 222.2 84% 4.9%;
    --foreground: 210 40% 98%;
    --card: 217.2 32.6% 17.5%;
    --card-foreground: 210 40% 98%;
    --primary: 221.2 83.2% 53.3%;
    --primary-foreground: 210 40% 98%;
    --border: 217.2 32.6% 17.5%;
  }
}

@layer base {
  * { @apply border-border; }
  body { @apply bg-background text-foreground; }
}
```

---

## 🏗 Step 2: State Management & API

### `src/store/auth-store.ts` (Zustand)
```typescript
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (user: User, token: string) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      login: (user, token) => set({ user, token, isAuthenticated: true }),
      logout: () => set({ user: null, token: null, isAuthenticated: false }),
    }),
    { name: 'aegivion-auth' }
  )
);
```

### `src/lib/api.ts` (Axios)
```typescript
import axios from 'axios';
import { useAuthStore } from '@/store/auth-store';

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api',
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) config.headers.Authorization = `Bearer {token}`;
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().logout();
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);
```

---

## 🧭 Step 3: Enterprise Layout Shell

### `src/components/layout/sidebar.tsx`
```tsx
"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { 
  LayoutDashboard, Cloud, ShieldAlert, FileWarning, 
  Siren, Scale, Bot, FileText, Settings, ChevronLeft 
} from "lucide-react";
import { Button } from "@/components/ui/button";

const menuItems = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Cloud Accounts", href: "/cloud-accounts", icon: Cloud },
  { name: "Assets", href: "/assets", icon: ShieldAlert },
  { name: "Findings", href: "/findings", icon: FileWarning },
  { name: "Incidents", href: "/incidents", icon: Siren },
  { name: "Compliance", href: "/compliance", icon: Scale },
  { name: "AI Assistant", href: "/ai", icon: Bot },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const isCollapsed = false; // Simple toggle wrapper

  return (
    <aside className={cn(
      "fixed left-0 top-0 z-40 h-screen border-r border-surface-border bg-surface-card transition-all duration-300 w-64"
    )}>
      <div className="flex h-16 items-center justify-between border-b border-surface-border px-4">
        <span className="text-xl font-bold text-brand-primary">Aegivion</span>
      </div>

      <nav className="flex flex-col gap-1 p-2">
        {menuItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive 
                  ? "bg-brand-primary/10 text-brand-primary" 
                  : "text-muted-foreground hover:bg-slate-800 hover:text-foreground"
              )}
            >
              <item.icon className="h-5 w-5 flex-shrink-0" />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
```
