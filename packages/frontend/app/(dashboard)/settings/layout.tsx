import { Shield, User, Building, Users, Key, Bell, List } from "lucide-react";
import Link from "next/link";

const navItems = [
  { name: "Profile", href: "/settings", icon: User },
  { name: "Organization", href: "/settings/organization", icon: Building },
  { name: "Users & Roles", href: "/settings/users", icon: Users },
  { name: "Cloud Accounts", href: "/settings/cloud-accounts", icon: Key },
  { name: "Notifications", href: "/settings/notifications", icon: Bell },
  { name: "Audit Log", href: "/settings/audit", icon: List },
  { name: "AI Settings", href: "/settings/ai", icon: Shield },
];

export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col md:flex-row gap-8">
      <aside className="w-full md:w-64 shrink-0">
        <h2 className="text-xl font-bold mb-4">Settings</h2>
        <nav className="flex flex-col space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className="flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
              >
                <Icon className="h-4 w-4" />
                {item.name}
              </Link>
            );
          })}
        </nav>
      </aside>
      <main className="flex-1 min-w-0">
        {children}
      </main>
    </div>
  );
}
