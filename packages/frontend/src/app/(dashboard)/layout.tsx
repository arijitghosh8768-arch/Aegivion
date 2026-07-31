import { Sidebar } from "@/components/layout/sidebar";
import { TopNav } from "@/components/layout/top-nav";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen bg-[#0F172A]">
      <Sidebar />
      <div className="flex-1 pl-64 transition-all duration-300">
        <TopNav />
        <main className="p-6">{children}</main>
      </div>
    </div>
  );
}
