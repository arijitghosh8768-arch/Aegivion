import { DashboardWidgets } from "@/components/dashboard/widgets";
import { FindingsChart } from "@/components/charts/findings-chart";

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight text-white">Security Overview</h1>
        <p className="text-slate-400">Real-time visibility into your cloud security posture.</p>
      </div>

      <DashboardWidgets />

      <div className="grid gap-6 md:grid-cols-2">
        <div className="bg-[#1E293B] p-6 rounded-lg border border-slate-700">
          <FindingsChart />
        </div>
      </div>
    </div>
  );
}
