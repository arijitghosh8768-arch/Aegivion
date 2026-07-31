import { Cloud, ShieldAlert, Scale, Bot, TrendingUp, TrendingDown } from "lucide-react";

const widgets = [
  { title: "Total Assets", value: "12,450", icon: Cloud, trend: "+12%", trendUp: true, color: "text-blue-500" },
  { title: "Critical Findings", value: "24", icon: ShieldAlert, trend: "-5%", trendUp: false, color: "text-red-500" },
  { title: "Compliance Score", value: "87%", icon: Scale, trend: "+2%", trendUp: true, color: "text-green-500" },
  { title: "AI Recommendations", value: "156", icon: Bot, trend: "+24", trendUp: true, color: "text-purple-500" },
];

export function DashboardWidgets() {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {widgets.map((widget) => (
        <div key={widget.title} className="bg-[#1E293B] border border-slate-700 rounded-lg p-5">
          <div className="flex flex-row items-center justify-between space-y-0 pb-2">
            <span className="text-sm font-medium text-slate-400">{widget.title}</span>
            <widget.icon className={`h-5 w-5 ${widget.color}`} />
          </div>
          <div className="mt-2">
            <div className="text-2xl font-bold text-white">{widget.value}</div>
            <p className="text-xs text-slate-405 flex items-center mt-1">
              {widget.trendUp ? <TrendingUp className="mr-1 h-3 w-3 text-green-500" /> : <TrendingDown className="mr-1 h-3 w-3 text-red-500" />}
              <span className={widget.trendUp ? "text-green-500" : "text-red-500"}>{widget.trend}</span> from last month
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
