import React from "react"

export function DashboardSkeleton() {
  return (
    <div className="space-y-6 animate-pulse p-6">
      {/* Widget Skeletons */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-[#1E293B] border border-slate-700 rounded-lg p-5">
            <div className="h-4 w-24 bg-[#0F172A] rounded mb-3"></div>
            <div className="h-8 w-16 bg-[#0F172A] rounded"></div>
          </div>
        ))}
      </div>
      
      {/* Chart & Table Skeletons */}
      <div className="grid gap-6 md:grid-cols-2">
        <div className="bg-[#1E293B] border border-slate-700 rounded-lg p-6">
          <div className="h-6 w-40 bg-[#0F172A] rounded mb-4"></div>
          <div className="h-64 w-full bg-[#0F172A] rounded"></div>
        </div>
      </div>
    </div>
  )
}
