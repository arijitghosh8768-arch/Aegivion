"use client"

import * as React from "react"
import { ShieldAlert, ArrowUpDown, MoreHorizontal, Filter } from "lucide-react"

export type Finding = {
  id: string
  title: string
  severity: "critical" | "high" | "medium" | "low"
  asset: string
  provider: "AWS" | "Azure" | "GCP"
  status: "open" | "in_progress" | "resolved"
  discoveredAt: string
}

const data: Finding[] = [
  { id: "f-1", title: "S3 Bucket Public Access", severity: "critical", asset: "prod-data-bucket", provider: "AWS", status: "open", discoveredAt: "2026-07-30" },
  { id: "f-2", title: "IAM User Without MFA", severity: "high", asset: "admin-user-01", provider: "AWS", status: "in_progress", discoveredAt: "2026-07-29" },
  { id: "f-3", title: "Unencrypted RDS Instance", severity: "medium", asset: "db-analytics", provider: "AWS", status: "open", discoveredAt: "2026-07-28" },
  { id: "f-4", title: "Security Group Allows SSH from 0.0.0.0/0", severity: "critical", asset: "sg-web-tier", provider: "AWS", status: "open", discoveredAt: "2026-07-31" },
]

export function FindingsTable() {
  const [filterText, setFilterText] = React.useState("")

  const filteredData = data.filter(item => 
    item.title.toLowerCase().includes(filterText.toLowerCase())
  )

  return (
    <div className="bg-[#1E293B] border border-slate-700 rounded-lg p-6">
      <div className="flex flex-row items-center justify-between mb-6">
        <div>
          <h2 className="flex items-center gap-2 text-xl font-bold text-white">
            <ShieldAlert className="h-5 w-5 text-red-500" /> Security Findings
          </h2>
          <p className="text-sm text-slate-400 mt-1">Manage and remediate identified vulnerabilities.</p>
        </div>
        <div className="flex items-center gap-2">
          <button className="px-3 py-1.5 bg-[#0F172A] border border-slate-700 rounded hover:bg-slate-800 text-xs font-semibold text-slate-300">Export CSV</button>
        </div>
      </div>

      <div className="flex items-center py-4">
        <input
          placeholder="Filter findings by title..."
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="max-w-sm bg-[#0F172A] border border-slate-700 text-slate-100 rounded px-3 py-1.5 text-xs focus:outline-none"
        />
      </div>

      <div className="overflow-x-auto rounded-lg border border-slate-700">
        <table className="min-w-full divide-y divide-slate-700 bg-[#0F172A]/50">
          <thead className="bg-[#0F172A]">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Finding Title</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Affected Asset</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Provider</th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700">
            {filteredData.map((row) => (
              <tr key={row.id} className="hover:bg-slate-800/40">
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${
                    row.severity === 'critical' ? 'bg-red-500/10 text-red-500 border border-red-500/20' :
                    row.severity === 'high' ? 'bg-orange-500/10 text-orange-500 border border-orange-500/20' :
                    'bg-yellow-500/10 text-yellow-500 border border-yellow-500/20'
                  }`}>
                    {row.severity}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-100 font-medium">{row.title}</td>
                <td className="px-6 py-4 whitespace-nowrap"><code className="text-xs bg-slate-800 px-1.5 py-0.5 rounded text-slate-300">{row.asset}</code></td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-350">{row.provider}</td>
                <td className="px-6 py-4 whitespace-nowrap capitalize text-sm text-slate-400">{row.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
