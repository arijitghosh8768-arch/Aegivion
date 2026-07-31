"use client";

import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";

const data = [
  { date: "Jul 25", Critical: 4, High: 12, Medium: 24, Low: 45 },
  { date: "Jul 26", Critical: 3, High: 15, Medium: 20, Low: 38 },
  { date: "Jul 27", Critical: 5, High: 10, Medium: 28, Low: 50 },
  { date: "Jul 28", Critical: 2, High: 8, Medium: 18, Low: 30 },
  { date: "Jul 29", Critical: 6, High: 14, Medium: 22, Low: 42 },
  { date: "Jul 30", Critical: 4, High: 11, Medium: 26, Low: 48 },
  { date: "Jul 31", Critical: 3, High: 9, Medium: 19, Low: 35 },
];

export function FindingsChart() {
  return (
    <div>
      <h3 className="text-lg font-bold mb-4 text-white">Findings Over Time</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#DC2626" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#DC2626" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#F59E0B" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="date" stroke="#94A3B8" />
            <YAxis stroke="#94A3B8" />
            <Tooltip contentStyle={{ backgroundColor: "#1E293B", border: "1px solid #334155", borderRadius: "8px", color: "#fff" }} />
            <Legend />
            <Area type="monotone" dataKey="Critical" stroke="#DC2626" fillOpacity={1} fill="url(#colorCritical)" />
            <Area type="monotone" dataKey="High" stroke="#F59E0B" fillOpacity={1} fill="url(#colorHigh)" />
            <Area type="monotone" dataKey="Medium" stroke="#2563EB" fillOpacity={0.2} fill="#2563EB" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
