"use client";

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { RISK_TREND, THREAT_TIMELINE, COMPLIANCE_TREND } from "@/lib/data/compliance";
import { ASSET_GROWTH_SERIES as AG } from "@/lib/data/providers";
import { ChartTooltip } from "@/components/shared/chart-tooltip";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const axisStyle = { fontSize: 10.5, fill: "var(--muted-foreground)" };

export function RiskTrendChart({ className }: { className?: string }) {
  return (
    <Card className={cn("card-hover", className)}>
      <CardHeader>
        <CardTitle>Risk Trend</CardTitle>
        <CardDescription>Aggregate exposure score · last 30 days</CardDescription>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={240}>
          <AreaChart data={RISK_TREND} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="risk-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#6d5df6" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#6d5df6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 6" stroke="var(--border)" vertical={false} />
            <XAxis dataKey="day" tick={axisStyle} axisLine={false} tickLine={false} interval={2} />
            <YAxis tick={axisStyle} axisLine={false} tickLine={false} domain={[0, 100]} />
            <Tooltip content={<ChartTooltip />} />
            <Area type="monotone" dataKey="score" name="Risk score" stroke="#6d5df6" strokeWidth={2.2} fill="url(#risk-grad)" />
          </AreaChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

export function ThreatTimelineChart({ className }: { className?: string }) {
  return (
    <Card className={cn("card-hover", className)}>
      <CardHeader>
        <CardTitle>Threat Timeline</CardTitle>
        <CardDescription>Alert severity volume · last 24 hours</CardDescription>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={THREAT_TIMELINE} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 6" stroke="var(--border)" vertical={false} />
            <XAxis dataKey="time" tick={axisStyle} axisLine={false} tickLine={false} interval={2} />
            <YAxis tick={axisStyle} axisLine={false} tickLine={false} />
            <Tooltip content={<ChartTooltip />} cursor={{ fill: "var(--muted)", opacity: 0.4 }} />
            <Bar dataKey="severity" name="Severity" radius={[5, 5, 0, 0]} maxBarSize={22}>
              {THREAT_TIMELINE.map((d, i) => (
                <Cell key={i} fill={d.severity >= 7 ? "#ef4444" : d.severity >= 4 ? "#f59e0b" : "#4f7cf7"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

export function ComplianceTrendChart({ className }: { className?: string }) {
  return (
    <Card className={cn("card-hover", className)}>
      <CardHeader>
        <CardTitle>Compliance Trend</CardTitle>
        <CardDescription>Score by framework · 12 weeks</CardDescription>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={210}>
          <LineChart data={COMPLIANCE_TREND} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 6" stroke="var(--border)" vertical={false} />
            <XAxis dataKey="week" tick={axisStyle} axisLine={false} tickLine={false} interval={3} />
            <YAxis tick={axisStyle} axisLine={false} tickLine={false} domain={[55, 100]} />
            <Tooltip content={<ChartTooltip />} />
            <Line type="monotone" dataKey="soc2" name="SOC 2" stroke="#6d5df6" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="pci" name="PCI DSS" stroke="#c35df5" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="nist" name="NIST" stroke="#0ea5e9" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="cis" name="CIS AWS" stroke="#f59e0b" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}

export function AssetGrowthChart({ className }: { className?: string }) {
  return (
    <Card className={cn("card-hover", className)}>
      <CardHeader>
        <CardTitle>Asset Growth</CardTitle>
        <CardDescription>Discovered assets by provider</CardDescription>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={210}>
          <BarChart data={AG} margin={{ top: 4, right: 4, left: -12, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 6" stroke="var(--border)" vertical={false} />
            <XAxis dataKey="month" tick={axisStyle} axisLine={false} tickLine={false} interval={2} />
            <YAxis tick={axisStyle} axisLine={false} tickLine={false} />
            <Tooltip content={<ChartTooltip />} cursor={{ fill: "var(--muted)", opacity: 0.4 }} />
            <Bar dataKey="aws" name="AWS" stackId="a" fill="#FF9900" radius={[0, 0, 0, 0]} />
            <Bar dataKey="azure" name="Azure" stackId="a" fill="#0078D4" />
            <Bar dataKey="gcp" name="GCP" stackId="a" fill="#4285F4" radius={[5, 5, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
