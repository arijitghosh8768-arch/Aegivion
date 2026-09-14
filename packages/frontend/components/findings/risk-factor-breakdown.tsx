"use client";

import { Bar, BarChart, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, Cell } from "recharts";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

interface RiskFactor {
  name: string;
  value: number;
  max: number;
  description: string;
}

interface RiskFactorBreakdownProps {
  factors: RiskFactor[];
  totalScore: number;
}

export function RiskFactorBreakdown({ factors, totalScore }: RiskFactorBreakdownProps) {
  if (!factors || factors.length === 0) return null;
  
  const chartData = factors.map(f => ({
    name: f.name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
    value: f.value,
    max: f.max,
    description: f.description,
    fill: f.value > (f.max * 0.7) ? "hsl(var(--destructive))" : 
          f.value > (f.max * 0.4) ? "hsl(var(--warning, 38 92% 50%))" : 
          "hsl(var(--muted-foreground))"
  })).sort((a, b) => b.value - a.value);

  return (
    <Card className="shadow-none border-dashed bg-muted/20">
      <CardHeader className="py-4">
        <CardTitle className="text-sm font-medium">Risk Score Breakdown (v2.1)</CardTitle>
        <CardDescription className="text-xs">
          Total Score: {totalScore}/100. Factors driving this score.
        </CardDescription>
      </CardHeader>
      <CardContent className="py-0 pb-4 h-[200px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
            <XAxis type="number" domain={[0, 'dataMax']} hide />
            <YAxis dataKey="name" type="category" tick={{ fontSize: 10 }} width={100} />
            <RechartsTooltip 
              formatter={(value: number, name: string, props: any) => [`${value} / ${props.payload.max}`, 'Score']}
              labelFormatter={(label) => label}
              contentStyle={{ borderRadius: '8px', border: '1px solid hsl(var(--border))', fontSize: '12px' }}
            />
            <Bar dataKey="value" radius={[0, 4, 4, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
