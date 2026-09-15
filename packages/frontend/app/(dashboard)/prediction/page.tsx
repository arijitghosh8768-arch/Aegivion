"use client";

import { useMemo } from "react";
import { motion } from "framer-motion";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { TrendingUp, CalendarClock, AlertTriangle, Sparkles, LineChart } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { PageHeader } from "@/components/shared/page-header";
import { ChartTooltip } from "@/components/shared/chart-tooltip";
import { ScoreRing } from "@/components/shared/score-ring";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { fetchApi } from "@/lib/api-client";
import { cn } from "@/lib/utils";

const axisStyle = { fontSize: 10.5, fill: "var(--muted-foreground)" };

export default function PredictionPage() {
  const { data: riskData, isLoading, isError } = useQuery<any>({
    queryKey: ["risk-intelligence"],
    queryFn: () => fetchApi<any>("/v1/risk/intelligence"),
  });

  // Chart data: prefer riskData.trend, fall back to empty
  const chartData = useMemo(() => {
    if (!riskData) return [];
    if (Array.isArray(riskData.trend)) return riskData.trend;
    if (Array.isArray(riskData.forecast)) return riskData.forecast;
    return [];
  }, [riskData]);

  // Risk factors list
  const riskFactors: Array<{ factor: string; weight: number; trend: string }> = useMemo(() => {
    if (!riskData) return [];
    if (Array.isArray(riskData.risk_factors)) return riskData.risk_factors;
    if (Array.isArray(riskData.factors)) return riskData.factors;
    return [];
  }, [riskData]);

  // Likelihood score (0-100)
  const likelihood: number = riskData?.likelihood ?? riskData?.risk_score ?? riskData?.score ?? 0;

  // Peak label from API or generic
  const peakLabel: string = riskData?.peak_label ?? riskData?.peak ?? null;

  const isEmpty = !isLoading && !isError && !riskData;

  return (
    <div>
      <PageHeader
        title="Prediction"
        description="ML-driven forecasts of attack probability across your estate for the next 14 days."
      >
        <Button variant="outline">
          <CalendarClock className="h-4 w-4" /> 72h forecast
        </Button>
        <Button variant="gradient">
          <Sparkles className="h-4 w-4" /> Explain predictions
        </Button>
      </PageHeader>

      {isLoading && (
        <div className="flex h-64 items-center justify-center text-sm text-muted-foreground">
          Loading prediction data…
        </div>
      )}

      {isError && (
        <div className="flex h-64 items-center justify-center text-sm text-destructive">
          Failed to load prediction data. Please try again.
        </div>
      )}

      {isEmpty && (
        <div className="flex h-64 flex-col items-center justify-center gap-3 rounded-2xl border border-dashed border-border bg-card text-center">
          <LineChart className="h-8 w-8 text-muted-foreground/50" />
          <p className="text-sm text-muted-foreground">
            No prediction data yet. Connect a cloud account and run a scan to generate ML forecasts.
          </p>
        </div>
      )}

      {!isLoading && !isError && riskData && (
        <>
          <div className="grid gap-5 xl:grid-cols-3">
            {/* forecast chart */}
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-2xl border border-border bg-card p-5 shadow-soft xl:col-span-2"
            >
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h3 className="flex items-center gap-2 text-[14px] font-semibold">
                    <TrendingUp className="h-4 w-4 text-primary" /> Attack probability forecast
                  </h3>
                  <p className="text-[11.5px] text-muted-foreground">Next 14 days · confidence band shown</p>
                </div>
                {peakLabel && (
                  <Badge variant="warning">
                    <AlertTriangle className="h-3 w-3" /> Peak: {peakLabel}
                  </Badge>
                )}
              </div>
              {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <AreaChart data={chartData} margin={{ top: 6, right: 8, left: -14, bottom: 0 }}>
                    <defs>
                      <linearGradient id="forecast-grad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#f59e0b" stopOpacity={0.4} />
                        <stop offset="100%" stopColor="#f59e0b" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="band-grad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#6d5df6" stopOpacity={0.25} />
                        <stop offset="100%" stopColor="#6d5df6" stopOpacity={0.04} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 6" stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="day" tick={axisStyle} axisLine={false} tickLine={false} interval={1} />
                    <YAxis tick={axisStyle} axisLine={false} tickLine={false} domain={[0, 100]} unit="%" />
                    <Tooltip content={<ChartTooltip />} />
                    <Area type="monotone" dataKey="high" name="Upper bound" stroke="none" fill="url(#band-grad)" />
                    <Area type="monotone" dataKey="low" name="Lower bound" stroke="none" fill="url(#band-grad)" />
                    <Area
                      type="monotone"
                      dataKey="probability"
                      name="Probability"
                      stroke="#f59e0b"
                      strokeWidth={2.4}
                      fill="url(#forecast-grad)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-[280px] items-center justify-center text-sm text-muted-foreground">
                  No forecast trend data available.
                </div>
              )}
            </motion.div>

            {/* right column */}
            <motion.div
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="space-y-5"
            >
              <div className="rounded-2xl border border-border bg-card p-5 shadow-soft">
                <h3 className="text-[14px] font-semibold">Next-72h likelihood</h3>
                <p className="mb-4 text-[11.5px] text-muted-foreground">
                  {riskData?.attack_type ?? riskData?.category ?? "Attack probability"}
                </p>
                <div className="flex items-center justify-center">
                  <ScoreRing
                    value={likelihood}
                    size={150}
                    label="likelihood"
                    sublabel={`${likelihood}% · ${likelihood >= 70 ? "critical" : likelihood >= 40 ? "elevated" : "low"}`}
                    color="#f59e0b"
                  />
                </div>
                {riskFactors.length > 0 && (
                  <div className="mt-4 space-y-2">
                    {riskFactors.slice(0, 3).map((f) => (
                      <div key={f.factor} className="flex items-center justify-between text-[11.5px]">
                        <span className="text-muted-foreground">{f.factor}</span>
                        <span
                          className={cn(
                            "font-bold tabular-nums",
                            f.trend?.startsWith("+") ? "text-destructive" : "text-success",
                          )}
                        >
                          {Math.round((f.weight ?? 0) * 100)}% {f.trend}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {riskData?.highest_risk_window && (
                <div className="rounded-2xl border border-warning/25 bg-warning/5 p-5">
                  <h3 className="flex items-center gap-2 text-[14px] font-semibold">
                    <AlertTriangle className="h-4 w-4 text-warning" /> Highest-risk window
                  </h3>
                  <p className="mt-2 text-[12px] leading-relaxed text-muted-foreground">
                    {riskData.highest_risk_window}
                  </p>
                  <div className="mt-3 flex gap-2">
                    <Button size="sm" variant="gradient">Schedule guard duty</Button>
                    <Button size="sm" variant="outline">Review model factors</Button>
                  </div>
                </div>
              )}
            </motion.div>
          </div>
        </>
      )}
    </div>
  );
}

function heatColor(v: number): string {
  if (v < 0.2) return "rgba(34,197,94,0.18)";
  if (v < 0.4) return "rgba(34,197,94,0.42)";
  if (v < 0.55) return "rgba(245,158,11,0.5)";
  if (v < 0.7) return "rgba(245,158,11,0.72)";
  if (v < 0.85) return "rgba(239,68,68,0.72)";
  return "rgba(239,68,68,0.92)";
}
