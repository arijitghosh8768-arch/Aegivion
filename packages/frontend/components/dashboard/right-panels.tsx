"use client";

import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { AnimatePresence, motion } from "framer-motion";
import {
  BrainCircuit,
  ArrowRight,
  TriangleAlert,
  Layers,
  Network,
  Info,
  Send,
  Bot,
  AudioLines,
} from "lucide-react";
import { fetchApi } from "@/lib/api-client";
import { AI_INSIGHT, LIVE_THREATS } from "@/lib/data/dashboard";
import { answer, getSuggestions, type AiResponse } from "@/lib/data/ai";
import { cn } from "@/lib/utils";

/* ------------------------------------------------------------------ */
/* AI Security Insights                                                */
/* ------------------------------------------------------------------ */

export function AiSecurityInsights({ className }: { className?: string }) {
  return (
    <div className={cn("flex flex-col rounded-2xl border border-border bg-card p-4 shadow-soft", className)}>
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-sm font-bold tracking-tight">AI SECURITY INSIGHTS</h3>
          <p className="text-xs text-muted-foreground">Powered by Aegivion AI</p>
        </div>
        <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-brand-gradient">
          <BrainCircuit className="h-4 w-4 text-white" />
        </span>
      </div>

      <p className="mt-3 flex-1 text-[12.5px] leading-relaxed text-foreground/85">
        {AI_INSIGHT.messageBefore}
        <span className="font-semibold text-destructive">{AI_INSIGHT.messageHighlight}</span>
      </p>

      <div className="mt-3">
        <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
          Risk Level
        </div>
        <div className="flex items-center gap-2.5">
          <div className="flex items-end gap-[3px]">
            {Array.from({ length: AI_INSIGHT.totalBars }).map((_, i) => (
              <span
                key={i}
                className={cn(
                  "w-2 rounded-full",
                  i < AI_INSIGHT.riskBars ? "bg-destructive" : "bg-muted"
                )}
                style={{ height: 12 + ((i % 3) + 1) * 4 }}
              />
            ))}
          </div>
          <span className="text-[13px] font-bold text-destructive">{AI_INSIGHT.riskLevel}</span>
        </div>
      </div>

      <Link
        href="/detection-engine"
        className="mt-4 inline-flex h-9 items-center justify-center gap-1.5 rounded-full bg-primary text-primary-foreground text-sm font-medium shadow transition-colors hover:bg-primary/90"
      >
        View &amp; Resolve <ArrowRight className="h-4 w-4" />
      </Link>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Live Threat Feed                                                    */
/* ------------------------------------------------------------------ */

const THREAT_META = {
  critical: { icon: TriangleAlert, cls: "bg-destructive/10 text-destructive" },
  layers: { icon: Layers, cls: "bg-warning/12 text-warning" },
  network: { icon: Network, cls: "bg-warning/12 text-warning" },
  info: { icon: Info, cls: "bg-info/12 text-info" },
} as const;

export function LiveThreatFeed({ className }: { className?: string }) {
  const { data: threats = [], isLoading } = useQuery({
    queryKey: ["live-threats"],
    queryFn: async () => {
      const json = await fetchApi<any>("/v1/findings?limit=5");
      return (json.findings || []).slice(0, 4).map((f: any) => {
        let level = "info";
        const sev = f.severity?.toLowerCase();
        if (sev === "critical") level = "critical";
        else if (sev === "high") level = "layers";
        else if (sev === "medium") level = "network";

        return {
          id: f.id,
          level,
          title: f.title,
          scope: `${f.resource_type || "Resource"} • ${(f.cloud_provider || "Cloud").toUpperCase()}`,
          time: "Just now",
        };
      });
    },
    refetchInterval: 10000, // optionally poll
  });

  return (
    <div className={cn("flex flex-col rounded-2xl border border-border bg-card p-4 shadow-soft", className)}>
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold tracking-tight">Live Threat Feed</h3>
        <Link href="/threats" className="text-xs font-semibold text-primary transition hover:underline">
          View All
        </Link>
      </div>
      <p className="mt-0.5 text-xs text-muted-foreground">Real-time security events</p>

      <div className="mt-3 flex flex-1 flex-col justify-between gap-1">
        {isLoading ? (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">Loading...</div>
        ) : threats.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">No recent threats.</div>
        ) : (
          threats.map((t: any, i: number) => {
            const meta = THREAT_META[t.level as keyof typeof THREAT_META] || THREAT_META.info;
            const Icon = meta.icon;
            return (
              <motion.div
                key={t.id}
                initial={{ opacity: 0, x: 10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.05 * i }}
                className="flex items-center gap-3 rounded-xl px-1.5 py-2 transition hover:bg-muted/50"
              >
                <span className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-full", meta.cls)}>
                  <Icon className="h-4 w-4" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[12px] font-semibold">{t.title}</div>
                  <div className="truncate text-[10.5px] text-muted-foreground">{t.scope}</div>
                </div>
                <span className="shrink-0 text-[10.5px] font-medium tabular-nums text-muted-foreground">{t.time}</span>
              </motion.div>
            );
          })
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Ask Aegivion AI chat                                                */
/* ------------------------------------------------------------------ */

interface Msg {
  id: string;
  role: "user" | "ai";
  text: string;
  response?: AiResponse;
  thinking?: boolean;
}

export function AskAegivionAI({ className }: { className?: string }) {
  const [messages, setMessages] = useState<Msg[]>([
    {
      id: "m0",
      role: "ai",
      text: "Hi! I'm Aegivion AI — ask me anything about your cloud security posture.",
    },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  const send = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || busy) return;
    setInput("");
    setBusy(true);
    setMessages((m) => [...m, { id: `u-${Date.now()}`, role: "user", text: trimmed }]);
    setTimeout(() => {
      setMessages((m) => [...m, { id: `a-${Date.now()}`, role: "ai", text: "", thinking: true }]);
      setTimeout(() => {
        const res = answer(trimmed);
        setMessages((m) => m.map((msg) => (msg.thinking ? { ...msg, thinking: false, response: res, text: "" } : msg)));
        setBusy(false);
      }, 700);
    }, 250);
  };

  return (
    <div className={cn("flex flex-col overflow-hidden rounded-2xl border border-border bg-card shadow-soft", className)}>
      <div className="flex items-center gap-2.5 border-b border-border px-4 py-3">
        <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-brand-gradient">
          <Bot className="h-4 w-4 text-white" />
        </span>
        <div className="flex-1">
          <div className="flex items-center gap-1.5 text-[13px] font-bold">
            Ask Aegivion AI
            <span className="flex items-center gap-1 text-[10px] font-semibold text-success">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute h-full w-full animate-ping rounded-full bg-success opacity-60" />
                <span className="relative h-1.5 w-1.5 rounded-full bg-success" />
              </span>
              Online
            </span>
          </div>
          <div className="truncate text-[10.5px] text-muted-foreground">
            How can I help you securing your cloud today?
          </div>
        </div>
      </div>

      {/* waveform */}
      <div className="flex h-10 items-end justify-center gap-[3px] border-b border-border/60 bg-muted/30 px-4">
        {[3, 6, 9, 5, 11, 8, 14, 7, 10, 4, 12, 6, 9, 3, 8, 12, 5, 9, 6, 11, 4, 8, 6, 10, 5, 7, 9, 3, 12, 6].map((h, i) => (
          <motion.span
            key={i}
            className="w-[3px] rounded-full bg-brand-purple/60"
            style={{ height: h }}
            animate={{ height: [h, h * 0.4, h], opacity: [0.6, 1, 0.6] }}
            transition={{ repeat: Infinity, duration: 1.6, delay: (i % 7) * 0.12, ease: "easeInOut" }}
          />
        ))}
      </div>

      <div ref={scrollRef} className="max-h-[150px] flex-1 space-y-2 overflow-y-auto px-4 py-3">
        <AnimatePresence initial={false}>
          {messages.map((m) => (
            <motion.div
              key={m.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              className={cn("flex", m.role === "user" ? "justify-end" : "justify-start")}
            >
              {m.role === "ai" ? (
                <div className="max-w-[92%] rounded-2xl rounded-tl-sm border border-border bg-muted/50 px-3 py-2 text-sm leading-relaxed">
                  {m.thinking ? (
                    <span className="flex items-center gap-1 py-0.5">
                      {[0, 1, 2].map((i) => (
                        <motion.span
                          key={i}
                          className="h-1.5 w-1.5 rounded-full bg-primary/70"
                          animate={{ opacity: [0.3, 1, 0.3] }}
                          transition={{ repeat: Infinity, duration: 1, delay: i * 0.18 }}
                        />
                      ))}
                    </span>
                  ) : m.response ? (
                    <div className="space-y-1.5">
                      {m.response.blocks.map((b, i) => {
                        if (b.type === "heading") return <div key={i} className="text-[12px] font-bold">{b.content}</div>;
                        if (b.type === "list")
                          return (
                            <ul key={i} className="space-y-0.5">
                              {b.items?.map((it, j) => (
                                <li key={j} className="flex gap-1.5">
                                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />
                                  <span>{it}</span>
                                </li>
                              ))}
                            </ul>
                          );
                        return <p key={i} className="leading-relaxed">{b.content}</p>;
                      })}
                    </div>
                  ) : (
                    m.text
                  )}
                </div>
              ) : (
                <div className="max-w-[85%] rounded-2xl rounded-tr-sm bg-brand-gradient px-3 py-2 text-sm font-medium text-white shadow-soft">
                  {m.text}
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* suggestions and input grouped */}
      <div className="flex flex-col gap-2 border-t border-border px-4 py-3 bg-card rounded-b-2xl">
        <div className="flex gap-1.5 overflow-x-auto hide-scrollbar">
          {getSuggestions().slice(0, 3).map((s) => (
            <button
              key={s}
              onClick={() => send(s)}
              disabled={busy}
              className="shrink-0 cursor-pointer rounded-full border border-primary/20 bg-primary/5 px-2.5 py-1 text-xs font-medium text-primary transition hover:bg-primary/10 disabled:opacity-50"
            >
              {s}
            </button>
          ))}
        </div>

        {/* input */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && send(input)}
              placeholder="Ask anything..."
              className="h-9 w-full rounded-full border border-input bg-muted/40 pl-4 pr-10 text-sm outline-none transition focus:border-primary/50 focus:ring-2 focus:ring-ring/40"
            />
            <AudioLines className="absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          </div>
          <button
            onClick={() => send(input)}
            disabled={busy || !input.trim()}
            className="flex h-9 w-9 shrink-0 cursor-pointer items-center justify-center rounded-full bg-brand-gradient text-white shadow-soft transition hover:brightness-110 disabled:opacity-40"
          >
            <Send className="h-4 w-4 -translate-x-[0.5px] translate-y-[0.5px]" strokeWidth={2.4} />
          </button>
        </div>
      </div>
    </div>
  );
}
