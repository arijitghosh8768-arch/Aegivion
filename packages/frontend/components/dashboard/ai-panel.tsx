"use client";

import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Bot, Send, Sparkles, ArrowUpRight } from "lucide-react";
import { answer, getSuggestions, type AiResponse } from "@/lib/data/ai";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";

interface Msg {
  id: string;
  role: "user" | "ai";
  text: string;
  response?: AiResponse;
  thinking?: boolean;
}

export function AiPanel({ className, expanded = false }: { className?: string; expanded?: boolean }) {
  const userName = useAppStore((s) => s.user?.name.split(" ")[0]);
  const greeting = userName
    ? `Hi ${userName}, I'm Aegivion Copilot — your explainable cloud security analyst. Ask me about your posture, threats or findings.`
    : "I'm Aegivion Copilot — your explainable cloud security analyst. Ask me about your posture, threats or findings.";
  const [messages, setMessages] = useState<Msg[]>([
    {
      id: "m0",
      role: "ai",
      text: greeting,
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
    }, 300);
  };

  return (
    <div className={cn("flex flex-col overflow-hidden rounded-2xl border border-border bg-card shadow-soft", className)}>
      <div className="flex items-center gap-2.5 border-b border-border bg-brand-gradient px-4 py-3">
        <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-white/15">
          <Bot className="h-4 w-4 text-white" />
        </span>
        <div className="flex-1">
          <div className="text-[13px] font-semibold text-white">Aegivion Copilot</div>
          <div className="flex items-center gap-1 text-[10px] text-white/80">
            <span className="h-1.5 w-1.5 rounded-full bg-white" />
            Explainable · Decision-grade
          </div>
        </div>
        <Sparkles className="h-4 w-4 text-white/90" />
      </div>

      <div ref={scrollRef} className={cn("flex-1 space-y-3 overflow-y-auto p-3.5", expanded ? "min-h-[360px]" : "min-h-[220px]")}>
        <AnimatePresence initial={false}>
          {messages.map((m) => (
            <motion.div
              key={m.id}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className={cn("flex", m.role === "user" ? "justify-end" : "justify-start")}
            >
              {m.role === "ai" ? (
                <div className="max-w-[92%]">
                  <div className="flex items-start gap-2">
                    <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-primary/10">
                      <Bot className="h-3.5 w-3.5 text-primary" />
                    </span>
                    <div className="rounded-2xl rounded-tl-sm border border-border bg-muted/50 px-3.5 py-2.5 text-[12.5px] leading-relaxed">
                      {m.thinking ? (
                        <TypingDots />
                      ) : m.response ? (
                        <AiBlocks blocks={m.response.blocks} />
                      ) : (
                        m.text
                      )}
                    </div>
                  </div>
                  {m.response && (
                    <div className="mt-1.5 flex items-center gap-1 pl-8 text-[10px] text-muted-foreground">
                      <span className="font-medium text-primary">Sources:</span>
                      {m.response.sources.slice(0, 2).join(" · ")} · {m.response.latencyMs}ms
                    </div>
                  )}
                </div>
              ) : (
                <div className="max-w-[85%] rounded-2xl rounded-tr-sm bg-brand-gradient px-3.5 py-2.5 text-[12.5px] font-medium leading-relaxed text-white shadow-soft">
                  {m.text}
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      <div className="border-t border-border p-3">
        <div className="mb-2 flex flex-wrap gap-1.5">
          {getSuggestions()
            .slice(0, 3)
            .map((s) => (
              <button
                key={s}
                onClick={() => send(s)}
                disabled={busy}
                className="cursor-pointer rounded-full border border-primary/20 bg-primary/5 px-2.5 py-1 text-[10.5px] font-medium text-primary transition hover:bg-primary/10 disabled:opacity-50"
              >
                {s}
              </button>
            ))}
        </div>
        <div className="flex items-center gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && send(input)}
            placeholder="Ask about your security posture…"
            className="h-9 flex-1 rounded-xl border border-input bg-muted/40 px-3 text-[13px] outline-none transition focus:border-primary/50 focus:ring-2 focus:ring-ring/40"
          />
          <button
            onClick={() => send(input)}
            disabled={busy || !input.trim()}
            className="flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl bg-brand-gradient text-white shadow-soft transition hover:brightness-110 disabled:opacity-40"
            aria-label="Send"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
        {expanded && (
          <button className="mt-2 flex w-full cursor-pointer items-center justify-center gap-1 rounded-xl border border-border bg-muted/30 py-2 text-[11px] font-semibold text-muted-foreground transition hover:text-foreground">
            Open full Copilot workspace <ArrowUpRight className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}

function TypingDots() {
  return (
    <span className="flex items-center gap-1 py-1">
      {[0, 1, 2].map((i) => (
        <motion.span
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-primary/70"
          animate={{ opacity: [0.3, 1, 0.3] }}
          transition={{ repeat: Infinity, duration: 1, delay: i * 0.18 }}
        />
      ))}
    </span>
  );
}

function AiBlocks({ blocks }: { blocks: AiResponse["blocks"] }) {
  return (
    <div className="space-y-2">
      {blocks.map((b, i) => {
        if (b.type === "heading")
          return (
            <div key={i} className="text-[13px] font-bold">
              {b.content}
            </div>
          );
        if (b.type === "list")
          return (
            <ul key={i} className="space-y-1">
              {b.items?.map((it, j) => (
                <li key={j} className="flex gap-1.5">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />
                  <span>{it}</span>
                </li>
              ))}
            </ul>
          );
        if (b.type === "code")
          return (
            <pre key={i} className="code-block overflow-x-auto rounded-lg bg-foreground/[0.06] p-2.5 text-[11px] dark:bg-black/40">
              {b.content}
            </pre>
          );
        return <p key={i} className="leading-relaxed">{b.content}</p>;
      })}
    </div>
  );
}
