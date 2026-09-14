"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Search, CornerDownLeft, Command, FileBarChart, Radar, Bot, Boxes } from "lucide-react";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { NAV_SECTIONS } from "@/components/layout/nav";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";

interface Command {
  id: string;
  label: string;
  hint?: string;
  icon: React.ReactNode;
  action: () => void;
  group: string;
}

export function CommandMenu() {
  const { commandOpen, setCommandOpen } = useAppStore();
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandOpen(!commandOpen);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [commandOpen, setCommandOpen]);

  useEffect(() => {
    if (!commandOpen) return;
    const t = setTimeout(() => {
      setQuery("");
      setActive(0);
      inputRef.current?.focus();
    }, 50);
    return () => clearTimeout(t);
  }, [commandOpen]);

  const commands: Command[] = useMemo(() => {
    const pages: Command[] = NAV_SECTIONS.flatMap((s) =>
      s.items.map((i) => ({
        id: `nav-${i.href}`,
        label: `Go to ${i.title}`,
        hint: i.href === "/" ? "/dashboard" : i.href,
        icon: <i.icon className="h-4 w-4" />,
        action: () => {
          setCommandOpen(false);
          router.push(i.href);
        },
        group: s.label,
      }))
    );
    const actions: Command[] = [
      {
        id: "act-scan",
        label: "Run compliance scan across all accounts",
        hint: "Action",
        icon: <Radar className="h-4 w-4" />,
        action: () => {
          setCommandOpen(false);
          router.push("/detection-engine?tab=vulnerabilities");
        },
        group: "Actions",
      },
      {
        id: "act-report",
        label: "Generate weekly security report",
        hint: "Action",
        icon: <FileBarChart className="h-4 w-4" />,
        action: () => {
          setCommandOpen(false);
          router.push("/reports");
        },
        group: "Actions",
      },
      {
        id: "act-ai",
        label: "Ask AI Copilot a question",
        hint: "Action",
        icon: <Bot className="h-4 w-4" />,
        action: () => {
          setCommandOpen(false);
          router.push("/ai-copilot");
        },
        group: "Actions",
      },
      {
        id: "act-assets",
        label: "Show publicly exposed assets",
        hint: "Action",
        icon: <Boxes className="h-4 w-4" />,
        action: () => {
          setCommandOpen(false);
          router.push("/assets?filter=exposed");
        },
        group: "Actions",
      },
    ];
    return [...pages, ...actions];
  }, [router, setCommandOpen]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter(
      (c) => c.label.toLowerCase().includes(q) || (c.hint ?? "").toLowerCase().includes(q)
    );
  }, [commands, query]);

  useEffect(() => {
    const t = setTimeout(() => setActive(0), 0);
    return () => clearTimeout(t);
  }, [query]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      filtered[active]?.action();
    }
  };

  return (
    <Dialog open={commandOpen} onOpenChange={setCommandOpen}>
      <DialogContent className="top-[18%] max-w-xl gap-0 overflow-hidden p-0 sm:top-[18%]">
        <DialogTitle className="sr-only">Command menu</DialogTitle>
        <div className="flex items-center gap-3 border-b border-border px-4 py-3.5">
          <Search className="h-4 w-4 text-muted-foreground" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Search pages and actions…"
            className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
          <kbd className="flex items-center gap-0.5 rounded-md border border-border bg-muted px-1.5 py-0.5 text-[10px] font-semibold text-muted-foreground">
            <Command className="h-3 w-3" /> K
          </kbd>
        </div>
        <div className="max-h-[360px] overflow-y-auto p-2">
          {filtered.length === 0 && (
            <div className="px-3 py-10 text-center text-sm text-muted-foreground">
              No results for “{query}”
            </div>
          )}
          {filtered.map((c, i) => (
            <button
              key={c.id}
              onClick={c.action}
              onMouseEnter={() => setActive(i)}
              className={cn(
                "flex w-full cursor-pointer items-center gap-3 rounded-xl px-3 py-2.5 text-left text-[13px] transition-colors",
                i === active ? "bg-primary/10 text-foreground" : "text-muted-foreground"
              )}
            >
              <span className={cn(i === active ? "text-primary" : "text-muted-foreground")}>{c.icon}</span>
              <span className="flex-1 truncate font-medium">{c.label}</span>
              {c.hint && <span className="text-[10px] uppercase tracking-wide opacity-60">{c.hint}</span>}
              {i === active && <CornerDownLeft className="h-3.5 w-3.5 opacity-60" />}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-4 border-t border-border bg-muted/40 px-4 py-2 text-[10px] text-muted-foreground">
          <span>↑↓ to navigate</span>
          <span>↵ to select</span>
          <span className="ml-auto">esc to close</span>
        </div>
      </DialogContent>
    </Dialog>
  );
}
