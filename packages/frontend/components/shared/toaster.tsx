"use client";

import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle2, AlertCircle, Info, TriangleAlert, X } from "lucide-react";
import { useToastStore, type ToastKind } from "@/lib/toast";
import { cn } from "@/lib/utils";

const META: Record<ToastKind, { icon: React.ComponentType<{ className?: string }>; cls: string }> = {
  success: { icon: CheckCircle2, cls: "text-success" },
  error: { icon: AlertCircle, cls: "text-destructive" },
  info: { icon: Info, cls: "text-info" },
  warning: { icon: TriangleAlert, cls: "text-warning" },
};

export function Toaster() {
  const toasts = useToastStore((s) => s.toasts);
  const dismiss = useToastStore((s) => s.dismiss);

  return (
    <div className="pointer-events-none fixed bottom-5 right-5 z-[100] flex w-[340px] flex-col gap-2">
      <AnimatePresence>
        {toasts.map((t) => {
          const meta = META[t.kind];
          const Icon = meta.icon;
          return (
            <motion.div
              key={t.id}
              layout
              initial={{ opacity: 0, y: 24, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, x: 60, transition: { duration: 0.2 } }}
              transition={{ type: "spring", stiffness: 420, damping: 32 }}
              className="pointer-events-auto flex items-start gap-3 rounded-2xl border border-border bg-card/95 p-3.5 shadow-lift backdrop-blur-xl"
            >
              <Icon className={cn("mt-0.5 h-[18px] w-[18px] shrink-0", meta.cls)} />
              <div className="min-w-0 flex-1">
                <div className="text-[12.5px] font-semibold leading-tight">{t.title}</div>
                {t.description && (
                  <div className="mt-0.5 text-[11.5px] leading-snug text-muted-foreground">{t.description}</div>
                )}
              </div>
              <button
                onClick={() => dismiss(t.id)}
                className="cursor-pointer rounded-lg p-1 text-muted-foreground transition hover:bg-muted hover:text-foreground"
                aria-label="Dismiss"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </motion.div>
          );
        })}
      </AnimatePresence>
    </div>
  );
}
