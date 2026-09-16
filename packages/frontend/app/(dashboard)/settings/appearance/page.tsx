"use client";

import { useEffect } from "react";
import { motion } from "framer-motion";
import { useTheme } from "next-themes";
import {
  Palette,
  MonitorSmartphone,
  Moon,
  Sun,
  Check,
  Sparkles,
  Contrast,
  Accessibility,
  MoveRight,
} from "lucide-react";
import { PageHeader } from "@/components/shared/page-header";
import { Switch } from "@/components/ui/switch";
import { useAppStore, DEFAULT_APPEARANCE, type AppearancePrefs, type AccentColor, type CornerRadius } from "@/lib/store";
import { toast } from "@/lib/toast";
import { cn } from "@/lib/utils";

const ACCENT_META: Record<string, { hex: string; name: string }> = {
  purple: { hex: "#6d5df6", name: "Purple" },
  blue: { hex: "#3b82f6", name: "Blue" },
  emerald: { hex: "#10b981", name: "Emerald" },
  indigo: { hex: "#4f46e5", name: "Indigo" },
};

const RADII_META: Record<string, { label: string; px: string }> = {
  compact: { label: "Compact", px: "12px" },
  default: { label: "Default", px: "16px" },
  large: { label: "Large", px: "22px" },
};

export default function AppearancePage() {
  const appearance = useAppStore((s) => s.appearance);
  const setAppearance = useAppStore((s) => s.setAppearance);
  const { setTheme, resolvedTheme } = useTheme();

  // Keep next-themes in sync with the persisted preference.
  useEffect(() => {
    if (appearance.themeMode === "dark") setTheme("dark");
    else if (appearance.themeMode === "light") setTheme("light");
    else setTheme("system");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appearance.themeMode]);

  const toggle = (key: keyof AppearancePrefs) => (v: boolean) => {
    setAppearance({ [key]: v } as Partial<AppearancePrefs>);
    toast(v ? "success" : "info", v ? "Enabled" : "Disabled", "Preference updated instantly across the app.");
  };

  return (
    <div className="mx-auto max-w-[1080px]">
      <PageHeader
        title="Appearance"
        description="Theme, accent color and interface density — applied instantly across the entire platform."
      >
        <span className="flex items-center gap-1.5 rounded-full border border-success/25 bg-success/10 px-3 py-1 text-xs font-semibold text-success">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute h-full w-full animate-ping rounded-full bg-success opacity-60" />
            <span className="relative h-1.5 w-1.5 rounded-full bg-success" />
          </span>
          Live preview — no refresh needed
        </span>
      </PageHeader>

      <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
        <div className="space-y-5">
          {/* Theme mode */}
          <Card icon={MonitorSmartphone} title="Theme mode" subtitle="System follows your OS preference automatically.">
            <div className="flex flex-col gap-2 sm:flex-row">
              {(
                [
                  { id: "system", label: "System (default)", icon: MonitorSmartphone },
                  { id: "light", label: "Light", icon: Sun },
                  { id: "dark", label: "Dark", icon: Moon },
                ] as const
              ).map((m) => (
                <button
                  key={m.id}
                  onClick={() => {
                    setAppearance({ themeMode: m.id });
                    toast("success", `Theme set to ${m.label}`, "The entire platform updated instantly.");
                  }}
                  className={cn(
                    "flex flex-1 cursor-pointer items-center gap-2 rounded-xl border px-4 py-3 text-[13px] font-semibold transition",
                    appearance.themeMode === m.id
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-border bg-muted/30 text-muted-foreground hover:border-primary/30 hover:text-foreground"
                  )}
                >
                  <m.icon className="h-4 w-4" />
                  {m.label}
                  {appearance.themeMode === m.id && <Check className="ml-auto h-4 w-4" />}
                </button>
              ))}
            </div>
            <p className="mt-3 text-sm text-muted-foreground">
              Current OS resolution: <span className="font-semibold text-foreground capitalize">{resolvedTheme}</span>. Use the
              moon icon in the top bar to switch instantly — it stays in sync with this page.
            </p>
          </Card>

          {/* Accent color */}
          <Card icon={Palette} title="Accent color" subtitle="Recolors buttons, charts, links and the entire topology.">
            <div className="flex flex-wrap gap-3">
              {Object.entries(ACCENT_META).map(([id, a]) => (
                <button
                  key={id}
                  onClick={() => {
                    setAppearance({ accent: id as AccentColor });
                    toast("success", `Accent color set to ${a.name}`);
                  }}
                  className="flex cursor-pointer items-center gap-2.5 rounded-xl border border-border bg-muted/30 px-3.5 py-2.5 transition hover:bg-muted/60"
                >
                  <span
                    className="flex h-8 w-8 items-center justify-center rounded-full text-white shadow-soft"
                    style={{ background: a.hex }}
                  >
                    {appearance.accent === id && <Check className="h-4 w-4" />}
                  </span>
                  <span className={cn("text-[12.5px] font-semibold", appearance.accent === id ? "text-foreground" : "text-muted-foreground")}>
                    {a.name}
                  </span>
                </button>
              ))}
            </div>
          </Card>

          {/* Border radius */}
          <Card icon={Sparkles} title="Border radius" subtitle="Adjusts cards, dialogs, buttons and inputs.">
            <div className="flex gap-2">
              {Object.entries(RADII_META).map(([id, r]) => (
                <button
                  key={id}
                  onClick={() => setAppearance({ radius: id as CornerRadius })}
                  className={cn(
                    "flex flex-1 cursor-pointer flex-col items-center gap-2 rounded-xl border px-3 py-3 transition",
                    appearance.radius === id
                      ? "border-primary/40 bg-primary/10 text-primary"
                      : "border-border bg-muted/30 text-muted-foreground hover:border-primary/30"
                  )}
                >
                  <span
                    className="h-9 w-16 border-2 transition"
                    style={{ borderRadius: r.px, borderColor: appearance.radius === id ? "currentColor" : "var(--border)" }}
                  />
                  <span className="text-sm font-semibold">{r.label}</span>
                </button>
              ))}
            </div>
          </Card>

          {/* Density + motion */}
          <Card icon={MoveRight} title="Density & motion" subtitle="Compact mode tightens spacing; animations toggle all motion.">
            <div className="space-y-2.5">
              <Row label="Compact mode" desc="Reduce padding and element sizes" checked={appearance.compactMode} onChange={toggle("compactMode")} />
              <Row label="Animations" desc="Enable transitions and micro-interactions" checked={appearance.animations} onChange={toggle("animations")} />
            </div>
          </Card>

          {/* Accessibility */}
          <Card icon={Accessibility} title="Accessibility" subtitle="Perceptual and motor preferences for every user.">
            <div className="space-y-2.5">
              <Row label="Reduced motion" desc="Minimize parallax, pulses and movement" checked={appearance.reducedMotion} onChange={toggle("reducedMotion")} />
              <Row label="High contrast" desc="Strengthen borders and text contrast" checked={appearance.highContrast} onChange={toggle("highContrast")} />
              <Row label="Large text" desc="Increase base font size across the app" checked={appearance.largeText} onChange={toggle("largeText")} />
            </div>
          </Card>
        </div>

        {/* Live preview */}
        <div className="h-fit space-y-4">
          <div className="overflow-hidden rounded-2xl border border-border bg-card shadow-soft">
            <div className="flex items-center gap-2 border-b border-border bg-gradient-to-r from-primary/10 to-transparent px-4 py-3">
              <span className="flex h-7 w-7 items-center justify-center rounded-lg" style={{ background: `${ACCENT_META[appearance.accent].hex}1f` }}>
                <Palette className="h-3.5 w-3.5" style={{ color: ACCENT_META[appearance.accent].hex }} />
              </span>
              <div>
                <div className="text-[12.5px] font-bold">Live preview</div>
                <div className="text-[10px] text-muted-foreground">Updates as you configure</div>
              </div>
            </div>
            <div className="space-y-3 p-4">
              <div className="flex items-center gap-2">
                <span className="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold text-white" style={{ background: ACCENT_META[appearance.accent].hex }}>
                  AM
                </span>
                <div className="flex-1">
                  <div className="h-2 w-28 rounded-full bg-muted" />
                  <div className="mt-1 h-1.5 w-20 rounded-full bg-muted" />
                </div>
                <span className="h-2 w-2 rounded-full bg-success" />
              </div>
              <div className="rounded-xl border border-border p-3">
                <div className="text-sm font-bold">Security score</div>
                <div className="mt-2 flex h-2 overflow-hidden rounded-full bg-muted">
                  <div className="h-full w-[92%]" style={{ background: ACCENT_META[appearance.accent].hex }} />
                </div>
                <div className="mt-2 grid grid-cols-3 gap-1.5">
                  <div className="h-8 rounded-lg bg-muted/70" />
                  <div className="h-8 rounded-lg bg-muted/70" />
                  <div className="h-8 rounded-lg bg-muted/70" />
                </div>
              </div>
              <div className="flex gap-2">
                <div className="flex h-8 flex-1 items-center justify-center rounded-lg text-xs font-semibold text-white" style={{ background: ACCENT_META[appearance.accent].hex }}>
                  Primary button
                </div>
                <div className="flex h-8 flex-1 items-center justify-center rounded-lg border border-border text-xs font-semibold text-muted-foreground">
                  Secondary
                </div>
              </div>
              <div className="flex items-center justify-between rounded-lg border border-border px-3 py-2">
                <span className="text-xs font-medium">Dark mode card</span>
                <span className="h-2 w-2 rounded-full bg-muted-foreground/50" />
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-border bg-card p-4 text-sm leading-relaxed text-muted-foreground shadow-soft">
            <span className="mb-1 flex items-center gap-1.5 font-semibold text-foreground">
              <Contrast className="h-3.5 w-3.5 text-primary" /> Everything syncs
            </span>
            Dashboard, Cloud Topology, Detection Engine, Threat Correlation, AI Copilot and Reports all read the same
            global appearance state — changes apply the moment you click.
          </div>

          <button
            onClick={() => setAppearance(DEFAULT_APPEARANCE)}
            className="flex h-9 w-full cursor-pointer items-center justify-center rounded-xl border border-border text-[12px] font-semibold text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
          >
            Reset to defaults
          </button>
        </div>
      </div>
    </div>
  );
}

function Card({
  icon: Icon,
  title,
  subtitle,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border border-border bg-card p-5 shadow-soft"
    >
      <div className="mb-4 flex items-center gap-2.5">
        <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-primary/10">
          <Icon className="h-4 w-4 text-primary" />
        </span>
        <div>
          <h3 className="text-[14.5px] font-bold leading-tight">{title}</h3>
          {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
        </div>
      </div>
      {children}
    </motion.section>
  );
}

function Row({
  label,
  desc,
  checked,
  onChange,
}: {
  label: string;
  desc: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-xl border border-border/60 px-4 py-3 transition hover:bg-muted/30">
      <div>
        <div className="text-[13px] font-medium">{label}</div>
        <div className="text-sm text-muted-foreground">{desc}</div>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
