"use client";

import { useEffect } from "react";
import { useAppStore } from "@/lib/store";

const ACCENTS: Record<string, { hex: string; brandBlue: string }> = {
  purple: { hex: "#6d5df6", brandBlue: "#4f7cf7" },
  blue: { hex: "#3b82f6", brandBlue: "#2563eb" },
  emerald: { hex: "#10b981", brandBlue: "#0d9488" },
  indigo: { hex: "#4f46e5", brandBlue: "#4338ca" },
};

const RADII: Record<string, string> = {
  compact: "12px",
  default: "16px",
  large: "22px",
};

export function useAppearanceStyles() {
  const appearance = useAppStore((s) => s.appearance);

  useEffect(() => {
    const root = document.documentElement;
    const a = ACCENTS[appearance.accent] ?? ACCENTS.purple;
    root.style.setProperty("--primary", a.hex);
    root.style.setProperty("--ring", a.hex);
    root.style.setProperty("--brand-purple", a.hex);
    root.style.setProperty("--brand-blue", a.brandBlue);
    root.style.setProperty("--brand-pink", appearance.accent === "purple" ? "#c35df5" : a.hex);
    root.style.setProperty("--radius", RADII[appearance.radius] ?? "16px");
    document.body.style.fontSize = appearance.largeText ? "17px" : "";
    document.body.style.colorScheme = appearance.highContrast ? "only-light" : "";
  }, [appearance]);
}

export { ACCENTS, RADII };
