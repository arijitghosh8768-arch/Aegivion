import { cn } from "@/lib/utils";
import type { ProviderId } from "@/lib/types";

const META: Record<ProviderId, { letter: string; color: string; bg: string }> = {
  aws: { letter: "A", color: "#FF9900", bg: "rgba(255,153,0,0.14)" },
  azure: { letter: "Az", color: "#0078D4", bg: "rgba(0,120,212,0.14)" },
  gcp: { letter: "G", color: "#4285F4", bg: "rgba(66,133,244,0.14)" },
};

export function ProviderMark({
  provider,
  size = 32,
  className,
}: {
  provider: ProviderId;
  size?: number;
  className?: string;
}) {
  const m = META[provider];
  return (
    <span
      className={cn("inline-flex shrink-0 items-center justify-center rounded-xl font-bold", className)}
      style={{
        width: size,
        height: size,
        color: m.color,
        backgroundColor: m.bg,
        fontSize: size * 0.4,
        boxShadow: `inset 0 0 0 1px ${m.color}33`,
      }}
    >
      {m.letter}
    </span>
  );
}
