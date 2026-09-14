"use client";

import { useEffect, useRef, useState } from "react";

/** Animate a number from 0 to target using requestAnimationFrame. */
export function useCountUp(target: number, duration = 1200, decimals = 0): number {
  const [value, setValue] = useState(0);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    const start = performance.now();
    const from = 0;
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setValue(from + (target - from) * eased);
      if (p < 1) rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, [target, duration]);

  return Number(value.toFixed(decimals));
}

export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(false);
  useEffect(() => {
    const mql = window.matchMedia(query);
    const id = requestAnimationFrame(() => setMatches(mql.matches));
    const handler = (e: MediaQueryListEvent) => setMatches(e.matches);
    mql.addEventListener("change", handler);
    return () => {
      cancelAnimationFrame(id);
      mql.removeEventListener("change", handler);
    };
  }, [query]);
  return matches;
}
