import React from 'react';
import { cn } from "@/lib/utils";

export function buttonVariants({ variant = "default" }: { variant?: "default" | "outline" } = {}) {
  const base = "inline-flex items-center justify-center rounded-md text-sm font-medium transition-all focus-visible:outline-none disabled:opacity-50 disabled:pointer-events-none";
  const variants = {
    default: "px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-white shadow",
    outline: "px-4 py-2 border border-slate-700 hover:bg-slate-800 rounded text-slate-300",
  };
  return cn(base, variants[variant] || variants.default);
}

export function Button({ children, className = '', variant = 'default', ...props }: any) {
  return (
    <button className={cn(buttonVariants({ variant }), className)} {...props}>
      {children}
    </button>
  );
}
