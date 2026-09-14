"use client";

import { motion } from "framer-motion";

export function AuthBackground() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      <div className="absolute inset-0 bg-grid opacity-50 [mask-image:radial-gradient(ellipse_at_center,black,transparent_75%)]" />
      <motion.div
        className="absolute -left-32 top-[-10%] h-[520px] w-[520px] rounded-full bg-brand-purple/25 blur-[110px]"
        animate={{ x: [0, 50, 0], y: [0, 30, 0], scale: [1, 1.08, 1] }}
        transition={{ duration: 16, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className="absolute right-[-8%] top-[20%] h-[460px] w-[460px] rounded-full bg-brand-blue/22 blur-[110px]"
        animate={{ x: [0, -45, 0], y: [0, 40, 0], scale: [1, 1.1, 1] }}
        transition={{ duration: 19, repeat: Infinity, ease: "easeInOut", delay: 1 }}
      />
      <motion.div
        className="absolute bottom-[-15%] left-[28%] h-[420px] w-[420px] rounded-full bg-brand-pink/18 blur-[120px]"
        animate={{ x: [0, 35, 0], y: [0, -30, 0], scale: [1, 1.06, 1] }}
        transition={{ duration: 22, repeat: Infinity, ease: "easeInOut", delay: 2 }}
      />
      {/* floating particles */}
      {[
        { top: "18%", left: "12%", size: 5, delay: 0 },
        { top: "30%", left: "78%", size: 4, delay: 1.2 },
        { top: "68%", left: "20%", size: 6, delay: 0.6 },
        { top: "74%", left: "70%", size: 4, delay: 1.8 },
        { top: "45%", left: "45%", size: 3, delay: 2.4 },
      ].map((p, i) => (
        <motion.span
          key={i}
          className="absolute rounded-full bg-primary/40"
          style={{ top: p.top, left: p.left, width: p.size, height: p.size }}
          animate={{ y: [0, -26, 0], opacity: [0.25, 0.7, 0.25] }}
          transition={{ duration: 7, repeat: Infinity, ease: "easeInOut", delay: p.delay }}
        />
      ))}
    </div>
  );
}
