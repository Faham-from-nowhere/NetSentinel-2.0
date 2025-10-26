// src/components/vortex-demo.tsx
"use client";

import React from "react";
import { Vortex } from "@/components/ui/vortex";
import Link from "next/link";

export default function VortexDemo() {
  const handleViewDemo = () => {
    // 🔗 Replace this with your actual demo link (e.g., Loom, YouTube, or internal route)
    window.open("https://www.loom.com/share/your-demo-id", "_blank");
  };

  return (
    <Vortex
      backgroundColor="black"
      className="w-screen h-screen flex flex-col items-center justify-center px-4 sm:px-6 text-center"
    >
      <h1 className="text-white text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold max-w-4xl leading-tight">
        See Threats Before They Strike
      </h1>
      <p className="text-white/85 text-base sm:text-lg md:text-xl max-w-2xl mt-6 mb-10">
        NetSentinel uses AI-powered anomaly detection and real-time narrative intelligence to transform raw network traffic into actionable security insights—before data is lost.
      </p>
      <div className="flex flex-col sm:flex-row items-center gap-4">
        <Link
          href="/dashboard"
          className="px-6 py-3.5 bg-emerald-600 hover:bg-emerald-700 transition duration-200 rounded-lg text-white font-medium shadow-[0px_4px_0px_0px_rgba(34,193,195,0.3)_inset]"
        >
          Launch Command Center
        </Link>
        <button
          onClick={handleViewDemo}
          className="px-6 py-3.5 text-white/90 font-medium hover:text-white transition duration-200 rounded-lg border border-white/20 hover:bg-white/5"
        >
          View Demo
        </button>
      </div>
    </Vortex>
  );
}