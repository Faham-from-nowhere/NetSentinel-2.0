// src/app/page.tsx
"use client";

import React from "react";
import { Vortex } from "@/components/ui/vortex";
import Link from "next/link";
import { TypewriterEffectSmooth } from "@/components/ui/typewriter-effect";

export default function LandingPage() {
  const words = [
    { text: "See",className: "!text-white" },
    { text: "Threats",className: "!text-white" },
    { text: "Before",className: "!text-white" },
    { text: "They",className: "!text-white" },
    { text: "Strike",className: "!text-white" },
  ];

  return (
    <Vortex
      backgroundColor="black"
      className="w-screen h-screen flex flex-col items-center justify-center px-4 text-center"
    >
      {/* Typewriter Heading */}
      <div className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold max-w-4xl leading-tight">
        <TypewriterEffectSmooth
          words={words}
          className="text-white"
          cursorClassName="bg-emerald-400"
        />
      </div>

      <p className="text-white/85 text-base sm:text-lg md:text-xl max-w-2xl mt-6 mb-12">
        NetSentinel uses AI-powered anomaly detection and real-time narrative intelligence to transform raw network traffic into actionable security insights.
      </p>

      <div className="flex flex-col sm:flex-row items-center gap-6">
        {/* Enter Command Center Button */}
        <Link href="/dashboard" legacyBehavior>
          <a
            className="group relative px-8 py-4 rounded-xl font-bold text-white transition-all duration-300 hover:scale-[1.02] active:scale-95 backdrop-blur-sm border border-white/10 hover:border-white/20"
          >
            <div className="absolute inset-0 bg-white/3 group-hover:bg-white/5 transition-colors duration-300 rounded-xl"></div>
            <div className="relative flex items-center gap-3">
              {/* SVG without horizontal line */}
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="22"
                height="22"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="text-emerald-400"
              >
                <path d="M7 10l5-5 5 5" />
                <path d="M7 14l5 5 5-5" />
              </svg>
              Enter Command Center
            </div>
          </a>
        </Link>

        {/* View Demo Button */}
        <button
          onClick={() => alert("A 60-second Loom demo is coming soon!")}
          className="group relative px-8 py-4 rounded-xl font-bold text-white/90 transition-all duration-300 hover:scale-[1.02] active:scale-95 backdrop-blur-sm border border-white/10 hover:border-white/20"
        >
          <div className="absolute inset-0 bg-white/3 group-hover:bg-white/5 transition-colors duration-300 rounded-xl"></div>
          <div className="relative flex items-center gap-2">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              className="text-white/70 group-hover:text-white transition-colors"
            >
              <circle cx="12" cy="12" r="10" />
              <polygon points="10 8 16 12 10 16 10 8" />
            </svg>
            View Demo
          </div>
        </button>
      </div>
    </Vortex>
  );
}