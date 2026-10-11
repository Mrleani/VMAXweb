"use client";

import { Loader2, Radar } from "lucide-react";

interface ScanningStateProps {
  targetUrl: string;
  progress: number;
  stepText: string;
}

export function ScanningState({ targetUrl, progress, stepText }: ScanningStateProps) {
  return (
    <section className="mx-auto max-w-3xl py-16">
      <div className="glass-panel glow-emerald relative overflow-hidden rounded-3xl border-emerald-500/30 p-8 text-center">
        <div className="absolute left-0 top-0 h-1 w-full animate-scan bg-gradient-to-r from-transparent via-emerald-500 to-transparent" />

        <div className="mx-auto mb-6 flex h-20 w-20 animate-pulse items-center justify-center rounded-2xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
          <Radar className="h-9 w-9" />
        </div>

        <h3 className="mb-2 text-2xl font-bold text-white">
          Analyzing Target Vulnerabilities
        </h3>
        <p className="mb-8 font-mono text-sm text-emerald-400">Target: {targetUrl}</p>

        <div className="mb-6 w-full overflow-hidden rounded-full border border-slate-700 bg-slate-800 p-0.5">
          <div
            className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-400 transition-all duration-300 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>

        <div className="flex items-center justify-between px-2 font-mono text-xs text-slate-400">
          <span className="flex items-center gap-2">
            <Loader2 className="h-3.5 w-3.5 animate-spin text-emerald-400" />
            {stepText}
          </span>
          <span className="font-bold text-white">{progress}%</span>
        </div>
      </div>
    </section>
  );
}
