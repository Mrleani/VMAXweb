"use client";

import { Globe, KeyRound, ShieldCheck, Zap } from "lucide-react";
import { useState, type FormEvent } from "react";

interface ScannerHeroProps {
  onScan: (url: string, verificationToken?: string) => void;
  busy: boolean;
}

const QUICK_TARGETS = [
  "https://example.com",
  "https://github.com",
  "https://vercel.com",
];

export function ScannerHero({ onScan, busy }: ScannerHeroProps) {
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);

  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!url.trim()) return;
    onScan(url, token.trim() || undefined);
  }

  return (
    <section className="relative py-12 text-center md:py-16">
      <div className="pointer-events-none absolute inset-0 -z-10 flex items-center justify-center opacity-30">
        <div className="h-96 w-96 rounded-full bg-emerald-500/10 blur-3xl" />
        <div className="h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl" />
      </div>

      <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-800/80 px-4 py-1.5 text-xs font-medium text-slate-300">
        <ShieldCheck className="h-4 w-4 text-emerald-400" />
        <span>StarNet B2B Security Framework 2.0</span>
      </div>

      <h1 className="mx-auto max-w-4xl text-4xl font-black leading-tight tracking-tight text-white sm:text-6xl">
        Maximum Velocity. <br />
        <span className="bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
          Uncompromised Web Security.
        </span>
      </h1>

      <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-slate-400">
        Instant automated security audits for modern Web Apps and APIs. Zero setup
        required. OWASP-aligned configuration and exposure checks with actionable
        developer remediation.
      </p>

      <div className="mx-auto mt-10 max-w-3xl">
        <form
          onSubmit={handleSubmit}
          className="glass-panel glow-cyan flex flex-col items-center gap-3 rounded-2xl border-slate-700/80 p-2.5 transition-all focus-within:border-emerald-500/50 sm:flex-row"
        >
          <div className="flex w-full items-center gap-3 px-4 py-2">
            <Globe className="h-5 w-5 text-slate-400" />
            <input
              type="text"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="https://your-api-or-website.com"
              required
              className="w-full bg-transparent font-mono text-base text-white placeholder-slate-500 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={busy}
            className="flex w-full items-center justify-center gap-2 whitespace-nowrap rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 px-8 py-4 text-sm font-bold tracking-wide text-brand-dark shadow-lg shadow-emerald-500/20 transition-all hover:from-emerald-400 hover:to-teal-500 disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
          >
            <Zap className="h-4 w-4" />
            <span>Run Security Audit</span>
          </button>
        </form>

        <div className="mt-3 flex items-center justify-center">
          <button
            type="button"
            onClick={() => setShowToken((value) => !value)}
            className="inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-500 transition-colors hover:text-emerald-400"
          >
            <KeyRound className="h-3 w-3" />
            {showToken ? "Hide ownership verification" : "Enable active checks (DNS verification)"}
          </button>
        </div>

        {showToken && (
          <input
            type="text"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder="vmax-verify TXT token (enables port & subdomain scans)"
            className="mt-2 w-full rounded-xl border border-slate-800 bg-slate-900/70 px-4 py-3 font-mono text-xs text-slate-200 placeholder-slate-600 focus:border-emerald-500/50 focus:outline-none"
          />
        )}

        <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-xs text-slate-400">
          <span className="font-medium text-slate-500">Quick Test Targets:</span>
          {QUICK_TARGETS.map((target) => (
            <button
              key={target}
              type="button"
              onClick={() => setUrl(target)}
              className="rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1 font-mono text-slate-300 transition-colors hover:bg-slate-700"
            >
              {target.replace("https://", "")}
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}
