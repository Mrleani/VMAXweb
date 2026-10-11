"use client";

import { Boxes, Cpu, Lock, Workflow } from "lucide-react";

interface ArchitectureSectionProps {
  onOpenPricing: () => void;
}

const MODULES: { id: string; title: string; verified: boolean }[] = [
  { id: "headers", title: "HTTP Security Headers & Information Disclosure", verified: false },
  { id: "tls", title: "SSL/TLS Cryptography & Transport Security", verified: false },
  { id: "api", title: "API & Endpoint Security Audit", verified: false },
  { id: "sensitive_files", title: "Sensitive Data Exposure & OWASP Check", verified: false },
  { id: "ports", title: "Network & Port Security", verified: true },
  { id: "subdomains", title: "Subdomain & Attack Surface Mapping", verified: true },
];

const PIPELINE = [
  "Target validation & SSRF guard",
  "Concurrent module fan-out",
  "Ownership verification gate",
  "Scoring & grade engine",
  "Report, PDF & alerts",
];

export function ArchitectureSection({ onOpenPricing }: ArchitectureSectionProps) {
  return (
    <section id="architecture" className="scroll-mt-24 space-y-8">
      <div className="text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-widest text-cyan-400">
          <Cpu className="h-3.5 w-3.5" /> Architecture
        </span>
        <h2 className="mt-4 text-3xl font-black text-white sm:text-4xl">
          How the VMAXweb Engine Works
        </h2>
        <p className="mx-auto mt-3 max-w-2xl text-sm text-slate-400">
          A hybrid Next.js + FastAPI platform: a stateless audit engine running
          six security modules concurrently, backed by Supabase for persistence
          and authentication.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="glass-panel rounded-3xl border-slate-800 p-8">
          <span className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-slate-400">
            <Workflow className="h-3.5 w-3.5 text-emerald-400" /> Scan Pipeline
          </span>
          <ol className="mt-5 space-y-4">
            {PIPELINE.map((step, index) => (
              <li key={step} className="flex items-center gap-3">
                <span className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full border border-emerald-500/30 bg-emerald-500/10 text-xs font-bold text-emerald-400">
                  {index + 1}
                </span>
                <span className="text-sm text-slate-200">{step}</span>
              </li>
            ))}
          </ol>

          <div className="mt-8 space-y-3 border-t border-slate-800 pt-6 text-sm text-slate-400">
            <p>
              <strong className="text-slate-200">Engine:</strong> Python 3.13 ·
              FastAPI · httpx · dnspython · cryptography · fpdf2
            </p>
            <p>
              <strong className="text-slate-200">Frontend:</strong> Next.js 14 ·
              React 18 · Tailwind CSS
            </p>
            <p>
              <strong className="text-slate-200">Data &amp; Auth:</strong> Supabase
              (PostgreSQL + Row-Level Security)
            </p>
          </div>
        </div>

        <div className="glass-panel rounded-3xl border-slate-800 p-8">
          <span className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-slate-400">
            <Boxes className="h-3.5 w-3.5 text-emerald-400" /> Audit Modules
          </span>
          <ul className="mt-5 space-y-3">
            {MODULES.map((module) => (
              <li
                key={module.id}
                className="flex items-start justify-between gap-3 rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3"
              >
                <span className="text-sm text-slate-200">{module.title}</span>
                {module.verified ? (
                  <span className="flex flex-shrink-0 items-center gap-1 rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-amber-400">
                    <Lock className="h-3 w-3" /> Verified
                  </span>
                ) : (
                  <span className="flex-shrink-0 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-emerald-400">
                    Passive
                  </span>
                )}
              </li>
            ))}
          </ul>
          <p className="mt-5 text-[11px] leading-relaxed text-slate-500">
            Active modules (ports, subdomains) run only against targets you have
            verified via a DNS TXT record. This prevents the engine from being
            weaponised against third-party infrastructure.
          </p>
        </div>
      </div>

      <div className="glass-panel flex flex-col items-center justify-between gap-4 rounded-3xl border-emerald-500/20 p-6 text-center sm:flex-row sm:text-left">
        <p className="text-sm text-slate-300">
          Want the engine to run 24/7 with scheduled scans and alerts?
        </p>
        <button
          type="button"
          onClick={onOpenPricing}
          className="rounded-xl bg-emerald-500 px-5 py-2.5 text-xs font-bold text-brand-dark transition-colors hover:bg-emerald-400"
        >
          View Pricing &amp; Plans
        </button>
      </div>
    </section>
  );
}
