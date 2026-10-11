"use client";

import { BookOpen, ShieldAlert, Terminal } from "lucide-react";

const GRADE_BANDS = [
  { grade: "A", range: "90–100", label: "LOW RISK" },
  { grade: "B", range: "80–89", label: "MODERATE RISK" },
  { grade: "C", range: "70–79", label: "ELEVATED RISK" },
  { grade: "D", range: "60–69", label: "HIGH RISK" },
  { grade: "F", range: "0–59", label: "CRITICAL RISK" },
];

const SEVERITIES = [
  { name: "Critical", penalty: "−18", color: "text-brand-crimson" },
  { name: "Warning", penalty: "−6", color: "text-brand-amber" },
  { name: "Info", penalty: "−1", color: "text-brand-cyan" },
  { name: "Passed", penalty: "0", color: "text-emerald-400" },
];

const OWASP = [
  {
    code: "A01",
    title: "Broken Access Control",
    note: "CORS wildcards, exposed admin & debug endpoints.",
  },
  {
    code: "A02",
    title: "Cryptographic Failures",
    note: "Weak TLS protocols, expired certs, missing HSTS.",
  },
  {
    code: "A03",
    title: "Injection & XSS",
    note: "Missing Content-Security-Policy, framing headers.",
  },
  {
    code: "A05",
    title: "Security Misconfiguration",
    note: "Server version leaks, directory listing, debug ports.",
  },
  {
    code: "A06",
    title: "Vulnerable Components",
    note: "Outdated protocols and crypto suites in use.",
  },
  {
    code: "A09",
    title: "Logging & Monitoring Gaps",
    note: "Enables scheduled scans & drift detection on Pro.",
  },
];

export function DocumentationSection() {
  return (
    <section id="documentation" className="scroll-mt-24 space-y-8">
      <div className="text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-amber-500/20 bg-amber-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-widest text-amber-400">
          <BookOpen className="h-3.5 w-3.5" /> Documentation
        </span>
        <h2 className="mt-4 text-3xl font-black text-white sm:text-4xl">
          Scoring, Severity &amp; OWASP Coverage
        </h2>
        <p className="mx-auto mt-3 max-w-2xl text-sm text-slate-400">
          Every audit is graded on a transparent, deterministic model mapped to
          the OWASP Top 10 — no black boxes.
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="glass-panel rounded-3xl border-slate-800 p-8">
          <span className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-slate-400">
            <Terminal className="h-3.5 w-3.5 text-emerald-400" /> Health Score
          </span>
          <p className="mt-5 rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3 font-mono text-xs text-slate-300">
            score = clamp(100 − (critical×18 + warning×6 + info×1), 0, 100)
          </p>
          <div className="mt-5 space-y-2">
            {GRADE_BANDS.map((band) => (
              <div
                key={band.grade}
                className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/50 px-4 py-2 text-sm"
              >
                <span className="flex items-center gap-3">
                  <span className="flex h-7 w-7 items-center justify-center rounded-md bg-slate-800 font-bold text-emerald-400">
                    {band.grade}
                  </span>
                  <span className="text-slate-300">{band.label}</span>
                </span>
                <span className="font-mono text-xs text-slate-400">{band.range}</span>
              </div>
            ))}
          </div>
          <div className="mt-5 flex flex-wrap gap-2 border-t border-slate-800 pt-5">
            {SEVERITIES.map((sev) => (
              <span
                key={sev.name}
                className="rounded-full border border-slate-800 bg-slate-900/60 px-3 py-1 text-[11px] font-medium text-slate-400"
              >
                <span className={sev.color}>{sev.name}</span> · {sev.penalty} pts
              </span>
            ))}
          </div>
        </div>

        <div className="glass-panel rounded-3xl border-slate-800 p-8">
          <span className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-slate-400">
            <ShieldAlert className="h-3.5 w-3.5 text-amber-400" /> OWASP Top 10 Coverage
          </span>
          <ul className="mt-5 space-y-3">
            {OWASP.map((item) => (
              <li key={item.code} className="flex gap-3">
                <span className="mt-0.5 flex-shrink-0 rounded-md border border-slate-800 bg-slate-900/60 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-400">
                  {item.code}
                </span>
                <span>
                  <span className="block text-sm font-semibold text-slate-200">
                    {item.title}
                  </span>
                  <span className="block text-xs text-slate-400">{item.note}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="glass-panel rounded-3xl border-slate-800 p-8">
        <span className="text-xs font-bold uppercase tracking-widest text-slate-400">
          Verifying Target Ownership
        </span>
        <p className="mt-4 text-sm text-slate-400">
          Active modules (port scanning, subdomain discovery) are locked until you
          prove control of the target. Add this TXT record to your DNS, then
          include the token when you scan:
        </p>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3">
            <span className="block text-[10px] font-bold uppercase tracking-widest text-slate-500">
              TXT Record Name
            </span>
            <span className="mt-1 block font-mono text-xs text-emerald-400">
              yourdomain.com
            </span>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3">
            <span className="block text-[10px] font-bold uppercase tracking-widest text-slate-500">
              TXT Record Value
            </span>
            <span className="mt-1 block font-mono text-xs text-emerald-400">
              vmax-verify=&lt;token&gt;
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}
