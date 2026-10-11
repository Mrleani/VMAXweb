"use client";

import { Check, Star, Zap } from "lucide-react";

interface PricingSectionProps {
  onUpgrade: () => void;
  onActivePlan: () => void;
}

const FREE_FEATURES = [
  "5 manual security scans / month",
  "All 6 security audit modules",
  "0–100 health score & A–F grade",
  "Developer remediation snippets",
  "Branded PDF audit reports",
  "Scan history dashboard",
];

const PRO_FEATURES = [
  "Unlimited manual scans",
  "24/7 scheduled daily & weekly scans",
  "Instant Slack & email alerts",
  "Subdomain & port attack-surface mapping",
  "White-label PDF reports (your logo)",
  "REST API access & webhooks",
  "Priority support",
];

export function PricingSection({ onUpgrade, onActivePlan }: PricingSectionProps) {
  return (
    <section id="pricing" className="scroll-mt-24 space-y-8">
      <div className="text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-widest text-emerald-400">
          <Star className="h-3.5 w-3.5" /> Pricing &amp; Plans
        </span>
        <h2 className="mt-4 text-3xl font-black text-white sm:text-4xl">
          Full-Power Security, Zero Compromise
        </h2>
        <p className="mx-auto mt-3 max-w-2xl text-sm text-slate-400">
          Start free with full-power manual audits. Upgrade to Pro when you need
          continuous automated protection for your entire attack surface.
        </p>
      </div>

      <div className="mx-auto grid max-w-4xl gap-6 lg:grid-cols-2">
        <div className="glass-panel flex flex-col rounded-3xl border-slate-800 p-8">
          <span className="text-xs font-bold uppercase tracking-widest text-slate-400">
            Free Plan
          </span>
          <div className="mt-2 text-4xl font-black text-white">
            $0 <span className="text-sm font-normal text-slate-400">/mo</span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Manual Audits &amp; PDF Export
          </p>
          <ul className="mt-6 space-y-3 text-sm text-slate-300">
            {FREE_FEATURES.map((feature) => (
              <li key={feature} className="flex items-start gap-2.5">
                <Check className="mt-0.5 h-4 w-4 flex-shrink-0 text-slate-500" />
                {feature}
              </li>
            ))}
          </ul>
          <button
            type="button"
            onClick={onActivePlan}
            className="mt-8 w-full rounded-xl bg-slate-800 py-3 text-sm font-semibold text-slate-200 transition-colors hover:bg-slate-700"
          >
            Active Plan
          </button>
        </div>

        <div className="glass-panel glow-emerald relative flex flex-col rounded-3xl border-emerald-500/40 bg-gradient-to-b from-emerald-950/40 to-slate-900 p-8">
          <span className="absolute right-6 top-6 rounded-full bg-emerald-500/20 px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider text-emerald-400">
            Recommended
          </span>
          <span className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-emerald-400">
            <Zap className="h-3.5 w-3.5" /> Pro Plan
          </span>
          <div className="mt-2 text-4xl font-black text-white">
            $29 <span className="text-sm font-normal text-slate-400">/mo</span>
          </div>
          <p className="mt-1 text-xs text-slate-300">
            24/7 Scheduled Scans &amp; Alerts
          </p>
          <ul className="mt-6 space-y-3 text-sm text-slate-200">
            {PRO_FEATURES.map((feature) => (
              <li key={feature} className="flex items-start gap-2.5">
                <Check className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-400" />
                {feature}
              </li>
            ))}
          </ul>
          <button
            type="button"
            onClick={onUpgrade}
            className="mt-8 w-full rounded-xl bg-emerald-500 py-3 text-sm font-bold text-brand-dark shadow-lg shadow-emerald-500/20 transition-colors hover:bg-emerald-400"
          >
            Upgrade to Pro
          </button>
        </div>
      </div>

      <p className="text-center text-[11px] text-slate-500">
        Prices in USD. Cancel anytime. Pro billing is processed securely via
        Stripe.
      </p>
    </section>
  );
}
