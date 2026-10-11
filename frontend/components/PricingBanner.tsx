"use client";

import { Star } from "lucide-react";

interface PricingBannerProps {
  onUpgrade: () => void;
  onActivePlan: () => void;
}

export function PricingBanner({ onUpgrade, onActivePlan }: PricingBannerProps) {
  return (
    <div
      id="pricing"
      className="glass-panel relative overflow-hidden rounded-3xl border-emerald-500/30 bg-gradient-to-r from-slate-900 via-brand-card to-slate-900 p-8"
    >
      <div className="flex flex-col items-center justify-between gap-8 lg:flex-row">
        <div className="space-y-3 text-center lg:text-left">
          <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-400">
            <Star className="h-3.5 w-3.5" /> VMAXweb Automation Upgrade
          </div>
          <h3 className="text-2xl font-black text-white sm:text-3xl">
            Automate Your Security 24/7
          </h3>
          <p className="max-w-xl text-sm text-slate-400">
            Free plan gives you{" "}
            <strong className="text-white">Full-Power manual audits</strong>. Upgrade
            to Pro for continuous automated daily scans, instant Slack alerts, and
            White-Label PDF reports.
          </p>
        </div>

        <div className="flex w-full flex-col items-center gap-4 sm:flex-row lg:w-auto">
          <div className="w-full rounded-2xl border border-slate-800 bg-slate-900/90 p-5 text-center sm:w-52">
            <span className="text-xs font-bold uppercase text-slate-400">
              Free Plan
            </span>
            <div className="my-1 text-2xl font-black text-white">
              $0 <span className="text-xs font-normal text-slate-400">/mo</span>
            </div>
            <p className="mb-3 text-[11px] text-slate-400">
              Manual Audits &amp; PDF Export
            </p>
            <button
              type="button"
              onClick={onActivePlan}
              className="w-full rounded-lg bg-slate-800 py-2 text-xs font-semibold text-slate-300 hover:bg-slate-700"
            >
              Active Plan
            </button>
          </div>

          <div className="glass-panel glow-emerald relative w-full rounded-2xl border-emerald-500/40 bg-gradient-to-b from-emerald-950/40 to-slate-900 p-5 text-center sm:w-56">
            <span className="rounded-full bg-emerald-500/20 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-emerald-400">
              Recommended
            </span>
            <div className="my-1 text-3xl font-black text-white">
              $29 <span className="text-xs font-normal text-slate-400">/mo</span>
            </div>
            <p className="mb-3 text-[11px] text-slate-300">
              24/7 Scheduled Scans &amp; Alerts
            </p>
            <button
              type="button"
              onClick={onUpgrade}
              className="w-full rounded-lg bg-emerald-500 py-2 text-xs font-bold text-brand-dark shadow-md transition-colors hover:bg-emerald-400"
            >
              Upgrade to Pro
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
