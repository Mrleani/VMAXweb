"use client";

import { FileText, Printer } from "lucide-react";

import type { ScanResponse } from "@/lib/types";
import { FindingsTable } from "./FindingsTable";
import { PricingBanner } from "./PricingBanner";
import { ScoreOverview } from "./ScoreOverview";

interface ResultsDashboardProps {
  result: ScanResponse;
  onExportPdf: () => void;
  onUpgrade: () => void;
  onActivePlan: () => void;
}

export function ResultsDashboard({
  result,
  onExportPdf,
  onUpgrade,
  onActivePlan,
}: ResultsDashboardProps) {
  const scannedAt = new Date(result.finished_at).toUTCString();

  return (
    <section className="space-y-10 py-6">
      <div className="glass-panel flex flex-col items-start justify-between gap-4 rounded-2xl border-slate-800 p-6 md:flex-row md:items-center">
        <div>
          <div className="flex items-center gap-3">
            <span className="rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 font-mono text-xs font-semibold text-emerald-400">
              Audit Completed
            </span>
            <h2 className="font-mono text-xl font-bold text-white sm:text-2xl">
              {result.target.url}
            </h2>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Scan Time: <span className="text-slate-300">{scannedAt}</span> • Duration:{" "}
            <span className="text-slate-300">{result.duration_ms} ms</span> • Audit
            Engine: VMAXweb v{result.engine_version}
          </p>
        </div>

        <div className="no-print flex w-full items-center gap-3 md:w-auto">
          <button
            type="button"
            onClick={() => window.print()}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-xs font-semibold text-slate-200 transition-all hover:bg-slate-700 md:flex-initial"
          >
            <Printer className="h-3.5 w-3.5" />
            <span>Print Audit</span>
          </button>
          <button
            type="button"
            onClick={onExportPdf}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-emerald-500 px-5 py-2.5 text-xs font-bold text-brand-dark shadow-lg shadow-emerald-500/20 transition-all hover:bg-emerald-400 md:flex-initial"
          >
            <FileText className="h-3.5 w-3.5" />
            <span>Export PDF Report</span>
          </button>
        </div>
      </div>

      <ScoreOverview summary={result.summary} />

      <FindingsTable findings={result.findings} />

      <PricingBanner onUpgrade={onUpgrade} onActivePlan={onActivePlan} />
    </section>
  );
}
