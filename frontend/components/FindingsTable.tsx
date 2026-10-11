"use client";

import { ChevronDown, Code2, ListChecks, ShieldAlert } from "lucide-react";
import { useMemo, useState } from "react";

import { SEVERITY_STYLES } from "@/lib/severity";
import type { Finding, SeverityFilter } from "@/lib/types";

const TABS: { id: SeverityFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "warning", label: "Warnings" },
  { id: "passed", label: "Passed" },
  { id: "info", label: "Info" },
];

interface FindingsTableProps {
  findings: Finding[];
}

export function FindingsTable({ findings }: FindingsTableProps) {
  const [filter, setFilter] = useState<SeverityFilter>("all");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const counts = useMemo(() => {
    return findings.reduce<Record<string, number>>(
      (acc, finding) => {
        acc[finding.severity] = (acc[finding.severity] ?? 0) + 1;
        return acc;
      },
      { all: findings.length },
    );
  }, [findings]);

  const visible = useMemo(
    () =>
      filter === "all"
        ? findings
        : findings.filter((finding) => finding.severity === filter),
    [findings, filter],
  );

  function toggle(id: string) {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="glass-panel overflow-hidden rounded-2xl border-slate-800">
      <div className="flex flex-col items-start justify-between gap-4 border-b border-slate-800 p-6 sm:flex-row sm:items-center">
        <div>
          <h3 className="flex items-center gap-2 text-lg font-bold text-white">
            <ListChecks className="h-5 w-5 text-emerald-400" />
            Comprehensive Audit Results Table
          </h3>
          <p className="mt-0.5 text-xs text-slate-400">
            Click any row to expand technical details and remediation snippets.
          </p>
        </div>

        <div className="no-print flex items-center rounded-xl border border-slate-800 bg-slate-900 p-1 text-xs font-medium">
          {TABS.map((tab) => {
            const active = filter === tab.id;
            const count = counts[tab.id] ?? 0;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilter(tab.id)}
                className={`rounded-lg px-3 py-1.5 transition-all ${
                  active
                    ? "bg-slate-800 font-semibold text-white"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {tab.label} ({count})
              </button>
            );
          })}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="border-b border-slate-800 bg-slate-900/50 text-[11px] font-bold uppercase tracking-wider text-slate-400">
              <th className="px-6 py-3.5">Security Module / Check Item</th>
              <th className="px-4 py-3.5">Severity</th>
              <th className="px-4 py-3.5">Technical Status</th>
              <th className="px-6 py-3.5">Action &amp; Recommendation</th>
              <th className="px-4 py-3.5 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-sm">
            {visible.map((finding) => {
              const style = SEVERITY_STYLES[finding.severity];
              const isOpen = expanded.has(finding.id);
              return (
                <FragmentRow
                  key={finding.id}
                  finding={finding}
                  style={style}
                  isOpen={isOpen}
                  onToggle={() => toggle(finding.id)}
                />
              );
            })}
          </tbody>
        </table>

        {visible.length === 0 && (
          <p className="p-8 text-center text-sm text-slate-500">
            No findings in this category.
          </p>
        )}
      </div>
    </div>
  );
}

interface FragmentRowProps {
  finding: Finding;
  style: (typeof SEVERITY_STYLES)[keyof typeof SEVERITY_STYLES];
  isOpen: boolean;
  onToggle: () => void;
}

function FragmentRow({ finding, style, isOpen, onToggle }: FragmentRowProps) {
  return (
    <>
      <tr
        onClick={onToggle}
        className="group cursor-pointer transition-colors hover:bg-slate-800/40"
      >
        <td className="px-6 py-4 font-medium text-white">
          <div className="font-bold">{finding.name}</div>
          <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-400">
            <span>{finding.module}</span>
            <span className="rounded border border-emerald-500/40 bg-emerald-500/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-emerald-400">
              {finding.confidence} confidence
            </span>
          </div>
        </td>
        <td className="px-4 py-4">
          <span
            className={`rounded-md border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider ${style.badge}`}
          >
            {style.label}
          </span>
        </td>
        <td className="px-4 py-4 font-mono text-xs text-slate-300">
          {finding.status}
        </td>
        <td className="px-6 py-4 text-xs text-slate-300">{finding.summary}</td>
        <td className="no-print px-4 py-4 text-right">
          <span className="inline-flex h-7 w-7 items-center justify-center rounded-lg bg-slate-800 text-slate-400 transition-all group-hover:bg-slate-700 group-hover:text-emerald-400">
            <ChevronDown
              className={`h-3 w-3 transition-transform ${isOpen ? "rotate-180" : ""}`}
            />
          </span>
        </td>
      </tr>
      {isOpen && (
        <tr className="border-b border-slate-800 bg-slate-900/90">
          <td colSpan={5} className="p-6">
            <div className="glass-panel space-y-4 rounded-xl border-slate-700/80 p-5">
              <div>
                <h4 className="mb-1 flex items-center gap-1 text-xs font-bold uppercase tracking-wider text-emerald-400">
                  <ShieldAlert className="h-3.5 w-3.5" /> Problem Explanation
                </h4>
                <p className="text-xs leading-relaxed text-slate-300">
                  {finding.explanation}
                </p>
              </div>
              <div>
                <h4 className="mb-2 flex items-center gap-1 text-xs font-bold uppercase tracking-wider text-cyan-400">
                  <Code2 className="h-3.5 w-3.5" /> How to Fix (Developer Remediation
                  Snippet)
                </h4>
                <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-brand-dark p-3 font-mono text-xs text-emerald-300">
                  {finding.fix_snippet || "# No remediation snippet required."}
                </pre>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
