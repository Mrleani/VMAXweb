import { CircleAlert, CircleCheck, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";

import { gradeBadgeClasses, gradeColor } from "@/lib/severity";
import type { ScanSummary } from "@/lib/types";

const CIRCUMFERENCE = 326.72;

interface ScoreOverviewProps {
  summary: ScanSummary;
}

export function ScoreOverview({ summary }: ScoreOverviewProps) {
  const total = Math.max(
    1,
    summary.critical + summary.warning + summary.passed + summary.info,
  );
  const offset = CIRCUMFERENCE * (1 - summary.score / 100);

  return (
    <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
      <div className="glass-panel relative flex flex-col items-center justify-center overflow-hidden rounded-2xl border-slate-800 p-6 text-center">
        <div className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
          Overall Security Health
        </div>
        <div className="relative my-2 flex items-center justify-center">
          <svg className="h-32 w-32">
            <circle
              className="text-slate-800"
              strokeWidth="8"
              stroke="currentColor"
              fill="transparent"
              r="52"
              cx="64"
              cy="64"
            />
            <circle
              className={`transition-all duration-1000 ease-out ${gradeColor(summary.score)}`}
              strokeWidth="8"
              strokeDasharray={CIRCUMFERENCE}
              strokeDashoffset={offset}
              strokeLinecap="round"
              stroke="currentColor"
              fill="transparent"
              r="52"
              cx="64"
              cy="64"
              transform="rotate(-90 64 64)"
            />
          </svg>
          <div className="absolute flex flex-col items-center">
            <span className="text-3xl font-black text-white">{summary.score}</span>
            <span className="text-[10px] font-bold uppercase text-slate-400">
              / 100
            </span>
          </div>
        </div>
        <span
          className={`mt-2 rounded-full border px-3 py-1 text-xs font-bold ${gradeBadgeClasses(
            summary.score,
          )}`}
        >
          GRADE {summary.grade} - {summary.grade_label}
        </span>
      </div>

      <StatCard
        label="Critical Issues"
        value={summary.critical}
        hint="Requires immediate developer remediation"
        accent="red"
        percent={Math.round((summary.critical / total) * 100)}
        icon={<TriangleAlert className="h-4 w-4" />}
      />
      <StatCard
        label="Warnings"
        value={summary.warning}
        hint="Security best practices missing"
        accent="amber"
        percent={Math.round((summary.warning / total) * 100)}
        icon={<CircleAlert className="h-4 w-4" />}
      />
      <StatCard
        label="Passed Checks"
        value={summary.passed}
        hint="Validated against OWASP standards"
        accent="emerald"
        percent={Math.round((summary.passed / total) * 100)}
        icon={<CircleCheck className="h-4 w-4" />}
      />
    </div>
  );
}

type Accent = "red" | "amber" | "emerald";

const ACCENTS: Record<
  Accent,
  { border: string; chip: string; text: string; bar: string }
> = {
  red: {
    border: "border-red-500/20",
    chip: "bg-red-500/10 text-red-400",
    text: "text-red-400",
    bar: "bg-red-500",
  },
  amber: {
    border: "border-amber-500/20",
    chip: "bg-amber-500/10 text-amber-400",
    text: "text-amber-400",
    bar: "bg-amber-400",
  },
  emerald: {
    border: "border-emerald-500/20",
    chip: "bg-emerald-500/10 text-emerald-400",
    text: "text-emerald-400",
    bar: "bg-emerald-400",
  },
};

interface StatCardProps {
  label: string;
  value: number;
  hint: string;
  accent: Accent;
  percent: number;
  icon: ReactNode;
}

function StatCard({ label, value, hint, accent, percent, icon }: StatCardProps) {
  const style = ACCENTS[accent];
  return (
    <div
      className={`glass-panel flex flex-col justify-between rounded-2xl border p-6 ${style.border}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          {label}
        </span>
        <span
          className={`flex h-8 w-8 items-center justify-center rounded-lg ${style.chip}`}
        >
          {icon}
        </span>
      </div>
      <div className="my-4">
        <div className={`text-4xl font-black ${style.text}`}>{value}</div>
        <p className="mt-1 text-xs text-slate-400">{hint}</p>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full ${style.bar}`} style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}
