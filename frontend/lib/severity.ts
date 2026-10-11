import type { Severity } from "./types";

export interface SeverityStyle {
  label: string;
  badge: string;
  dot: string;
  text: string;
}

export const SEVERITY_STYLES: Record<Severity, SeverityStyle> = {
  critical: {
    label: "CRITICAL",
    badge: "bg-red-500/10 text-red-400 border-red-500/20",
    dot: "bg-red-400",
    text: "text-red-400",
  },
  warning: {
    label: "WARNING",
    badge: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    dot: "bg-amber-400",
    text: "text-amber-400",
  },
  passed: {
    label: "PASSED",
    badge: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    dot: "bg-emerald-400",
    text: "text-emerald-400",
  },
  info: {
    label: "INFO",
    badge: "bg-sky-500/10 text-sky-400 border-sky-500/20",
    dot: "bg-sky-400",
    text: "text-sky-400",
  },
};

export function gradeColor(score: number): string {
  if (score >= 90) return "text-emerald-400";
  if (score >= 70) return "text-amber-400";
  return "text-red-400";
}

export function gradeBadgeClasses(score: number): string {
  if (score >= 90) return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
  if (score >= 70) return "bg-amber-500/10 text-amber-400 border-amber-500/20";
  return "bg-red-500/10 text-red-400 border-red-500/20";
}
