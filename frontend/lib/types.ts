export type Severity = "critical" | "warning" | "passed" | "info";

export interface Finding {
  id: string;
  module: string;
  name: string;
  severity: Severity;
  status: string;
  summary: string;
  explanation: string;
  fix_snippet: string;
  confidence: "high" | "medium" | "low";
  meta: Record<string, unknown>;
}

export interface Target {
  url: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
}

export interface ScanSummary {
  score: number;
  grade: string;
  grade_label: string;
  critical: number;
  warning: number;
  passed: number;
  info: number;
}

export interface ScanResponse {
  scan_id: string;
  target: Target;
  summary: ScanSummary;
  findings: Finding[];
  started_at: string;
  finished_at: string;
  duration_ms: number;
  engine_version: string;
}

export interface ScanHistoryItem {
  id: string;
  url: string;
  host: string;
  score: number;
  grade: string;
  grade_label: string;
  trigger: "manual" | "scheduled";
  finished_at: string;
}

export interface ProfileInfo {
  id: string;
  email: string | null;
  plan: "free" | "pro";
  monthly_used: number;
  monthly_limit: number | null;
}

export type SeverityFilter = "all" | Severity;
