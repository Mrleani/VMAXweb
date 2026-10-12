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

export interface Entitlements {
  unlimited_scans: boolean;
  active_modules: boolean;
  scheduled_scans: boolean;
  alerts: boolean;
  webhooks: boolean;
  api_access: boolean;
  white_label_pdf: boolean;
  priority_support: boolean;
}

export interface AccountInfo {
  id: string;
  email: string | null;
  plan: "free" | "pro";
  monthly_used: number;
  monthly_limit: number | null;
  entitlements: Entitlements;
  brand_name: string | null;
  logo_base64: string | null;
  brand_color: string | null;
  slack_webhook_url: string | null;
  webhook_url: string | null;
  webhook_secret_set: boolean;
  alert_email: string | null;
  alert_min_severity: "critical" | "warning" | "info";
  priority_support: boolean;
  is_owner: boolean;
}

export interface AccountUpdatePayload {
  brand_name?: string | null;
  logo_base64?: string | null;
  brand_color?: string | null;
  slack_webhook_url?: string | null;
  webhook_url?: string | null;
  webhook_secret?: string | null;
  alert_email?: string | null;
  alert_min_severity?: "critical" | "warning" | "info";
}

export interface ApiKeyInfo {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
}

export interface ApiKeyCreated {
  key: ApiKeyInfo;
  secret: string;
  warning: string;
}

export interface ScheduleInfo {
  id: string;
  url: string;
  cadence: "daily" | "weekly";
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  last_scan_id: string | null;
}

export type SeverityFilter = "all" | Severity;
