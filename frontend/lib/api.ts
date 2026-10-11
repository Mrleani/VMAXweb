import type {
  AccountInfo,
  AccountUpdatePayload,
  ApiKeyCreated,
  ApiKeyInfo,
  ScanResponse,
  ScheduleInfo,
} from "./types";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function runScan(
  url: string,
  verificationToken?: string,
): Promise<ScanResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/api/v1/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, verification_token: verificationToken || null }),
    });
  } catch {
    throw new ApiError(
      "Could not reach the VMAXweb engine. Is the backend running?",
    );
  }

  if (!response.ok) {
    const detail = await response
      .json()
      .then((data) => data?.detail as string | undefined)
      .catch(() => undefined);
    throw new ApiError(detail ?? `Scan failed (HTTP ${response.status})`, response.status);
  }

  return (await response.json()) as ScanResponse;
}

export async function downloadReport(
  scanId: string,
  filename: string,
): Promise<void> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/api/v1/scans/${scanId}/report`);
  } catch {
    throw new ApiError("Could not reach the VMAXweb engine for the PDF report.");
  }

  if (!response.ok) {
    throw new ApiError(
      `Report generation failed (HTTP ${response.status})`,
      response.status,
    );
  }

  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

export function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "";
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function authHeaders(token?: string | null): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function accountRequest<T>(
  path: string,
  options: { method?: string; body?: unknown; token?: string | null } = {},
): Promise<T> {
  const { method = "GET", body, token } = options;
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      headers: authHeaders(token),
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError("Could not reach the VMAXweb engine.");
  }

  if (!response.ok) {
    const detail = await response
      .json()
      .then((data) => data?.detail as string | undefined)
      .catch(() => undefined);
    throw new ApiError(detail ?? `Request failed (HTTP ${response.status})`, response.status);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export function getAccount(token?: string | null): Promise<AccountInfo> {
  return accountRequest<AccountInfo>("/api/v1/account", { token });
}

export function setPlan(plan: "free" | "pro", token?: string | null): Promise<AccountInfo> {
  return accountRequest<AccountInfo>("/api/v1/account/plan", {
    method: "POST",
    body: { plan },
    token,
  });
}

export function updateAccount(
  payload: AccountUpdatePayload,
  token?: string | null,
): Promise<AccountInfo> {
  return accountRequest<AccountInfo>("/api/v1/account", { method: "PUT", body: payload, token });
}

export function listApiKeys(token?: string | null): Promise<ApiKeyInfo[]> {
  return accountRequest<ApiKeyInfo[]>("/api/v1/api-keys", { token });
}

export function createApiKey(name: string, token?: string | null): Promise<ApiKeyCreated> {
  return accountRequest<ApiKeyCreated>("/api/v1/api-keys", {
    method: "POST",
    body: { name },
    token,
  });
}

export function revokeApiKey(keyId: string, token?: string | null): Promise<void> {
  return accountRequest<void>(`/api/v1/api-keys/${keyId}`, { method: "DELETE", token });
}

export function listSchedules(token?: string | null): Promise<ScheduleInfo[]> {
  return accountRequest<ScheduleInfo[]>("/api/v1/schedules", { token });
}

export function createSchedule(
  url: string,
  cadence: "daily" | "weekly",
  token?: string | null,
): Promise<ScheduleInfo> {
  return accountRequest<ScheduleInfo>("/api/v1/schedules", {
    method: "POST",
    body: { url, cadence },
    token,
  });
}

export function deleteSchedule(scheduleId: string, token?: string | null): Promise<void> {
  return accountRequest<void>(`/api/v1/schedules/${scheduleId}`, { method: "DELETE", token });
}
