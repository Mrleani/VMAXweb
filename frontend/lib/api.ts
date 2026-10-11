import type { ScanResponse } from "./types";

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
