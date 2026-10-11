"use client";

import { FileText, History, Loader2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import type { ScanHistoryItem } from "@/lib/types";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

async function fetchHistory(token: string | null): Promise<ScanHistoryItem[]> {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API_BASE}/api/v1/scans?limit=25`, { headers });
  if (!response.ok) return [];
  return (await response.json()) as ScanHistoryItem[];
}

async function downloadReport(
  scanId: string,
  host: string,
  token: string | null,
): Promise<void> {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${API_BASE}/api/v1/scans/${scanId}/report`, {
    headers,
  });
  if (!response.ok) throw new Error(`Report failed (${response.status})`);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vmaxweb-audit-${host}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

interface ScanHistoryProps {
  accessToken: string | null;
  onRefreshSignal: number;
}

export function ScanHistory({ accessToken, onRefreshSignal }: ScanHistoryProps) {
  const [items, setItems] = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    async function load() {
      setLoading(true);
      try {
        const data = await fetchHistory(accessToken);
        if (active) setItems(data);
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [accessToken, onRefreshSignal]);

  if (loading) {
    return (
      <div className="glass-panel flex items-center justify-center rounded-2xl border-slate-800 p-6 text-slate-400">
        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
        Loading scan history...
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="glass-panel rounded-2xl border-slate-800 p-6 text-center text-sm text-slate-500">
        <History className="mx-auto mb-2 h-5 w-5 text-slate-600" />
        No scans yet. Run your first security audit above.
      </div>
    );
  }

  return (
    <div className="glass-panel overflow-hidden rounded-2xl border-slate-800">
      <div className="border-b border-slate-800 p-6">
        <h3 className="flex items-center gap-2 text-lg font-bold text-white">
          <History className="h-5 w-5 text-emerald-400" />
          Recent Scans
        </h3>
        <p className="text-xs text-slate-400">
          Your latest audits, stored with your account.
        </p>
      </div>
      <div className="divide-y divide-slate-800/60">
        {items.map((item) => (
          <div
            key={item.id}
            className="flex flex-col items-start justify-between gap-3 p-4 sm:flex-row sm:items-center sm:px-6"
          >
            <div>
              <Link
                href={`#${item.id}`}
                className="font-mono text-sm font-medium text-emerald-300 transition-colors hover:text-emerald-200"
              >
                {item.url}
              </Link>
              <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-slate-500">
                <span>{item.host}</span>
                <span className="h-1 w-1 rounded-full bg-slate-700" />
                <span>
                  Score <strong className="text-slate-300">{item.score}</strong> • Grade{" "}
                  <strong className="text-slate-300">{item.grade}</strong>
                </span>
                <span className="h-1 w-1 rounded-full bg-slate-700" />
                <span className="capitalize">{item.trigger}</span>
                <span className="h-1 w-1 rounded-full bg-slate-700" />
                <span>{new Date(item.finished_at).toLocaleString()}</span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => downloadReport(item.id, item.host, accessToken)}
              className="no-print inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-700"
            >
              <FileText className="h-3.5 w-3.5" />
              PDF
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
