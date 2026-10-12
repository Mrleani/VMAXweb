"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Bell,
  CalendarClock,
  Crown,
  FileBadge,
  KeyRound,
  Loader2,
  Plus,
  ShieldCheck,
  Star,
  Trash2,
  Webhook,
} from "lucide-react";

import {
  createApiKey,
  createSchedule,
  deleteSchedule,
  getAccount,
  listApiKeys,
  listSchedules,
  revokeApiKey,
  setPlan,
  updateAccount,
} from "@/lib/api";
import type { AccountInfo, ApiKeyInfo, ScheduleInfo } from "@/lib/types";
import { useToast } from "./Toast";

interface ProPanelProps {
  accessToken: string | null;
  refreshSignal?: number;
}

export function ProPanel({ accessToken, refreshSignal = 0 }: ProPanelProps) {
  const { show } = useToast();
  const [account, setAccount] = useState<AccountInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const [brandName, setBrandName] = useState("");
  const [brandColor, setBrandColor] = useState("");
  const [logo, setLogo] = useState<string | null>(null);
  const [slack, setSlack] = useState("");
  const [webhook, setWebhook] = useState("");
  const [alertEmail, setAlertEmail] = useState("");
  const [minSeverity, setMinSeverity] = useState<"critical" | "warning" | "info">("critical");

  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [newKeySecret, setNewKeySecret] = useState<string | null>(null);
  const [schedules, setSchedules] = useState<ScheduleInfo[]>([]);
  const [scheduleUrl, setScheduleUrl] = useState("");
  const [cadence, setCadence] = useState<"daily" | "weekly">("daily");

  const apply = useCallback((data: AccountInfo) => {
    setAccount(data);
    setBrandName(data.brand_name ?? "");
    setBrandColor(data.brand_color ?? "");
    setLogo(data.logo_base64 ?? null);
    setSlack(data.slack_webhook_url ?? "");
    setWebhook(data.webhook_url ?? "");
    setAlertEmail(data.alert_email ?? "");
    setMinSeverity(data.alert_min_severity);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getAccount(accessToken);
      apply(data);
      if (data.plan === "pro") {
        const [k, s] = await Promise.all([
          listApiKeys(accessToken),
          listSchedules(accessToken),
        ]);
        setKeys(k);
        setSchedules(s);
      }
    } catch (error) {
      show(error instanceof Error ? error.message : "Could not load account.", "error");
    } finally {
      setLoading(false);
    }
  }, [accessToken, apply, show]);

  useEffect(() => {
    void load();
  }, [load, refreshSignal]);

  async function handleActivate() {
    setBusy(true);
    try {
      const data = await setPlan("pro", accessToken);
      apply(data);
      show("Pro plan activated.");
      await load();
    } catch (error) {
      show(error instanceof Error ? error.message : "Activation failed.", "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleDowngrade() {
    setBusy(true);
    try {
      const data = await setPlan("free", accessToken);
      apply(data);
      show("Switched to Free plan.");
    } catch (error) {
      show(error instanceof Error ? error.message : "Update failed.", "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveSettings() {
    setBusy(true);
    try {
      const data = await updateAccount(
        {
          brand_name: brandName || null,
          brand_color: brandColor || null,
          logo_base64: logo,
          slack_webhook_url: slack || null,
          webhook_url: webhook || null,
          alert_email: alertEmail || null,
          alert_min_severity: minSeverity,
        },
        accessToken,
      );
      apply(data);
      show("Pro settings saved.");
    } catch (error) {
      show(error instanceof Error ? error.message : "Save failed.", "error");
    } finally {
      setBusy(false);
    }
  }

  function handleLogoFile(file: File | undefined) {
    if (!file) return;
    if (file.size > 300 * 1024) {
      show("Logo must be under 300 KB.", "error");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => setLogo(typeof reader.result === "string" ? reader.result : null);
    reader.readAsDataURL(file);
  }

  async function handleCreateKey() {
    setBusy(true);
    try {
      const created = await createApiKey("dashboard", accessToken);
      setNewKeySecret(created.secret);
      setKeys((prev) => [created.key, ...prev]);
      show("API key created.");
    } catch (error) {
      show(error instanceof Error ? error.message : "Could not create key.", "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleRevokeKey(id: string) {
    try {
      await revokeApiKey(id, accessToken);
      setKeys((prev) => prev.filter((k) => k.id !== id));
      show("API key revoked.");
    } catch (error) {
      show(error instanceof Error ? error.message : "Could not revoke key.", "error");
    }
  }

  async function handleAddSchedule() {
    const url = scheduleUrl.trim();
    if (!url) return;
    setBusy(true);
    try {
      const created = await createSchedule(url, cadence, accessToken);
      setSchedules((prev) => [created, ...prev]);
      setScheduleUrl("");
      show("Scheduled scan created.");
    } catch (error) {
      show(error instanceof Error ? error.message : "Could not create schedule.", "error");
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteSchedule(id: string) {
    try {
      await deleteSchedule(id, accessToken);
      setSchedules((prev) => prev.filter((s) => s.id !== id));
      show("Schedule removed.");
    } catch (error) {
      show(error instanceof Error ? error.message : "Could not remove schedule.", "error");
    }
  }

  if (loading) {
    return (
      <section id="pro" className="flex justify-center py-10">
        <Loader2 className="h-5 w-5 animate-spin text-emerald-400" />
      </section>
    );
  }

  if (!account) return null;

  if (account.plan !== "pro") {
    return (
      <section id="pro" className="scroll-mt-24">
        <div className="glass-panel flex flex-col items-center gap-4 rounded-3xl border-slate-800 p-8 text-center">
          <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-widest text-emerald-400">
            <Crown className="h-3.5 w-3.5" /> VMAXweb Pro
          </span>
          <p className="max-w-xl text-sm text-slate-400">
            You are on the Free plan ({account.monthly_used}/
            {account.monthly_limit ?? "∞"} scans this month). Activate Pro to unlock
            unlimited scans, scheduled audits, Slack &amp; email alerts, webhooks,
            REST API access and white-label PDF reports.
          </p>
          <button
            type="button"
            onClick={handleActivate}
            disabled={busy}
            className="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-6 py-3 text-sm font-bold text-brand-dark transition-colors hover:bg-emerald-400 disabled:opacity-60"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Crown className="h-4 w-4" />}
            Activate Pro Plan
          </button>
          <p className="text-[11px] text-slate-500">
            Instant activation in this deployment. Add Stripe keys to enable paid
            checkout.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section id="pro" className="scroll-mt-24 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-widest text-emerald-400">
            <Crown className="h-3.5 w-3.5" /> Pro Console
          </span>
          <h2 className="mt-3 text-2xl font-black text-white">Pro Control Center</h2>
        </div>
        <div className="flex items-center gap-3">
          {account.priority_support && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-3 py-1.5 text-xs font-semibold text-emerald-300">
              <ShieldCheck className="h-3.5 w-3.5" /> Priority Support
            </span>
          )}
          {account.is_owner && (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 px-3 py-1.5 text-xs font-semibold text-amber-300">
              <Star className="h-3.5 w-3.5" /> Owner
            </span>
          )}
          <button
            type="button"
            onClick={handleDowngrade}
            disabled={busy}
            className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-800 disabled:opacity-60"
          >
            Switch to Free
          </button>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <ProCard icon={<Bell className="h-4 w-4" />} title="Alerts & Webhooks">
          <Field label="Slack webhook URL">
            <input
              value={slack}
              onChange={(e) => setSlack(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className={inputClass}
            />
          </Field>
          <Field label="Outgoing webhook URL">
            <input
              value={webhook}
              onChange={(e) => setWebhook(e.target.value)}
              placeholder="https://your-app.com/vmax-hook"
              className={inputClass}
            />
          </Field>
          <Field label="Alert email">
            <input
              value={alertEmail}
              onChange={(e) => setAlertEmail(e.target.value)}
              placeholder="security@your-company.com"
              className={inputClass}
            />
          </Field>
          <Field label="Alert on severity at or above">
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value as typeof minSeverity)}
              className={inputClass}
            >
              <option value="critical">Critical only</option>
              <option value="warning">Warning and above</option>
              <option value="info">Everything</option>
            </select>
          </Field>
          <p className="text-[11px] text-slate-500">
            Webhook payloads are signed with HMAC-SHA256 in the{" "}
            <code className="text-emerald-400">X-VMAX-Signature</code> header.
          </p>
        </ProCard>

        <ProCard icon={<FileBadge className="h-4 w-4" />} title="White-label PDF Reports">
          <Field label="Brand name">
            <input
              value={brandName}
              onChange={(e) => setBrandName(e.target.value)}
              placeholder="Acme Security"
              className={inputClass}
            />
          </Field>
          <Field label="Accent color">
            <input
              type="color"
              value={brandColor || "#10b981"}
              onChange={(e) => setBrandColor(e.target.value)}
              className="h-10 w-full cursor-pointer rounded-lg border border-slate-700 bg-slate-900"
            />
          </Field>
          <Field label="Logo (PNG/JPEG, ≤300 KB)">
            <input
              type="file"
              accept="image/png,image/jpeg"
              onChange={(e) => handleLogoFile(e.target.files?.[0])}
              className="block w-full text-xs text-slate-400 file:mr-3 file:rounded-lg file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-xs file:font-semibold file:text-slate-200"
            />
          </Field>
          {logo && (
            <button
              type="button"
              onClick={() => setLogo(null)}
              className="text-xs text-slate-500 underline hover:text-slate-300"
            >
              Remove logo
            </button>
          )}
          <button
            type="button"
            onClick={handleSaveSettings}
            disabled={busy}
            className="mt-2 rounded-lg bg-emerald-500 px-4 py-2 text-xs font-bold text-brand-dark hover:bg-emerald-400 disabled:opacity-60"
          >
            Save Pro settings
          </button>
        </ProCard>

        <ProCard icon={<CalendarClock className="h-4 w-4" />} title="Scheduled Scans">
          <div className="flex gap-2">
            <input
              value={scheduleUrl}
              onChange={(e) => setScheduleUrl(e.target.value)}
              placeholder="example.com"
              className={inputClass}
            />
            <select
              value={cadence}
              onChange={(e) => setCadence(e.target.value as typeof cadence)}
              className={inputClass + " max-w-[110px]"}
            >
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
            </select>
            <button
              type="button"
              onClick={handleAddSchedule}
              disabled={busy}
              className="rounded-lg bg-emerald-500 px-3 text-brand-dark hover:bg-emerald-400 disabled:opacity-60"
            >
              <Plus className="h-4 w-4" />
            </button>
          </div>
          <ul className="space-y-2">
            {schedules.length === 0 && (
              <li className="text-xs text-slate-500">No scheduled scans yet.</li>
            )}
            {schedules.map((s) => (
              <li
                key={s.id}
                className="flex items-center justify-between rounded-lg border border-slate-800 px-3 py-2 text-xs text-slate-300"
              >
                <span className="truncate">
                  {s.url} · <span className="text-emerald-400">{s.cadence}</span>
                </span>
                <button
                  type="button"
                  onClick={() => handleDeleteSchedule(s.id)}
                  className="text-slate-500 hover:text-rose-400"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </li>
            ))}
          </ul>
        </ProCard>

        <ProCard icon={<KeyRound className="h-4 w-4" />} title="REST API Keys">
          <button
            type="button"
            onClick={handleCreateKey}
            disabled={busy}
            className="rounded-lg border border-emerald-500/40 px-4 py-2 text-xs font-semibold text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-60"
          >
            Generate new key
          </button>
          {newKeySecret && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs">
              <p className="text-amber-300">Copy this key now — it won&apos;t be shown again:</p>
              <code className="mt-1 block break-all font-mono text-[11px] text-amber-200">
                {newKeySecret}
              </code>
            </div>
          )}
          <ul className="space-y-2">
            {keys.length === 0 && (
              <li className="text-xs text-slate-500">No API keys yet.</li>
            )}
            {keys.map((k) => (
              <li
                key={k.id}
                className="flex items-center justify-between rounded-lg border border-slate-800 px-3 py-2 text-xs text-slate-300"
              >
                <span className="font-mono">{k.prefix}…</span>
                <button
                  type="button"
                  onClick={() => handleRevokeKey(k.id)}
                  className="text-slate-500 hover:text-rose-400"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </li>
            ))}
          </ul>
          <p className="text-[11px] text-slate-500">
            Use as <code className="text-emerald-400">X-API-Key</code> or bearer
            token against the REST API.
          </p>
        </ProCard>
      </div>
    </section>
  );
}

const inputClass =
  "w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">
        {label}
      </span>
      {children}
    </label>
  );
}

function ProCard({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="glass-panel space-y-4 rounded-3xl border-slate-800 p-6">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white">
        <span className="text-emerald-400">{icon}</span>
        {title}
      </h3>
      {children}
    </div>
  );
}
