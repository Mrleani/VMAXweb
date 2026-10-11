"use client";

import { Mail, ShieldCheck, X } from "lucide-react";
import { FormEvent, useState } from "react";

import { signInWithMagicLink } from "@/lib/auth";
import { useToast } from "./Toast";

interface AuthModalProps {
  open: boolean;
  onClose: () => void;
}

export function AuthModal({ open, onClose }: AuthModalProps) {
  const { show } = useToast();
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  if (!open) return null;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    try {
      await signInWithMagicLink(email.trim());
      show(
        "Magic link sent. Check your email to continue. (Dev: open Supabase auth email).",
      );
      onClose();
    } catch (error) {
      show(
        error instanceof Error ? error.message : "Sign in failed.",
        "error",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-brand-dark/80 backdrop-blur-sm">
      <div className="glass-panel relative w-full max-w-md rounded-2xl border-slate-800 p-6">
        <button
          type="button"
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-500 transition-colors hover:text-slate-300"
        >
          <X className="h-4 w-4" />
        </button>
        <div className="mb-4 flex items-center gap-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-400 to-cyan-500 text-brand-dark">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Sign in to VMAXweb</h3>
            <p className="text-xs text-slate-400">
              Access scan history, PDF exports &amp; plan limits.
            </p>
          </div>
        </div>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/70 px-3">
            <Mail className="h-4 w-4 text-slate-500" />
            <input
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@company.com"
              required
              className="w-full bg-transparent py-3 text-sm text-white placeholder-slate-600 focus:outline-none"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 py-3 text-sm font-bold text-brand-dark shadow-lg shadow-emerald-500/20 transition-all hover:from-emerald-400 hover:to-teal-500 disabled:opacity-60"
          >
            {loading ? "Sending..." : "Send Magic Link"}
          </button>
        </form>
      </div>
    </div>
  );
}
