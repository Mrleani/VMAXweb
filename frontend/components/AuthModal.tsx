"use client";

import { Mail, ShieldCheck, X, Lock, UserPlus } from "lucide-react";
import { FormEvent, useState } from "react";

import { signInWithMagicLink, signUpWithPassword, signInWithPassword } from "@/lib/auth";
import { useToast } from "./Toast";

type AuthMode = "magic" | "signup" | "login";

interface AuthModalProps {
  open: boolean;
  onClose: () => void;
}

export function AuthModal({ open, onClose }: AuthModalProps) {
  const { show } = useToast();
  const [mode, setMode] = useState<AuthMode>("magic");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);

  if (!open) return null;

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    try {
      if (mode === "magic") {
        await signInWithMagicLink(email.trim());
        show("Magic link sent. Check your email to continue.");
      } else if (mode === "signup") {
        if (password !== confirmPassword) throw new Error("Passwords do not match");
        if (password.length < 8) throw new Error("Password must be at least 8 characters");
        await signUpWithPassword(email.trim(), password);
        show("Account created. Check your email to confirm, then sign in.");
        setMode("login");
      } else {
        await signInWithPassword(email.trim(), password);
        show("Signed in successfully.");
        onClose();
      }
    } catch (error) {
      show(error instanceof Error ? error.message : "Authentication failed.", "error");
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
            <h3 className="text-lg font-bold text-white">
              {mode === "magic" ? "Sign in to VMAXweb" : mode === "signup" ? "Create Account" : "Sign In"}
            </h3>
            <p className="text-xs text-slate-400">
              {mode === "magic"
                ? "Access scan history, PDF exports & plan limits."
                : mode === "signup"
                ? "Register with email and password."
                : "Enter your credentials."}
            </p>
          </div>
        </div>
        <div className="mb-4 flex gap-1 rounded-lg bg-slate-900/50 p-1">
          {(["magic", "signup", "login"] as AuthMode[]).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={`flex-1 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors ${
                mode === m
                  ? "bg-emerald-500/20 text-emerald-300"
                  : "text-slate-500 hover:text-slate-300"
              }`}
            >
              {m === "magic" ? "Magic Link" : m === "signup" ? "Sign Up" : "Sign In"}
            </button>
          ))}
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
              autoComplete="email"
              className="w-full bg-transparent py-3 text-sm text-white placeholder-slate-600 focus:outline-none"
            />
          </div>
          {(mode === "signup" || mode === "login") && (
            <div className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/70 px-3">
              <Lock className="h-4 w-4 text-slate-500" />
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder={mode === "signup" ? "Create password (min 8 chars)" : "Password"}
                required
                autoComplete={mode === "signup" ? "new-password" : "current-password"}
                className="w-full bg-transparent py-3 text-sm text-white placeholder-slate-600 focus:outline-none"
              />
            </div>
          )}
          {mode === "signup" && (
            <div className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-900/70 px-3">
              <Lock className="h-4 w-4 text-slate-500" />
              <input
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                placeholder="Confirm password"
                required
                autoComplete="new-password"
                className="w-full bg-transparent py-3 text-sm text-white placeholder-slate-600 focus:outline-none"
              />
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 py-3 text-sm font-bold text-brand-dark shadow-lg shadow-emerald-500/20 transition-all hover:from-emerald-400 hover:to-teal-500 disabled:opacity-60"
          >
            {loading
              ? "Please wait..."
              : mode === "magic"
              ? "Send Magic Link"
              : mode === "signup"
              ? "Create Account"
              : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}