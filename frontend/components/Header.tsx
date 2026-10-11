"use client";

import { LogIn, LogOut, User } from "lucide-react";
import { useToast } from "./Toast";

interface HeaderProps {
  onHome: () => void;
  onPricing: () => void;
  session: any | null;
  onSignIn: () => void;
  onSignOut: () => void;
}

export function Header({ onHome, onPricing, session, onSignIn, onSignOut }: HeaderProps) {
  const { show } = useToast();

  const navClass = "hover:text-emerald-400 transition-colors";

  return (
    <header className="no-print sticky top-0 z-50 border-b border-slate-800/80 bg-brand-dark/90 backdrop-blur-md">
      <div className="mx-auto flex h-20 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        <button
          type="button"
          onClick={onHome}
          className="flex items-center gap-3 text-left"
        >
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-400 to-cyan-500 text-xl font-bold text-brand-dark shadow-lg shadow-emerald-500/20">
            🍐
          </span>
          <span>
            <span className="flex items-center gap-2">
              <span className="bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-xl font-extrabold tracking-tight text-transparent">
                VMAXweb
              </span>
              <span className="rounded-full border border-emerald-500/20 bg-slate-800 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-emerald-400">
                by StarNet
              </span>
            </span>
            <span className="hidden text-xs font-medium text-slate-400 sm:block">
              Maximum Web &amp; API Security Engine
            </span>
          </span>
        </button>

        <nav className="hidden items-center gap-8 text-sm font-medium text-slate-300 md:flex">
          <button type="button" onClick={onHome} className={navClass}>
            Scanner
          </button>
          <button
            type="button"
            onClick={() =>
              show("Architecture Docs: Python FastAPI Engine & Next.js UI")
            }
            className={navClass}
          >
            Architecture
          </button>
          <button type="button" onClick={onPricing} className={navClass}>
            Pricing &amp; Plans
          </button>
          <button
            type="button"
            onClick={() =>
              show("Documentation: OWASP Top 10 Security Audit Guidelines")
            }
            className={navClass}
          >
            Documentation
          </button>
        </nav>

        <div className="flex items-center gap-3">
          <span className="hidden items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-400 sm:flex">
            <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
            Engine: Operational
          </span>
          {session ? (
            <>
              <span className="hidden items-center gap-1.5 rounded-full border border-slate-800 bg-slate-900/80 px-2.5 py-1.5 text-[11px] text-slate-400 md:flex">
                <User className="h-3.5 w-3.5" />
                {session.user.email ?? "Signed in"}
              </span>
              <button
                type="button"
                onClick={onSignOut}
                className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 transition-all hover:bg-slate-700"
              >
                <LogOut className="h-3.5 w-3.5" />
                Sign out
              </button>
            </>
          ) : (
            <button
              type="button"
              onClick={onSignIn}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-300 transition-all hover:bg-slate-700"
            >
              <LogIn className="h-3.5 w-3.5" />
              Sign in
            </button>
          )}
          <button
            type="button"
            onClick={onPricing}
            className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-semibold text-white transition-all hover:bg-slate-700"
          >
            Upgrade Pro
          </button>
        </div>
      </div>
    </header>
  );
}
