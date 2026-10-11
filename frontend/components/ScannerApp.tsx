"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";

import { downloadReport, normalizeUrl, runScan } from "@/lib/api";
import { getSession, signOut } from "@/lib/auth";
import { createClient } from "@/lib/supabase/client";
import type { ScanResponse } from "@/lib/types";
import { AuthModal } from "./AuthModal";
import { ArchitectureSection } from "./ArchitectureSection";
import { DocumentationSection } from "./DocumentationSection";
import { Footer } from "./Footer";
import { Header } from "./Header";
import { PricingSection } from "./PricingSection";
import { ProPanel } from "./ProPanel";
import { ResultsDashboard } from "./ResultsDashboard";
import { ScanHistory } from "./ScanHistory";
import { ScannerHero } from "./ScannerHero";
import { ScanningState } from "./ScanningState";
import { useToast } from "./Toast";

type View = "home" | "scanning" | "results";

const STEPS: { percent: number; text: string }[] = [
  { percent: 15, text: "Auditing HTTP Security Headers & Policies..." },
  { percent: 35, text: "Evaluating SSL/TLS Cryptography & Cert Chains..." },
  { percent: 55, text: "Checking CORS Misconfigurations & API Endpoints..." },
  { percent: 75, text: "Scanning OWASP Top 10 Surface & Open Ports..." },
  { percent: 90, text: "Generating Developer Remediation Matrix..." },
];

export function ScannerApp() {
  const { show } = useToast();
  const [view, setView] = useState<View>("home");
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [scanTarget, setScanTarget] = useState("");
  const [progress, setProgress] = useState(5);
  const [stepText, setStepText] = useState("Initializing VMAXweb core engine...");
  const [session, setSession] = useState<Session | null>(null);
  const [authOpen, setAuthOpen] = useState(false);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [pendingScroll, setPendingScroll] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const supabase = createClient();

  useEffect(() => {
    let active = true;
    getSession().then((s) => {
      if (active) setSession(s);
    });

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event: any, nextSession: any) => {
      setSession(nextSession as Session | null);
    });

    return () => {
      active = false;
      subscription.unsubscribe();
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleScan = useCallback(
    async (rawUrl: string, verificationToken?: string) => {
      const target = normalizeUrl(rawUrl);
      if (!target) return;

      setScanTarget(target);
      setProgress(5);
      setStepText("Initializing VMAXweb core engine...");
      setView("scanning");

      let stepIndex = 0;
      if (intervalRef.current) clearInterval(intervalRef.current);
      intervalRef.current = setInterval(() => {
        if (stepIndex < STEPS.length) {
          const step = STEPS[stepIndex];
          setProgress(step.percent);
          setStepText(step.text);
          stepIndex += 1;
        }
      }, 700);

      try {
        const token = session?.access_token ?? null;
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (token) headers.Authorization = `Bearer ${token}`;

        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://localhost:8000"}/api/v1/scan`,
          {
            method: "POST",
            headers,
            body: JSON.stringify({ url: target, verification_token: verificationToken || null }),
          },
        );

        if (!response.ok) {
          const detail = await response
            .json()
            .then((data) => data?.detail as string | undefined)
            .catch(() => undefined);
          if (intervalRef.current) clearInterval(intervalRef.current);
          setView("home");
          show(detail ?? `Scan failed (HTTP ${response.status})`, "error");
          return;
        }

        const data = (await response.json()) as ScanResponse;
        if (intervalRef.current) clearInterval(intervalRef.current);
        setProgress(100);
        setStepText("Audit Complete! Loading VMAXweb dashboard...");
        setTimeout(() => {
          setResult(data);
          setHistoryRefresh((v) => v + 1);
          setView("results");
        }, 500);
      } catch (error) {
        if (intervalRef.current) clearInterval(intervalRef.current);
        setView("home");
        show(
          error instanceof Error ? error.message : "Scan failed. Please try again.",
          "error",
        );
      }
    },
    [show, session],
  );

  const goHome = useCallback(() => {
    setView("home");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const scrollToSection = useCallback((id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
  }, []);

  const goToSection = useCallback(
    (id: string) => {
      if (view === "home") {
        scrollToSection(id);
      } else {
        setPendingScroll(id);
        setView("home");
      }
    },
    [view, scrollToSection],
  );

  useEffect(() => {
    if (view === "home" && pendingScroll) {
      const timer = setTimeout(() => {
        scrollToSection(pendingScroll);
        setPendingScroll(null);
      }, 60);
      return () => clearTimeout(timer);
    }
  }, [view, pendingScroll, scrollToSection]);

  const goPricing = useCallback(() => {
    goToSection("pricing");
  }, [goToSection]);

  const exportPdf = useCallback(async () => {
    if (!result) return;
    show("Generating VMAXweb PDF Security Audit Report...");
    try {
      const token = session?.access_token ?? null;
      const headers: Record<string, string> = {};
      if (token) headers.Authorization = `Bearer ${token}`;
      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://localhost:8000"}/api/v1/scans/${result.scan_id}/report`,
        { headers },
      );
      if (!response.ok) throw new Error(`PDF export failed (${response.status})`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vmaxweb-audit-${result.target.host}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      show("PDF report downloaded.");
    } catch (error) {
      show(
        error instanceof Error ? error.message : "PDF export failed.",
        "error",
      );
    }
  }, [result, show, session]);

  const handleUpgrade = useCallback(() => {
    goToSection("pro");
    show("Activate Pro from the Pro Console below.");
  }, [goToSection, show]);

  const handleActivePlan = useCallback(() => {
    show("You are currently using the Free Full-Power Plan.");
  }, [show]);

  async function handleSignOut() {
    try {
      await signOut();
      show("Signed out.");
    } catch (error) {
      show(error instanceof Error ? error.message : "Sign out failed.", "error");
    }
  }

  return (
    <div className="flex min-h-screen flex-col justify-between">
      <Header
        onHome={goHome}
        onPricing={goPricing}
        onArchitecture={() => goToSection("architecture")}
        onDocumentation={() => goToSection("documentation")}
        session={session}
        onSignIn={() => setAuthOpen(true)}
        onSignOut={handleSignOut}
      />

      <main className="mx-auto w-full max-w-7xl flex-grow px-4 py-8 sm:px-6 lg:px-8">
        {view === "home" && (
          <div className="space-y-16">
            <ScannerHero onScan={handleScan} busy={false} />
            <ScanHistory accessToken={session?.access_token ?? null} onRefreshSignal={historyRefresh} />
            <ArchitectureSection onOpenPricing={goPricing} />
            <PricingSection onUpgrade={handleUpgrade} onActivePlan={handleActivePlan} />
            <ProPanel accessToken={session?.access_token ?? null} />
            <DocumentationSection />
          </div>
        )}
        {view === "scanning" && (
          <ScanningState
            targetUrl={scanTarget}
            progress={progress}
            stepText={stepText}
          />
        )}
        {view === "results" && result && (
          <ResultsDashboard
            result={result}
            onExportPdf={exportPdf}
            onUpgrade={handleUpgrade}
            onActivePlan={handleActivePlan}
          />
        )}
      </main>

      <Footer />
      <AuthModal open={authOpen} onClose={() => setAuthOpen(false)} />
    </div>
  );
}
