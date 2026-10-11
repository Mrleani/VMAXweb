"""Scan orchestration: run all six modules concurrently and aggregate."""

from __future__ import annotations

import asyncio
import time

import httpx

from app import __version__
from app.core.config import get_settings
from app.core.safety import assert_resolves_safely, normalize_target
from app.models import SEVERITY_ORDER, Finding, ScanResult, Severity
from app.scanners import SCANNER_REGISTRY
from app.scanners.base import BaseScanner, ModuleReport, ScanContext
from app.scoring import grade_for, score_findings


class ScanEngine:
    async def run(self, raw_url: str, *, verified: bool = False) -> ScanResult:
        settings = get_settings()
        target = normalize_target(raw_url)
        await assert_resolves_safely(target.host)

        started_at = ScanResult.utc_now()
        start = time.perf_counter()

        headers = {"User-Agent": settings.user_agent, "Accept": "*/*"}
        timeout = httpx.Timeout(settings.request_timeout)
        limits = httpx.Limits(max_connections=settings.max_concurrency)

        async with httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            limits=limits,
            follow_redirects=True,
            verify=True,
        ) as client:
            ctx = ScanContext(target=target, client=client, settings=settings)
            scanners = [scanner_cls() for scanner_cls in SCANNER_REGISTRY]
            reports = await asyncio.gather(
                *(self._run_scanner(scanner, ctx, verified, settings) for scanner in scanners)
            )

        findings = self._merge(reports)
        score = score_findings(findings)
        grade, grade_label = grade_for(score)
        finished_at = ScanResult.utc_now()

        return ScanResult(
            target=target,
            score=score,
            grade=grade,
            grade_label=grade_label,
            findings=findings,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=int((time.perf_counter() - start) * 1000),
            engine_version=__version__,
        )

    async def _run_scanner(
        self,
        scanner: BaseScanner,
        ctx: ScanContext,
        verified: bool,
        settings,
    ) -> ModuleReport:
        if (
            scanner.requires_verified_target
            and settings.require_verified_target
            and not verified
        ):
            return ModuleReport(
                scanner_id=scanner.id,
                findings=[
                    scanner.result(
                        id="verification_required",
                        name=f"{scanner.title} - Verification Required",
                        severity=Severity.INFO,
                        status="Skipped (target not verified)",
                        summary=(
                            "Active checks require proven domain ownership. Verify the "
                            "target via a DNS TXT token to enable this module."
                        ),
                        explanation=(
                            "Ownership verification keeps VMAXweb from being abused to "
                            "probe systems you do not control."
                        ),
                        fix_snippet="# Add a TXT record: vmax-verify=<token> and re-run.",
                    )
                ],
            )

        try:
            findings = await scanner.scan(ctx)
            return ModuleReport(scanner_id=scanner.id, findings=findings)
        except Exception as exc:  # noqa: BLE001 - isolate module failures
            return ModuleReport(scanner_id=scanner.id, error=f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _merge(reports: list[ModuleReport]) -> list[Finding]:
        findings: list[Finding] = []
        for report in reports:
            if report.error:
                findings.append(
                    Finding(
                        id=f"{report.scanner_id}.error",
                        module="Engine",
                        name=f"Scanner '{report.scanner_id}' failed",
                        severity=Severity.INFO,
                        status="Module Error",
                        summary="This module could not complete and was skipped.",
                        explanation="Partial results are shown; re-run the audit to retry.",
                        confidence="high",
                        meta={"error": report.error},
                    )
                )
            findings.extend(report.findings)

        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
        return findings
