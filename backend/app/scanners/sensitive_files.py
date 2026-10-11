"""Module 4 - Sensitive Data Exposure & OWASP checks."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from app.models import Confidence, Finding, Severity
from app.scanners.base import BaseScanner, ScanContext


@dataclass(frozen=True)
class SensitivePath:
    id: str
    path: str
    name: str
    severity: Severity
    explanation: str
    fix_snippet: str
    markers: tuple[str, ...] = ()


SENSITIVE_PATHS: tuple[SensitivePath, ...] = (
    SensitivePath(
        id="dotenv",
        path="/.env",
        name="Exposed .env File",
        severity=Severity.CRITICAL,
        explanation=(
            "The .env file holds database passwords, API keys and signing secrets. "
            "Public access is a full credential compromise."
        ),
        fix_snippet="location ~ /\\.env { deny all; return 404; }",
        markers=("=", "SECRET", "KEY", "PASSWORD"),
    ),
    SensitivePath(
        id="git_config",
        path="/.git/config",
        name="Exposed .git Repository",
        severity=Severity.CRITICAL,
        explanation=(
            "A public .git directory lets attackers download the entire source "
            "history, including secrets removed from the working tree."
        ),
        fix_snippet="location ~ /\\.git { deny all; return 404; }",
        markers=("[core]", "repositoryformatversion"),
    ),
    SensitivePath(
        id="config_json",
        path="/config.json",
        name="Exposed config.json",
        severity=Severity.CRITICAL,
        explanation="Configuration files frequently contain credentials and internal endpoints.",
        fix_snippet="location = /config.json { deny all; }",
        markers=("{", "}"),
    ),
    SensitivePath(
        id="swagger",
        path="/swagger.json",
        name="Exposed API Schema (swagger.json)",
        severity=Severity.WARNING,
        explanation=(
            "A public API schema maps every endpoint, easing targeted API attacks."
        ),
        fix_snippet="# Require authentication or disable in production.",
        markers=("swagger", "openapi", "paths"),
    ),
    SensitivePath(
        id="openapi",
        path="/openapi.json",
        name="Exposed API Schema (openapi.json)",
        severity=Severity.WARNING,
        explanation="A public OpenAPI document exposes the full API surface.",
        fix_snippet="app = FastAPI(openapi_url=None)  # disable public schema",
        markers=("openapi", "paths"),
    ),
    SensitivePath(
        id="backup",
        path="/backup.zip",
        name="Exposed Backup Archive",
        severity=Severity.CRITICAL,
        explanation="Backup archives often contain full database dumps and source code.",
        fix_snippet="location ~* \\.(zip|tar|gz|sql|bak)$ { deny all; }",
    ),
    SensitivePath(
        id="db_sql",
        path="/db.sql",
        name="Exposed Database Dump",
        severity=Severity.CRITICAL,
        explanation="A downloadable SQL dump exposes all application data.",
        fix_snippet="location ~* \\.sql$ { deny all; }",
        markers=("INSERT INTO", "CREATE TABLE"),
    ),
    SensitivePath(
        id="server_status",
        path="/server-status",
        name="Exposed Apache server-status",
        severity=Severity.WARNING,
        explanation="server-status leaks internal requests, client IPs and server load.",
        fix_snippet="<Location /server-status>\n    Require local\n</Location>",
        markers=("Apache Server Status", "server-status"),
    ),
)


class SensitiveFileScanner(BaseScanner):
    id = "sensitive_files"
    module = "Vulnerability & Asset Check"
    title = "Sensitive Data Exposure & OWASP Check"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        baseline = await self._baseline_status(ctx)
        findings: list[Finding] = []

        for spec in SENSITIVE_PATHS:
            findings.append(await self._check_path(ctx, spec, baseline))

        findings.append(await self._check_cookies(ctx))
        return findings

    async def _baseline_status(self, ctx: ScanContext) -> int | None:
        random_path = f"/{secrets.token_hex(8)}"
        try:
            response = await ctx.client.get(f"{ctx.target.origin}{random_path}")
        except Exception:  # noqa: BLE001
            return None
        return response.status_code

    async def _check_path(
        self, ctx: ScanContext, spec: SensitivePath, baseline: int | None
    ) -> Finding:
        url = f"{ctx.target.origin}{spec.path}"
        try:
            response = await ctx.client.get(url)
        except Exception as exc:  # noqa: BLE001
            return self.result(
                id=spec.id,
                name=spec.name,
                severity=Severity.PASSED,
                status="Not reachable",
                summary="The path could not be retrieved.",
                explanation=spec.explanation,
                fix_snippet=spec.fix_snippet,
                confidence=Confidence.LOW,
                meta={"error": str(exc)},
            )

        body = response.text[:5000]
        # A 200 that matches the random-path baseline is usually a soft-404.
        soft_404 = baseline == response.status_code == 200 and self._looks_like_markerless(body, spec)

        if response.status_code == 200 and not soft_404:
            return self.result(
                id=spec.id,
                name=spec.name,
                severity=spec.severity,
                status="Publicly accessible (HTTP 200)",
                summary=f"{spec.path} is readable without authentication.",
                explanation=spec.explanation,
                fix_snippet=spec.fix_snippet,
                meta={"path": spec.path, "bytes": len(response.content)},
            )

        return self.result(
            id=spec.id,
            name=spec.name,
            severity=Severity.PASSED,
            status=f"Not accessible (HTTP {response.status_code})",
            summary=f"{spec.path} is not publicly exposed.",
            explanation=spec.explanation,
            fix_snippet=spec.fix_snippet,
            meta={"path": spec.path},
        )

    @staticmethod
    def _looks_like_markerless(body: str, spec: SensitivePath) -> bool:
        if not spec.markers:
            return True
        lowered = body.lower()
        return not any(marker.lower() in lowered for marker in spec.markers)

    async def _check_cookies(self, ctx: ScanContext) -> Finding:
        try:
            response = await ctx.client.get(ctx.target.url)
        except Exception as exc:  # noqa: BLE001
            return self.result(
                id="cookie_flags",
                name="Cookie Security Flags",
                severity=Severity.INFO,
                status="Unavailable",
                summary="Could not inspect cookies.",
                explanation="Session cookies should carry Secure, HttpOnly and SameSite.",
                fix_snippet="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
                confidence=Confidence.LOW,
                meta={"error": str(exc)},
            )

        cookies = response.headers.get_list("set-cookie")
        if not cookies:
            return self.result(
                id="cookie_flags",
                name="Cookie Security Flags",
                severity=Severity.PASSED,
                status="No cookies set",
                summary="No cookies were issued on the landing response.",
                explanation="Nothing to protect when no session cookie is set here.",
                fix_snippet="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
            )

        missing: dict[str, list[str]] = {}
        for raw in cookies:
            name = raw.split("=", 1)[0].strip()
            lowered = raw.lower()
            absent = []
            if "secure" not in lowered:
                absent.append("Secure")
            if "httponly" not in lowered:
                absent.append("HttpOnly")
            if "samesite" not in lowered:
                absent.append("SameSite")
            if absent:
                missing[name] = absent

        if missing:
            detail = "; ".join(f"{name}: missing {', '.join(flags)}" for name, flags in missing.items())
            return self.result(
                id="cookie_flags",
                name="Cookie Security Flags",
                severity=Severity.WARNING,
                status="Missing flags",
                summary=detail,
                explanation=(
                    "Without Secure/HttpOnly/SameSite, cookies are exposed to network "
                    "sniffing, XSS theft and CSRF."
                ),
                fix_snippet="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
                meta={"missing": missing},
            )

        return self.result(
            id="cookie_flags",
            name="Cookie Security Flags",
            severity=Severity.PASSED,
            status="All flags present",
            summary="All cookies set Secure, HttpOnly and SameSite.",
            explanation="Cookie theft and CSRF risk is minimized.",
            fix_snippet="Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
        )
