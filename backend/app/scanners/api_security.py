"""Module 3 - API & Endpoint Security (CORS, HTTP methods)."""

from __future__ import annotations

from app.models import Finding, Severity
from app.scanners.base import BaseScanner, ScanContext

_PROBE_ORIGIN = "https://vmax-probe.example"
_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


class ApiSecurityScanner(BaseScanner):
    id = "api"
    module = "API & Cross-Origin Security"
    title = "API & Endpoint Security Audit"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.append(await self._check_cors(ctx))
        findings.append(await self._check_methods(ctx))
        return findings

    async def _check_cors(self, ctx: ScanContext) -> Finding:
        headers = {"Origin": _PROBE_ORIGIN}
        response = None
        try:
            response = await ctx.client.options(ctx.target.url, headers=headers)
        except Exception:  # noqa: BLE001 - fall back to a GET probe below
            response = None

        lowered = {k.lower(): v for k, v in response.headers.items()} if response else {}
        if not lowered.get("access-control-allow-origin"):
            try:
                get_response = await ctx.client.get(ctx.target.url, headers=headers)
            except Exception as exc:  # noqa: BLE001
                return self.result(
                    id="cors",
                    name="CORS Policy Check",
                    severity=Severity.INFO,
                    status="Endpoint unreachable",
                    summary="The endpoint did not answer the CORS probe.",
                    explanation=(
                        "CORS misconfiguration is only relevant when cross-origin calls "
                        "are allowed."
                    ),
                    fix_snippet=(
                        "app.add_middleware(CORSMiddleware, "
                        "allow_origins=['https://app.example.com'])"
                    ),
                    meta={"error": str(exc)},
                )
            lowered = {k.lower(): v for k, v in get_response.headers.items()}

        allow_origin = lowered.get("access-control-allow-origin", "")
        allow_credentials = lowered.get("access-control-allow-credentials", "").lower() == "true"

        if allow_origin == "*" and allow_credentials:
            severity, status = Severity.CRITICAL, "Wildcard with credentials"
            summary = "CORS allows any origin while sending credentials."
        elif allow_origin == "*":
            severity, status = Severity.WARNING, "Overly Permissive (*)"
            summary = "CORS allows any origin to read responses."
        elif allow_origin == _PROBE_ORIGIN:
            severity = Severity.CRITICAL if allow_credentials else Severity.WARNING
            status = "Arbitrary origin reflected"
            summary = "CORS reflects arbitrary Origin headers, allowing cross-domain reads."
        elif allow_origin:
            severity, status = Severity.PASSED, f"Restricted to {allow_origin}"
            summary = "CORS is restricted to an explicit allow-list."
        else:
            severity, status = Severity.PASSED, "Not enabled"
            summary = "No CORS headers are returned for external origins."

        return self.result(
            id="cors",
            name="CORS Policy Check",
            severity=severity,
            status=status,
            summary=summary,
            explanation=(
                "A permissive Access-Control-Allow-Origin combined with credentials lets "
                "malicious sites perform authenticated cross-origin requests on behalf "
                "of logged-in users."
            ),
            fix_snippet=(
                "# FastAPI\nfrom fastapi.middleware.cors import CORSMiddleware\n\n"
                "app.add_middleware(\n    CORSMiddleware,\n"
                "    allow_origins=[\"https://your-official-domain.com\"],\n"
                "    allow_credentials=True,\n    allow_methods=[\"GET\", \"POST\"],\n)"
            ),
            meta={
                "allow_origin": allow_origin,
                "allow_credentials": allow_credentials,
            },
        )

    async def _check_methods(self, ctx: ScanContext) -> Finding:
        try:
            response = await ctx.client.options(ctx.target.url)
        except Exception as exc:  # noqa: BLE001
            return self.result(
                id="http_methods",
                name="HTTP Methods Assessment",
                severity=Severity.INFO,
                status="OPTIONS unavailable",
                summary="Could not enumerate allowed HTTP methods.",
                explanation="Some servers do not answer OPTIONS requests.",
                fix_snippet="# Restrict methods at the reverse proxy.",
                meta={"error": str(exc)},
            )

        allow = response.headers.get("allow") or response.headers.get("access-control-allow-methods", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = sorted(methods & _DANGEROUS_METHODS)

        if not methods:
            return self.result(
                id="http_methods",
                name="HTTP Methods Assessment",
                severity=Severity.PASSED,
                status="No Allow header exposed",
                summary="The server does not advertise enabled methods.",
                explanation="Hiding the method list reduces attacker reconnaissance.",
                fix_snippet="# Optionally disable TRACE at the proxy.",
            )

        if risky:
            severity, status = Severity.WARNING, f"Risky methods: {', '.join(risky)}"
            summary = "Potentially dangerous HTTP methods are advertised."
        else:
            severity, status = Severity.PASSED, f"Allowed: {', '.join(sorted(methods))}"
            summary = "Only safe HTTP methods are advertised."

        return self.result(
            id="http_methods",
            name="HTTP Methods Assessment",
            severity=severity,
            status=status,
            summary=summary,
            explanation=(
                "Methods such as PUT/DELETE can allow unauthorized write operations, "
                "and TRACE can enable Cross-Site Tracing (XST)."
            ),
            fix_snippet="# Nginx\nif ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }",
            meta={"allowed": sorted(methods), "risky": risky},
        )
