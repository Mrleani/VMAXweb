"""Module 1 - HTTP Security Headers & Information Disclosure."""

from __future__ import annotations

import re

from app.models import Confidence, Finding, Severity
from app.scanners.base import BaseScanner, ScanContext

_VERSION_PATTERN = re.compile(r"\d+\.\d+")


class HeaderScanner(BaseScanner):
    id = "headers"
    module = "HTTP Security Headers"
    title = "HTTP Security Headers & Information Disclosure"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        response = await ctx.client.get(ctx.target.url)
        headers = {k.lower(): v for k, v in response.headers.items()}
        content_type = headers.get("content-type", "").lower()
        is_html = "text/html" in content_type or "application/xhtml" in content_type
        findings: list[Finding] = []
        is_https = ctx.target.scheme == "https"

        findings.append(self._check_hsts(headers, is_https))
        findings.append(self._check_csp(headers, is_html))
        findings.append(self._check_x_frame_options(headers))
        findings.append(self._check_nosniff(headers))
        findings.append(self._check_referrer_policy(headers))
        findings.append(self._check_permissions_policy(headers))
        findings.append(self._check_coop(headers))
        findings.append(self._check_corp(headers))
        findings.extend(self._check_info_disclosure(headers))
        return findings

    # -- individual checks ----------------------------------------------
    def _check_hsts(self, headers: dict[str, str], is_https: bool) -> Finding:
        value = headers.get("strict-transport-security")
        if value:
            meta = self._hsts_meta(value)
            insecure = meta["max_age"] < 15552000 or not meta["include_subdomains"]
            return self.result(
                id="hsts",
                name="Strict-Transport-Security (HSTS)",
                severity=Severity.WARNING if insecure else Severity.PASSED,
                status=value if not insecure else "Weak Policy",
                summary=(
                    "HSTS is present but max-age is short or subdomains are not covered."
                    if insecure
                    else "HSTS is enforced with a long max-age."
                ),
                explanation=(
                    "HSTS prevents downgrade attacks (HTTP instead of HTTPS) and cookie "
                    "hijacking. Without a strong policy, attackers can intercept user "
                    "sessions via Man-in-the-Middle (MITM) attacks."
                ),
                fix_snippet=(
                    '# Nginx\nadd_header Strict-Transport-Security '
                    '"max-age=31536000; includeSubDomains; preload" always;'
                ),
                meta=meta,
            )

        if not is_https:
            return self.result(
                id="hsts",
                name="Strict-Transport-Security (HSTS)",
                severity=Severity.WARNING,
                status="N/A - Target is HTTP",
                summary="HSTS is only effective over HTTPS; serve the site over TLS.",
                explanation=(
                    "HSTS is ignored on plain HTTP responses. Move the target to HTTPS "
                    "and then enforce HSTS."
                ),
                fix_snippet="# Enable TLS termination before setting HSTS.",
            )

        return self.result(
            id="hsts",
            name="Strict-Transport-Security (HSTS)",
            severity=Severity.CRITICAL,
            status="Missing Header",
            summary="HSTS header is not enforced on the domain.",
            explanation=(
                "HSTS prevents downgrade attacks and cookie hijacking. Without this "
                "header, attackers can intercept user sessions via MITM attacks."
            ),
            fix_snippet=(
                '# Nginx\nadd_header Strict-Transport-Security '
                '"max-age=31536000; includeSubDomains" always;'
            ),
        )

    @staticmethod
    def _hsts_meta(value: str) -> dict:
        max_age = 0
        match = re.search(r"max-age=(\d+)", value)
        if match:
            max_age = int(match.group(1))
        return {
            "raw": value,
            "max_age": max_age,
            "include_subdomains": "includesubdomains" in value.lower(),
            "preload": "preload" in value.lower(),
        }

    def _check_csp(self, headers: dict[str, str], is_html: bool) -> Finding:
        value = headers.get("content-security-policy")
        if value:
            weak = "unsafe-inline" in value.lower() or "unsafe-eval" in value.lower()
            return self.result(
                id="csp",
                name="Content-Security-Policy (CSP)",
                severity=Severity.WARNING if weak else Severity.PASSED,
                status="Uses unsafe-inline/unsafe-eval" if weak else "Configured Securely",
                summary=(
                    "CSP allows unsafe inline/eval directives."
                    if weak
                    else "CSP restricts resource loading."
                ),
                explanation=(
                    "CSP protects against Cross-Site Scripting (XSS) and data injection "
                    "attacks by restricting which resources may execute."
                ),
                fix_snippet=(
                    "Content-Security-Policy: default-src 'self'; "
                    "script-src 'self'; object-src 'none'; base-uri 'self';"
                ),
                meta={"raw": value},
            )
        if not is_html:
            return self.result(
                id="csp",
                name="Content-Security-Policy (CSP)",
                severity=Severity.PASSED,
                status="N/A (non-HTML response)",
                summary="No HTML is served at this endpoint, so CSP is not applicable.",
                explanation=(
                    "CSP only mitigates script execution in HTML documents. JSON/API "
                    "responses are not affected."
                ),
                fix_snippet=(
                    "Content-Security-Policy: default-src 'self'; script-src 'self';"
                ),
                meta={"content_type": "non-html"},
            )
        return self.result(
            id="csp",
            name="Content-Security-Policy (CSP)",
            severity=Severity.WARNING,
            status="Missing Header",
            summary="No CSP header; the browser has no XSS mitigation policy.",
            explanation=(
                "Without CSP, any injected inline script executes with full page "
                "privileges, widening the blast radius of an XSS vulnerability."
            ),
            fix_snippet=(
                "Content-Security-Policy: default-src 'self'; "
                "script-src 'self'; object-src 'none'; frame-ancestors 'self';"
            ),
        )

    def _check_x_frame_options(self, headers: dict[str, str]) -> Finding:
        xfo = headers.get("x-frame-options")
        csp = headers.get("content-security-policy", "")
        if xfo:
            return self.result(
                id="x_frame_options",
                name="X-Frame-Options (Clickjacking)",
                severity=Severity.PASSED,
                status=f"{xfo} Enforced",
                summary="Prevents the domain from being framed in external iFrames.",
                explanation=(
                    "Protects users against Clickjacking attacks where attackers overlay "
                    "invisible frames over the page."
                ),
                fix_snippet="X-Frame-Options: SAMEORIGIN",
            )
        if "frame-ancestors" in csp.lower():
            return self.result(
                id="x_frame_options",
                name="X-Frame-Options (Clickjacking)",
                severity=Severity.PASSED,
                status="Covered by CSP frame-ancestors",
                summary="Framing is restricted via the CSP frame-ancestors directive.",
                explanation="Modern equivalents: CSP frame-ancestors supersedes X-Frame-Options.",
                fix_snippet="Content-Security-Policy: frame-ancestors 'self';",
            )
        return self.result(
            id="x_frame_options",
            name="X-Frame-Options (Clickjacking)",
            severity=Severity.WARNING,
            status="Missing Header",
            summary="Page can be embedded in third-party iFrames.",
            explanation=(
                "Missing frame protection enables Clickjacking: attackers overlay an "
                "invisible frame so users unknowingly trigger actions."
            ),
            fix_snippet="X-Frame-Options: SAMEORIGIN",
        )

    def _check_nosniff(self, headers: dict[str, str]) -> Finding:
        value = headers.get("x-content-type-options", "")
        if value.strip().lower() == "nosniff":
            return self.result(
                id="nosniff",
                name="X-Content-Type-Options (nosniff)",
                severity=Severity.PASSED,
                status="nosniff Enforced",
                summary="Browsers will not MIME-sniff responses.",
                explanation="Prevents MIME confusion attacks that can turn uploads into scripts.",
                fix_snippet="X-Content-Type-Options: nosniff",
            )
        return self.result(
            id="nosniff",
            name="X-Content-Type-Options (nosniff)",
            severity=Severity.WARNING,
            status="Missing Header",
            summary="MIME-sniffing is not disabled.",
            explanation=(
                "Without nosniff, browsers may interpret a file as a different type, "
                "enabling content-sniffing XSS attacks."
            ),
            fix_snippet="X-Content-Type-Options: nosniff",
        )

    def _check_referrer_policy(self, headers: dict[str, str]) -> Finding:
        value = headers.get("referrer-policy", "")
        if value:
            return self.result(
                id="referrer_policy",
                name="Referrer-Policy",
                severity=Severity.PASSED,
                status=value,
                summary="Referrer leakage is controlled.",
                explanation="Limits how much referrer information is sent to other origins.",
                fix_snippet="Referrer-Policy: strict-origin-when-cross-origin",
            )
        return self.result(
            id="referrer_policy",
            name="Referrer-Policy",
            severity=Severity.WARNING,
            status="Missing Header",
            summary="Full URLs may leak to third parties via the Referer header.",
            explanation=(
                "Without a Referrer-Policy, sensitive URL paths can leak to external "
                "sites and analytics providers."
            ),
            fix_snippet="Referrer-Policy: strict-origin-when-cross-origin",
        )

    def _check_permissions_policy(self, headers: dict[str, str]) -> Finding:
        value = headers.get("permissions-policy") or headers.get("feature-policy")
        if value:
            return self.result(
                id="permissions_policy",
                name="Permissions-Policy",
                severity=Severity.PASSED,
                status="Configured",
                summary="Powerful browser features are explicitly scoped.",
                explanation="Restricts access to camera, microphone, geolocation and similar APIs.",
                fix_snippet="Permissions-Policy: geolocation=(), camera=(), microphone=()",
            )
        return self.result(
            id="permissions_policy",
            name="Permissions-Policy",
            severity=Severity.INFO,
            status="Missing Header",
            summary="Sensitive browser features are not explicitly restricted.",
            explanation=(
                "Defining a Permissions-Policy reduces the impact of compromised "
                "third-party scripts."
            ),
            fix_snippet="Permissions-Policy: geolocation=(), camera=(), microphone=()",
        )

    def _check_coop(self, headers: dict[str, str]) -> Finding:
        value = headers.get("cross-origin-opener-policy", "")
        if value:
            return self.result(
                id="coop",
                name="Cross-Origin-Opener-Policy (COOP)",
                severity=Severity.PASSED,
                status=value,
                summary="Browsing contexts are isolated from cross-origin windows.",
                explanation=(
                    "COOP isolates your window from cross-origin openers, blocking "
                    "cross-window attacks such as Spectre-style leaks and tab-nabbing."
                ),
                fix_snippet="Cross-Origin-Opener-Policy: same-origin",
            )
        return self.result(
            id="coop",
            name="Cross-Origin-Opener-Policy (COOP)",
            severity=Severity.INFO,
            status="Missing Header",
            summary="Cross-origin window isolation is not enforced.",
            explanation=(
                "Without COOP, a cross-origin page that opened your tab keeps a live "
                "reference to it, enabling certain side-channel and clickjacking attacks."
            ),
            fix_snippet="Cross-Origin-Opener-Policy: same-origin",
        )

    def _check_corp(self, headers: dict[str, str]) -> Finding:
        value = headers.get("cross-origin-resource-policy", "")
        if value:
            return self.result(
                id="corp",
                name="Cross-Origin-Resource-Policy (CORP)",
                severity=Severity.PASSED,
                status=value,
                summary="Cross-origin resource embedding is explicitly restricted.",
                explanation=(
                    "CORP prevents other sites from embedding your resources, mitigating "
                    "cross-origin data leaks (e.g. Spectre, XS-Leaks)."
                ),
                fix_snippet="Cross-Origin-Resource-Policy: same-origin",
            )
        return self.result(
            id="corp",
            name="Cross-Origin-Resource-Policy (CORP)",
            severity=Severity.INFO,
            status="Missing Header",
            summary="Resources can be embedded by any origin.",
            explanation=(
                "Without CORP, other origins may load your responses, which can leak "
                "data through cross-origin side channels."
            ),
            fix_snippet="Cross-Origin-Resource-Policy: same-origin",
        )

    def _check_info_disclosure(self, headers: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []

        server = headers.get("server", "")
        if server and _VERSION_PATTERN.search(server):
            findings.append(
                self.result(
                    id="server_version",
                    name="Server Version Exposure",
                    severity=Severity.WARNING,
                    status=f"Discloses '{server}'",
                    summary="Server banner reveals the exact software version.",
                    explanation=(
                        "Revealing exact server versions lets attackers map known CVEs "
                        "for your web server and OS build."
                    ),
                    fix_snippet="# Nginx\nserver_tokens off;",
                    meta={"server": server},
                    confidence=Confidence.HIGH,
                )
            )
        elif server:
            findings.append(
                self.result(
                    id="server_version",
                    name="Server Version Exposure",
                    severity=Severity.PASSED,
                    status="No version disclosed",
                    summary="Server banner does not expose a version.",
                    explanation="Minimal server banners reduce reconnaissance value.",
                    fix_snippet="# Nginx\nserver_tokens off;",
                )
            )

        for header_name in ("x-powered-by", "x-aspnet-version", "x-generator"):
            if header_name in headers:
                findings.append(
                    self.result(
                        id=header_name.replace("-", "_"),
                        name=f"Technology Disclosure ({header_name})",
                        severity=Severity.WARNING,
                        status=f"Present: {headers[header_name]}",
                        summary=f"The '{header_name}' header leaks the technology stack.",
                        explanation=(
                            "Framework fingerprinting speeds up targeted attacks against "
                            "known stack vulnerabilities."
                        ),
                        fix_snippet=(
                            "# Nginx\nproxy_hide_header X-Powered-By;\n"
                            "# Express.js\napp.disable('x-powered-by');"
                        ),
                        meta={"value": headers[header_name]},
                    )
                )

        return findings
