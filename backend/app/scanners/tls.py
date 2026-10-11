"""Module 2 - SSL/TLS Cryptography & Transport Security."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.models import Confidence, Finding, Severity
from app.scanners.base import BaseScanner, ScanContext

_MODERN_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}
_EXPIRY_WARNING_DAYS = 30


class TlsScanner(BaseScanner):
    id = "tls"
    module = "Transport Layer / SSL"
    title = "SSL/TLS Cryptography & Transport Security"

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        if ctx.target.scheme != "https":
            return [
                self.result(
                    id="https_available",
                    name="HTTPS Availability",
                    severity=Severity.CRITICAL,
                    status="Target served over HTTP",
                    summary="The target does not use TLS; all traffic is plaintext.",
                    explanation=(
                        "Without HTTPS, credentials, session cookies and API payloads "
                        "travel unencrypted and can be read or modified in transit."
                    ),
                    fix_snippet="# Nginx\nlisten 443 ssl;\nssl_certificate /etc/ssl/cert.pem;",
                )
            ]

        findings: list[Finding] = []

        try:
            der, version, cipher = await self._fetch_certificate(
                ctx.target.host, ctx.target.port, ctx.settings.request_timeout
            )
        except (TimeoutError, ssl.SSLError, OSError) as exc:
            return [
                self.result(
                    id="tls_handshake",
                    name="TLS Handshake",
                    severity=Severity.CRITICAL,
                    status="Handshake failed",
                    summary="The TLS handshake could not be completed.",
                    explanation=(
                        "A failing handshake indicates a broken or misconfigured "
                        "certificate/transport layer."
                    ),
                    fix_snippet="# Verify the certificate chain and SNI configuration.",
                    confidence=Confidence.MEDIUM,
                    meta={"error": str(exc)},
                )
            ]

        cert = x509.load_der_x509_certificate(der)
        findings.append(self._check_expiry(cert))
        findings.append(self._check_protocol(version, cipher))
        findings.append(self._check_issuer(cert))
        findings.append(await self._check_https_redirect(ctx))
        return findings

    # -- checks ----------------------------------------------------------
    def _check_expiry(self, cert: x509.Certificate) -> Finding:
        try:
            expires = cert.not_valid_after_utc
        except AttributeError:  # pragma: no cover - older cryptography
            expires = cert.not_valid_after.replace(tzinfo=UTC)

        now = datetime.now(UTC)
        days_left = (expires - now).days
        meta = {"expires_at": expires.isoformat(), "days_left": days_left}

        if days_left < 0:
            severity, status = Severity.CRITICAL, "Certificate Expired"
            summary = "The TLS certificate has expired."
        elif days_left <= _EXPIRY_WARNING_DAYS:
            severity, status = Severity.WARNING, f"Expires in {days_left} Days"
            summary = "The TLS certificate is nearing expiration."
        else:
            severity, status = Severity.PASSED, f"Valid ({days_left} days left)"
            summary = "The TLS certificate is valid and has ample lifetime."

        return self.result(
            id="cert_expiry",
            name="TLS Certificate Expiration",
            severity=severity,
            status=status,
            summary=summary,
            explanation=(
                "Expired or soon-to-expire certificates cause browsers to block access "
                "with severe security warnings and break API clients."
            ),
            fix_snippet="# Certbot renewal\nsudo certbot renew --dry-run",
            meta=meta,
        )

    def _check_protocol(
        self, version: str | None, cipher: tuple | None
    ) -> Finding:
        cipher_name = cipher[0] if cipher else "unknown"
        if version in _MODERN_PROTOCOLS:
            severity, status = Severity.PASSED, f"{version} negotiated"
            summary = "A modern TLS protocol version is negotiated."
        else:
            severity, status = Severity.CRITICAL, f"{version or 'unknown'} negotiated"
            summary = "A legacy, insecure TLS protocol version is negotiated."

        return self.result(
            id="protocol",
            name="TLS Protocol Version & Cipher",
            severity=severity,
            status=status,
            summary=summary,
            explanation=(
                "TLS 1.0/1.1 are deprecated and vulnerable to BEAST/POODLE. Restrict "
                "servers to TLS 1.2 and 1.3 with strong cipher suites."
            ),
            fix_snippet="ssl_protocols TLSv1.2 TLSv1.3;",
            meta={"version": version, "cipher": cipher_name},
        )

    def _check_issuer(self, cert: x509.Certificate) -> Finding:
        def _attr(name: NameOID) -> str:
            attrs = cert.issuer.get_attributes_for_oid(name)
            return attrs[0].value if attrs else "Unknown"

        ca = _attr(NameOID.ORGANIZATION_NAME)
        cn = _attr(NameOID.COMMON_NAME)
        self_signed = cert.issuer == cert.subject
        return self.result(
            id="cert_issuer",
            name="Certificate Issuer",
            severity=Severity.WARNING if self_signed else Severity.PASSED,
            status="Self-signed" if self_signed else f"Issued by {ca} ({cn})",
            summary=(
                "The certificate is self-signed and untrusted by clients."
                if self_signed
                else "The certificate is issued by a recognized authority."
            ),
            explanation="Self-signed certificates trigger browser trust warnings.",
            fix_snippet="# Use a trusted CA (e.g. Let's Encrypt / Certbot).",
            meta={"issuer_cn": cn, "issuer_org": ca, "self_signed": self_signed},
        )

    async def _check_https_redirect(self, ctx: ScanContext) -> Finding:
        http_url = f"http://{ctx.target.host}"
        try:
            response = await ctx.client.get(http_url, follow_redirects=False)
        except Exception as exc:  # noqa: BLE001 - report any transport issue
            return self.result(
                id="https_redirect",
                name="HTTPS Protocol Enforcement",
                severity=Severity.WARNING,
                status="HTTP endpoint unreachable",
                summary="Could not verify HTTP-to-HTTPS redirection.",
                explanation="Verify that all HTTP traffic is redirected to HTTPS.",
                fix_snippet="server { listen 80; return 301 https://$host$request_uri; }",
                confidence=Confidence.LOW,
                meta={"error": str(exc)},
            )

        location = response.headers.get("location", "")
        redirects_to_https = response.status_code in (301, 302, 307, 308) and location.startswith(
            "https://"
        )

        if redirects_to_https:
            return self.result(
                id="https_redirect",
                name="HTTPS Protocol Enforcement",
                severity=Severity.PASSED,
                status=f"{response.status_code} -> {location}",
                summary="Plain HTTP is redirected to HTTPS.",
                explanation="Automatic redirection prevents accidental plaintext sessions.",
                fix_snippet="server { listen 80; return 301 https://$host$request_uri; }",
            )

        return self.result(
            id="https_redirect",
            name="HTTPS Protocol Enforcement",
            severity=Severity.WARNING,
            status=f"No redirect (HTTP {response.status_code})",
            summary="HTTP traffic is not automatically upgraded to HTTPS.",
            explanation=(
                "Users and API clients hitting the HTTP endpoint are not upgraded to "
                "a secure connection."
            ),
            fix_snippet="server { listen 80; return 301 https://$host$request_uri; }",
        )

    # -- transport -------------------------------------------------------
    @staticmethod
    async def _fetch_certificate(
        host: str, port: int, timeout: float
    ) -> tuple[bytes, str | None, tuple | None]:
        loop = asyncio.get_running_loop()

        def _connect() -> tuple[bytes, str | None, tuple | None]:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                context.wrap_socket(sock, server_hostname=host) as tls_sock,
            ):
                der = tls_sock.getpeercert(binary_form=True)
                return der, tls_sock.version(), tls_sock.cipher()

        return await asyncio.wait_for(loop.run_in_executor(None, _connect), timeout + 1)
