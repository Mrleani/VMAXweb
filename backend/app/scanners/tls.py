"""Module 2 - SSL/TLS Cryptography & Transport Security."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.models import Finding, Severity
from app.scanners.base import BaseScanner, ScanContext

_MODERN_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}
_EXPIRY_WARNING_DAYS = 30
_WEAK_SIGNATURE_HASHES = {"md5", "sha1"}


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

        host, port = ctx.target.host, ctx.target.port
        timeout = ctx.settings.request_timeout

        der_result, trust_result, v12, v13 = await asyncio.gather(
            self._fetch_certificate_async(host, port, timeout),
            self._verify_chain(host, port, timeout),
            self._supports_version(host, port, ssl.TLSVersion.TLSv1_2, timeout),
            self._supports_version(host, port, ssl.TLSVersion.TLSv1_3, timeout),
        )

        if isinstance(der_result, Exception):
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
                    meta={"error": str(der_result)},
                )
            ]

        der, version, cipher = der_result
        cert = x509.load_der_x509_certificate(der)

        findings: list[Finding] = []
        findings.append(self._check_chain_trust(trust_result))
        findings.append(self._check_expiry(cert))
        findings.append(self._check_protocol_support(v12, v13, version, cipher))
        findings.append(self._check_public_key(cert))
        findings.append(self._check_signature(cert))
        findings.append(self._check_issuer(cert))
        findings.append(await self._check_https_redirect(ctx))
        return findings

    # -- certificate checks ---------------------------------------------
    def _check_chain_trust(self, trust: dict) -> Finding:
        error = trust.get("error", "")
        if trust.get("trusted"):
            return self.result(
                id="chain_trust",
                name="Certificate Trust Chain",
                severity=Severity.PASSED,
                status="Trusted & hostname matches",
                summary="The certificate chain is valid and issued for this hostname.",
                explanation=(
                    "A fully validated chain means clients will not see trust warnings "
                    "and cannot be tricked by a mismatched certificate."
                ),
                fix_snippet="# Renew with a trusted CA if the chain ever breaks.",
                meta={"trusted": True},
            )

        lowered = error.lower()
        if "hostname mismatch" in lowered or "not valid for" in lowered:
            severity, status = Severity.CRITICAL, "Hostname mismatch"
            summary = "The certificate is not valid for the requested hostname."
        elif "expired" in lowered:
            severity, status = Severity.CRITICAL, "Expired (chain rejected)"
            summary = "The certificate is expired; clients reject the connection."
        elif "self-signed" in lowered or "self signed" in lowered:
            severity, status = Severity.CRITICAL, "Self-signed (untrusted)"
            summary = "The certificate is self-signed and not trusted by clients."
        elif "unable to get local issuer" in lowered or "incomplete" in lowered:
            severity, status = Severity.CRITICAL, "Incomplete chain"
            summary = "The server does not send the full certificate chain."
        else:
            severity, status = Severity.CRITICAL, "Verification failed"
            summary = "The certificate chain could not be validated against trusted roots."

        return self.result(
            id="chain_trust",
            name="Certificate Trust Chain",
            severity=severity,
            status=status,
            summary=summary,
            explanation=(
                "A chain that fails verification means every client sees a full-page "
                "security warning; users are trained to click through, defeating TLS."
            ),
            fix_snippet="# Install the full chain (leaf + intermediates) from your CA.",
            meta={"error": error},
        )

    def _check_expiry(self, cert: x509.Certificate) -> Finding:
        try:
            not_before = cert.not_valid_before_utc
            expires = cert.not_valid_after_utc
        except AttributeError:  # pragma: no cover - older cryptography
            not_before = cert.not_valid_before.replace(tzinfo=UTC)
            expires = cert.not_valid_after.replace(tzinfo=UTC)

        now = datetime.now(UTC)
        days_left = (expires - now).days
        meta = {
            "valid_from": not_before.isoformat(),
            "expires_at": expires.isoformat(),
            "days_left": days_left,
        }

        if not_before > now:
            severity, status = Severity.CRITICAL, "Not yet valid"
            summary = "The certificate validity period has not started yet."
        elif days_left < 0:
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

    def _check_protocol_support(
        self, v12: bool, v13: bool, version: str | None, cipher: tuple | None
    ) -> Finding:
        cipher_name = cipher[0] if cipher else "unknown"
        supported = []
        if v13:
            supported.append("TLS 1.3")
        if v12:
            supported.append("TLS 1.2")

        if not supported:
            severity, status = Severity.CRITICAL, "No modern TLS supported"
            summary = "Neither TLS 1.2 nor TLS 1.3 could be negotiated."
        elif not v13:
            severity, status = Severity.WARNING, "TLS 1.3 not supported"
            summary = "Only TLS 1.2 is offered; enable TLS 1.3 for forward secrecy."
        else:
            severity, status = Severity.PASSED, f"Supported: {', '.join(supported)}"
            summary = "Modern TLS protocols (1.2/1.3) are supported."

        return self.result(
            id="protocol",
            name="TLS Protocol Version & Cipher",
            severity=severity,
            status=status,
            summary=summary,
            explanation=(
                "TLS 1.2 is the modern minimum; TLS 1.3 adds stronger handshakes and "
                "forward secrecy. Legacy TLS 1.0/1.1 are deprecated (BEAST/POODLE)."
            ),
            fix_snippet="ssl_protocols TLSv1.2 TLSv1.3;",
            meta={
                "negotiated": version,
                "cipher": cipher_name,
                "tls_1_2": v12,
                "tls_1_3": v13,
            },
        )

    def _check_public_key(self, cert: x509.Certificate) -> Finding:
        key = cert.public_key()
        key_type = type(key).__name__
        key_size = getattr(key, "key_size", None)

        weak = False
        if key_type == "RSAPublicKey" and (key_size or 0) < 2048:
            weak = True
        elif key_type == "DSAPublicKey":
            weak = True
        elif key_type == "EllipticCurvePublicKey" and (key_size or 0) < 256:
            weak = True

        if weak:
            severity, status = Severity.WARNING, f"Weak key ({key_type} {key_size})"
            summary = "The certificate public key is below modern strength guidance."
        else:
            severity, status = Severity.PASSED, f"{key_type} {key_size or ''}".strip()
            summary = "The certificate public key meets modern strength guidance."

        return self.result(
            id="key_strength",
            name="Public Key Strength",
            severity=severity,
            status=status,
            summary=summary,
            explanation=(
                "RSA keys under 2048 bits and small EC curves are considered weak and "
                "are deprecated by modern browsers."
            ),
            fix_snippet="# Issue the certificate with RSA >= 2048 or EC P-256+.",
            meta={"key_type": key_type, "key_size": key_size},
        )

    def _check_signature(self, cert: x509.Certificate) -> Finding:
        try:
            hash_alg = (cert.signature_hash_algorithm.name or "").lower()
        except Exception:  # noqa: BLE001 - some algorithms are unsupported locally
            hash_alg = "unknown"

        weak = hash_alg in _WEAK_SIGNATURE_HASHES
        if weak:
            severity, status = Severity.WARNING, f"Weak signature ({hash_alg})"
            summary = "The certificate is signed with a deprecated hash algorithm."
        else:
            severity, status = Severity.PASSED, f"Signed with {hash_alg}"
            summary = "The certificate uses a modern signature algorithm."

        return self.result(
            id="signature_algorithm",
            name="Certificate Signature Algorithm",
            severity=severity,
            status=status,
            summary=summary,
            explanation=(
                "SHA-1 and MD5 signatures are collision-prone and rejected by modern "
                "clients."
            ),
            fix_snippet="# Re-issue the certificate using SHA-256 or stronger.",
            meta={"signature_hash": hash_alg},
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
    def _connect_verified(host: str, port: int, timeout: float) -> None:
        context = ssl.create_default_context()
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host),
        ):
            return

    async def _verify_chain(self, host: str, port: int, timeout: float) -> dict:
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, self._connect_verified, host, port, timeout),
                timeout + 1,
            )
            return {"trusted": True, "error": ""}
        except (TimeoutError, ssl.SSLError, OSError) as exc:
            return {"trusted": False, "error": str(exc)}

    @staticmethod
    def _fetch_certificate(
        host: str, port: int, timeout: float
    ) -> tuple[bytes, str | None, tuple | None]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls_sock,
        ):
            der = tls_sock.getpeercert(binary_form=True)
            return der, tls_sock.version(), tls_sock.cipher()

    async def _fetch_certificate_async(
        self, host: str, port: int, timeout: float
    ) -> tuple[bytes, str | None, tuple | None] | Exception:
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._fetch_certificate, host, port, timeout),
                timeout + 1,
            )
        except (TimeoutError, ssl.SSLError, OSError) as exc:
            return exc

    @staticmethod
    def _handshake_version(host: str, port: int, version, timeout: float) -> bool:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                context.wrap_socket(sock, server_hostname=host),
            ):
                return True
        except (ssl.SSLError, OSError):
            return False

    async def _supports_version(self, host: str, port: int, version, timeout: float) -> bool:
        loop = asyncio.get_running_loop()
        probe_timeout = min(timeout, 6.0)
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(
                    None, self._handshake_version, host, port, version, probe_timeout
                ),
                probe_timeout + 1,
            )
        except (TimeoutError, ssl.SSLError, OSError):
            return False
