"""Module 6 - Subdomain & Attack Surface Mapping.

Discovery is passive, using the public Certificate Transparency log at
crt.sh. Resolving discovered hosts is a light active step, so the module is
gated behind target ownership verification.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import dns.asyncresolver
import dns.resolver

from app.models import Finding, Severity
from app.scanners.base import BaseScanner, ScanContext
from app.scoring.confidence import Evidence

_CRT_SH_ENDPOINT = "https://crt.sh/"
_DEV_HINTS = ("dev", "test", "stage", "staging", "admin", "internal", "beta", "uat")


@dataclass(frozen=True)
class SubdomainHit:
    host: str
    alive: bool


class SubdomainScanner(BaseScanner):
    id = "subdomains"
    module = "Attack Surface"
    title = "Subdomain & Attack Surface Mapping"
    requires_verified_target = True

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        domain = ctx.target.host.removeprefix("www.")
        names, ct_ok = await self._discover(ctx, domain)

        if not ct_ok:
            return [
                self.result(
                    id="discovery",
                    name="Subdomain Discovery",
                    severity=Severity.INFO,
                    status="CT log unavailable",
                    summary="Certificate Transparency logs could not be queried.",
                    explanation=(
                        "Discovery is passive and best-effort; the public CT log was "
                        "unreachable, so the attack surface could not be mapped."
                    ),
                    fix_snippet="# Re-run later or audit DNS records directly.",
                    evidence=Evidence.WEAK,
                )
            ]

        if not names:
            return [
                self.result(
                    id="discovery",
                    name="Subdomain Discovery",
                    severity=Severity.PASSED,
                    status="No subdomains found",
                    summary="Certificate Transparency logs returned no subdomains.",
                    explanation="No additional surface was mapped from public CT logs.",
                    fix_snippet="# Periodically audit DNS records and CT logs.",
                )
            ]

        hits = await self._resolve_all(ctx, names)
        alive = [h for h in hits if h.alive]
        risky = [h for h in alive if any(hint in h.host for hint in _DEV_HINTS)]

        findings: list[Finding] = [
            self.result(
                id="inventory",
                name="Subdomain Inventory",
                severity=Severity.INFO,
                status=f"{len(names)} found, {len(alive)} resolving",
                summary="Subdomains discovered via Certificate Transparency.",
                explanation=(
                    "Each additional subdomain is additional attack surface; unknown or "
                    "forgotten hosts are common breach entry points."
                ),
                fix_snippet="# Maintain an owned-asset inventory and monitor CT logs.",
                meta={"found": sorted(names), "resolving": sorted(h.host for h in alive)},
            )
        ]

        if risky:
            findings.append(
                self.result(
                    id="dev_exposure",
                    name="Development / Admin Subdomains Exposed",
                    severity=Severity.WARNING,
                    status=", ".join(h.host for h in risky),
                    summary="Non-production hosts are publicly resolvable.",
                    explanation=(
                        "dev/staging/admin hosts frequently run debug builds, weaker auth "
                        "or outdated software."
                    ),
                    fix_snippet="# IP-allowlist or SSO-protect non-production environments.",
                    evidence=Evidence.STRONG,
                    meta={"hosts": [h.host for h in risky]},
                )
            )
        else:
            findings.append(
                self.result(
                    id="dev_exposure",
                    name="Development / Admin Subdomains Exposed",
                    severity=Severity.PASSED,
                    status="None publicly resolvable",
                    summary="No obvious dev/admin subdomains were reachable.",
                    explanation="Keeping non-production hosts private reduces risk.",
                    fix_snippet="# Continue restricting non-production environments.",
                )
            )

        return findings

    async def _discover(self, ctx: ScanContext, domain: str) -> tuple[set[str], bool]:
        records = None
        for attempt in range(3):
            try:
                response = await ctx.client.get(
                    _CRT_SH_ENDPOINT,
                    params={"q": f"%25.{domain}", "output": "json"},
                    timeout=ctx.settings.request_timeout * 2,
                )
                response.raise_for_status()
                records = response.json()
                break
            except Exception:  # noqa: BLE001 - CT log is best-effort
                if attempt < 2:
                    await asyncio.sleep(1.0 * (attempt + 1))
        if not isinstance(records, list):
            return set(), False

        names: set[str] = set()
        for record in records:
            for field in ("name_value", "common_name"):
                value = record.get(field, "")
                for line in str(value).splitlines():
                    host = line.strip().lower().lstrip("*.")
                    if host.endswith(domain) and host != domain and " " not in host:
                        names.add(host)

        return set(sorted(names)[: ctx.settings.subdomain_limit]), True

    async def _resolve_all(self, ctx: ScanContext, names: set[str]) -> list[SubdomainHit]:
        semaphore = asyncio.Semaphore(ctx.settings.max_concurrency)

        async def resolve(host: str) -> SubdomainHit:
            async with semaphore:
                alive = await self._resolves(host, ctx.settings.port_timeout)
            return SubdomainHit(host=host, alive=alive)

        return await asyncio.gather(*(resolve(name) for name in names))

    @staticmethod
    async def _resolves(host: str, timeout: float) -> bool:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        for record_type in ("A", "AAAA"):
            try:
                answers = await resolver.resolve(host, record_type)
                if answers:
                    return True
            except Exception:  # noqa: BLE001 - NXDOMAIN / timeout / no record
                continue
        return False
