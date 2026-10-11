"""Module 5 - Network & Port Security.

Active TCP connect scan of high-risk ports. This module is gated behind
target ownership verification (see ``requires_verified_target``).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.models import Finding, Severity
from app.scanners.base import BaseScanner, ScanContext


@dataclass(frozen=True)
class PortSpec:
    port: int
    service: str
    severity: Severity


PORT_CATALOG: tuple[PortSpec, ...] = (
    PortSpec(21, "FTP", Severity.CRITICAL),
    PortSpec(22, "SSH", Severity.WARNING),
    PortSpec(23, "Telnet", Severity.CRITICAL),
    PortSpec(25, "SMTP", Severity.WARNING),
    PortSpec(3306, "MySQL", Severity.CRITICAL),
    PortSpec(5432, "PostgreSQL", Severity.CRITICAL),
    PortSpec(6379, "Redis", Severity.CRITICAL),
    PortSpec(9200, "Elasticsearch", Severity.CRITICAL),
    PortSpec(27017, "MongoDB", Severity.CRITICAL),
    PortSpec(2375, "Docker API", Severity.CRITICAL),
    PortSpec(8080, "Alt HTTP", Severity.WARNING),
    PortSpec(8443, "Alt HTTPS", Severity.WARNING),
)


class PortScanner(BaseScanner):
    id = "ports"
    module = "Network & Port Audit"
    title = "Network & Port Security"
    requires_verified_target = True

    async def scan(self, ctx: ScanContext) -> list[Finding]:
        semaphore = asyncio.Semaphore(ctx.settings.max_concurrency)
        host = ctx.target.host

        async def probe(spec: PortSpec) -> tuple[PortSpec, bool]:
            async with semaphore:
                is_open = await self._is_open(host, spec.port, ctx.settings.port_timeout)
            return spec, is_open

        results = await asyncio.gather(*(probe(spec) for spec in PORT_CATALOG))

        findings: list[Finding] = []
        for spec, is_open in results:
            if is_open:
                findings.append(
                    self.result(
                        id=f"port_{spec.port}",
                        name=f"Exposed Port {spec.port} ({spec.service})",
                        severity=spec.severity,
                        status="Open to Public",
                        summary=(
                            f"Port {spec.port} ({spec.service}) is reachable from the "
                            "public internet."
                        ),
                        explanation=(
                            "Databases and admin services must never be exposed publicly. "
                            "Restrict them to private networks or a VPN/bastion host."
                        ),
                        fix_snippet=f"# UFW firewall\nsudo ufw deny {spec.port}/tcp",
                        meta={"port": spec.port, "service": spec.service},
                    )
                )
            else:
                findings.append(
                    self.result(
                        id=f"port_{spec.port}",
                        name=f"Port {spec.port} ({spec.service})",
                        severity=Severity.PASSED,
                        status="Closed / Filtered",
                        summary=f"Port {spec.port} is not publicly reachable.",
                        explanation="Closed ports reduce the attack surface.",
                        fix_snippet=f"# UFW firewall\nsudo ufw deny {spec.port}/tcp",
                        meta={"port": spec.port, "service": spec.service},
                    )
                )
        return findings

    @staticmethod
    async def _is_open(host: str, port: int, timeout: float) -> bool:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except (TimeoutError, OSError):
            return False
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001, S110
            pass
        return True
