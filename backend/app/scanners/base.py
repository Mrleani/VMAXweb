"""Shared scanner contract.

Each of the six audit modules implements :class:`BaseScanner`. Scanners are
stateless and receive an immutable :class:`ScanContext`; they may only touch
the network through the shared ``httpx.AsyncClient`` so timeouts, proxy and
User-Agent policy stay centralized.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import httpx

from app.core.config import Settings
from app.models import Confidence, Finding, Severity, Target
from app.scoring.confidence import Evidence, confidence_for


@dataclass(slots=True)
class SeverityTally:
    critical: int = 0
    warning: int = 0
    passed: int = 0
    info: int = 0

    def add(self, severity: Severity) -> None:
        setattr(self, severity.value, getattr(self, severity.value) + 1)


@dataclass(slots=True)
class ScanContext:
    target: Target
    client: httpx.AsyncClient
    settings: Settings


class BaseScanner(ABC):
    """Base class for all audit modules."""

    id: str
    module: str
    title: str
    requires_verified_target: bool = False

    @abstractmethod
    async def scan(self, ctx: ScanContext) -> list[Finding]:
        """Run the module against ``ctx.target`` and return findings."""

    # -- helpers ---------------------------------------------------------
    def result(
        self,
        *,
        id: str,
        name: str,
        severity: Severity,
        status: str,
        summary: str,
        explanation: str = "",
        fix_snippet: str = "",
        evidence: Evidence = Evidence.DEFINITIVE,
        confidence: Confidence | None = None,
        meta: dict | None = None,
    ) -> Finding:
        return Finding(
            id=f"{self.id}.{id}",
            module=self.module,
            name=name,
            severity=severity,
            status=status,
            summary=summary,
            explanation=explanation,
            fix_snippet=fix_snippet,
            confidence=confidence or confidence_for(evidence),
            meta=meta or {},
        )


@dataclass(slots=True)
class ModuleReport:
    scanner_id: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
