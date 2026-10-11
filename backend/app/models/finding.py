from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    PASSED = "passed"
    INFO = "info"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
    Severity.PASSED: 3,
}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(BaseModel):
    """A single audit result row.

    Mirrors the shape consumed by the dashboard table in the design:
    severity badge + technical status + recommendation + expandable detail.
    """

    id: str
    module: str
    name: str
    severity: Severity
    status: str
    summary: str
    explanation: str = ""
    fix_snippet: str = ""
    confidence: Confidence = Confidence.HIGH
    meta: dict[str, Any] = Field(default_factory=dict)

    @field_validator("fix_snippet", mode="before")
    @classmethod
    def _coerce_snippet(cls, value: Any) -> str:
        return "" if value is None else str(value)


class Target(BaseModel):
    """A normalized scan target."""

    url: str
    scheme: str
    host: str
    port: int
    path: str = "/"

    @property
    def origin(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        if self.port == default_port:
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def hostname(self) -> str:
        return self.host


class ScanResult(BaseModel):
    """Aggregated result of all scanners for one target."""

    target: Target
    score: int
    grade: str
    grade_label: str
    findings: list[Finding]
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    engine_version: str

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.WARNING)

    @property
    def passed_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.PASSED)

    @staticmethod
    def utc_now() -> datetime:
        return datetime.now(UTC)
