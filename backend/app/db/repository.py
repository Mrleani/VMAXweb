"""Persistence contract for scans, findings and targets."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

from app.models import ScanResult

Plan = str  # "free" | "pro"


@dataclass(slots=True)
class ScanListItem:
    id: str
    url: str
    host: str
    score: int
    grade: str
    grade_label: str
    trigger: str
    finished_at: datetime


class ScanRepository(ABC):
    """Storage backend for the audit engine.

    Implementations: :class:`app.db.memory.InMemoryRepository` (dev) and
    :class:`app.db.supabase.SupabaseRepository` (production).
    """

    @abstractmethod
    async def save_scan(
        self, user_id: str, result: ScanResult, *, trigger: str = "manual"
    ) -> str:
        """Persist a scan (and its findings/target) and return the scan id."""

    @abstractmethod
    async def get_scan(self, scan_id: str, user_id: str | None = None) -> ScanResult | None:
        """Fetch a full scan by id, optionally scoped to an owner."""

    @abstractmethod
    async def list_scans(self, user_id: str, limit: int = 50) -> list[ScanListItem]:
        """Return recent scans for a user, newest first."""

    @abstractmethod
    async def count_scans_since(self, user_id: str, since: datetime) -> int:
        """Count scans completed at/after ``since`` (for plan limits)."""

    @abstractmethod
    async def get_plan(self, user_id: str) -> Plan:
        """Return the user's plan, defaulting to 'free'."""
