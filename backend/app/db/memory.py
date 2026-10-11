"""In-memory repository used for local development and tests."""

from __future__ import annotations

import uuid
from datetime import datetime

from app.db.repository import Plan, ScanListItem, ScanRepository
from app.models import ScanResult


class InMemoryRepository(ScanRepository):
    def __init__(self) -> None:
        self._scans: dict[str, tuple[str, ScanResult, str]] = {}
        self._plans: dict[str, Plan] = {}

    async def save_scan(
        self, user_id: str, result: ScanResult, *, trigger: str = "manual"
    ) -> str:
        scan_id = uuid.uuid4().hex
        self._scans[scan_id] = (user_id, result, trigger)
        return scan_id

    async def get_scan(self, scan_id: str, user_id: str | None = None) -> ScanResult | None:
        entry = self._scans.get(scan_id)
        if entry is None:
            return None
        owner, result, _trigger = entry
        if user_id is not None and owner != user_id:
            return None
        return result

    async def list_scans(self, user_id: str, limit: int = 50) -> list[ScanListItem]:
        items = [
            ScanListItem(
                id=scan_id,
                url=result.target.url,
                host=result.target.host,
                score=result.score,
                grade=result.grade,
                grade_label=result.grade_label,
                trigger=trigger,
                finished_at=result.finished_at,
            )
            for scan_id, (owner, result, trigger) in self._scans.items()
            if owner == user_id
        ]
        items.sort(key=lambda item: item.finished_at, reverse=True)
        return items[:limit]

    async def count_scans_since(self, user_id: str, since: datetime) -> int:
        return sum(
            1
            for owner, result, _trigger in self._scans.values()
            if owner == user_id and result.finished_at >= since
        )

    async def get_plan(self, user_id: str) -> Plan:
        return self._plans.get(user_id, "free")

    def set_plan(self, user_id: str, plan: Plan) -> None:
        self._plans[user_id] = plan
