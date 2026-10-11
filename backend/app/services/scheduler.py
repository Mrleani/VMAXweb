"""Background scheduler that runs Pro accounts' daily/weekly audits."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from urllib.parse import urlsplit

from app.core.config import get_settings
from app.core.safety import TargetValidationError
from app.db.account_store import Schedule, account_store
from app.db.factory import get_repository
from app.services.alerts import dispatch_alerts
from app.services.scanner_service import ScanEngine
from app.services.verification import verify_domain

logger = logging.getLogger("vmaxweb.scheduler")


def _host_of(url: str) -> str:
    candidate = url if "://" in url else f"https://{url}"
    return (urlsplit(candidate).hostname or "").lower()


class ScanScheduler:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._engine = ScanEngine()

    def start(self) -> None:
        if not get_settings().scheduler_enabled or self._task is not None:
            return
        self._task = asyncio.create_task(self._loop())
        logger.info("Scan scheduler started")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _loop(self) -> None:
        interval = max(15, get_settings().scheduler_interval_seconds)
        while True:
            try:
                await self._tick()
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                logger.warning("Scheduler tick failed: %s", exc)
            await asyncio.sleep(interval)

    async def _tick(self) -> None:
        now = datetime.now(UTC)
        for schedule in account_store.due_schedules(now):
            await self._run_schedule(schedule)
            account_store.advance(schedule, now)

    async def _run_schedule(self, schedule: Schedule) -> None:
        settings = get_settings()
        account = account_store.get(schedule.user_id)

        verified = False
        if schedule.verification_token:
            verified = await verify_domain(
                _host_of(schedule.url), schedule.verification_token
            )

        try:
            result = await self._engine.run(schedule.url, verified=verified)
        except TargetValidationError as exc:
            logger.warning("Scheduled scan rejected for %s: %s", schedule.url, exc)
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning("Scheduled scan failed for %s: %s", schedule.url, exc)
            return

        scan_id = await get_repository().save_scan(
            schedule.user_id, result, trigger="scheduled"
        )
        schedule.last_scan_id = scan_id
        await dispatch_alerts(settings, account, result, scan_id)
        logger.info("Scheduled scan complete for %s (%s)", schedule.url, scan_id)
