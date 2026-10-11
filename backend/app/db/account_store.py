"""Pro-plan account state: entitlements, branding, alerts, keys, schedules.

This store is intentionally independent from :mod:`app.db` scan storage so the
Pro features work in every deployment. It is in-memory today; the Supabase
migration in ``supabase/migrations`` mirrors the same shape for persistence
when a database is connected.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

API_KEY_PREFIX = "vmax_"
_CADENCE_DELTAS = {"daily": timedelta(days=1), "weekly": timedelta(weeks=1)}


@dataclass(slots=True)
class ApiKey:
    id: str
    name: str
    prefix: str
    key_hash: str
    created_at: datetime
    last_used_at: datetime | None = None


@dataclass(slots=True)
class Schedule:
    id: str
    user_id: str
    url: str
    cadence: str  # "daily" | "weekly"
    next_run_at: datetime
    verification_token: str | None = None
    enabled: bool = True
    last_run_at: datetime | None = None
    last_scan_id: str | None = None


@dataclass(slots=True)
class Account:
    user_id: str
    plan: str = "free"
    brand_name: str | None = None
    logo_base64: str | None = None
    brand_color: str | None = None
    slack_webhook_url: str | None = None
    webhook_url: str | None = None
    webhook_secret: str | None = None
    alert_email: str | None = None
    alert_min_severity: str = "critical"  # critical | warning | info
    priority_support: bool = False
    api_keys: list[ApiKey] = field(default_factory=list)
    schedules: list[Schedule] = field(default_factory=list)

    @property
    def is_pro(self) -> bool:
        return self.plan == "pro"


class AccountStore:
    def __init__(self) -> None:
        self._accounts: dict[str, Account] = {}
        self._api_key_index: dict[str, str] = {}  # key_hash -> user_id

    # -- account ---------------------------------------------------------
    def get(self, user_id: str) -> Account:
        account = self._accounts.get(user_id)
        if account is None:
            account = Account(user_id=user_id)
            self._accounts[user_id] = account
        return account

    def set_plan(self, user_id: str, plan: str) -> Account:
        account = self.get(user_id)
        account.plan = "pro" if plan == "pro" else "free"
        return account

    # -- api keys --------------------------------------------------------
    def create_api_key(self, user_id: str, name: str) -> tuple[ApiKey, str]:
        raw = f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"
        key = ApiKey(
            id=uuid.uuid4().hex,
            name=name.strip() or "API key",
            prefix=raw[:12],
            key_hash=_hash_key(raw),
            created_at=datetime.now(UTC),
        )
        account = self.get(user_id)
        account.api_keys.append(key)
        self._api_key_index[key.key_hash] = user_id
        return key, raw

    def revoke_api_key(self, user_id: str, key_id: str) -> bool:
        account = self.get(user_id)
        for key in list(account.api_keys):
            if key.id == key_id:
                account.api_keys.remove(key)
                self._api_key_index.pop(key.key_hash, None)
                return True
        return False

    def resolve_api_key(self, raw_key: str) -> str | None:
        if not raw_key.startswith(API_KEY_PREFIX):
            return None
        user_id = self._api_key_index.get(_hash_key(raw_key))
        if user_id is None:
            return None
        account = self.get(user_id)
        for key in account.api_keys:
            if key.key_hash == _hash_key(raw_key):
                key.last_used_at = datetime.now(UTC)
                break
        return user_id

    # -- schedules -------------------------------------------------------
    def add_schedule(
        self,
        user_id: str,
        url: str,
        cadence: str,
        *,
        verification_token: str | None = None,
    ) -> Schedule:
        cadence = cadence if cadence in _CADENCE_DELTAS else "daily"
        schedule = Schedule(
            id=uuid.uuid4().hex,
            user_id=user_id,
            url=url,
            cadence=cadence,
            verification_token=verification_token,
            next_run_at=datetime.now(UTC) + _CADENCE_DELTAS[cadence],
        )
        self.get(user_id).schedules.append(schedule)
        return schedule

    def remove_schedule(self, user_id: str, schedule_id: str) -> bool:
        schedules = self.get(user_id).schedules
        for schedule in list(schedules):
            if schedule.id == schedule_id:
                schedules.remove(schedule)
                return True
        return False

    def due_schedules(self, now: datetime | None = None) -> list[Schedule]:
        now = now or datetime.now(UTC)
        return [
            schedule
            for account in self._accounts.values()
            for schedule in account.schedules
            if schedule.enabled and schedule.next_run_at <= now
        ]

    @staticmethod
    def advance(schedule: Schedule, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        schedule.last_run_at = now
        schedule.next_run_at = now + _CADENCE_DELTAS.get(
            schedule.cadence, timedelta(days=1)
        )

    def all_accounts(self) -> list[Account]:
        return list(self._accounts.values())


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


account_store = AccountStore()
