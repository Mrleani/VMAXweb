"""Selects the active repository implementation from settings."""

from __future__ import annotations

from app.core.config import get_settings
from app.db.memory import InMemoryRepository
from app.db.repository import ScanRepository
from app.db.supabase import SupabaseRepository

_repository: ScanRepository | None = None


def get_repository() -> ScanRepository:
    global _repository
    if _repository is None:
        settings = get_settings()
        if settings.supabase_url and settings.supabase_service_key:
            _repository = SupabaseRepository(
                settings.supabase_url, settings.supabase_service_key
            )
        else:
            _repository = InMemoryRepository()
    return _repository


def set_repository(repository: ScanRepository | None) -> None:
    """Override the active repository (used in tests)."""
    global _repository
    _repository = repository
