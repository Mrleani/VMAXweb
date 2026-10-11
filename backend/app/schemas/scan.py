from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models import Finding, Target


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target website or API URL to audit")
    verification_token: str | None = Field(
        default=None,
        description="DNS TXT token proving domain ownership (enables active checks)",
    )


class ScanSummary(BaseModel):
    score: int
    grade: str
    grade_label: str
    critical: int
    warning: int
    passed: int
    info: int


class ModuleInfo(BaseModel):
    id: str
    module: str
    title: str
    requires_verified_target: bool


class ScanResponse(BaseModel):
    scan_id: str
    target: Target
    summary: ScanSummary
    findings: list[Finding]
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    engine_version: str


class ScanHistoryItem(BaseModel):
    id: str
    url: str
    host: str
    score: int
    grade: str
    grade_label: str
    trigger: str
    finished_at: datetime


class ProfileInfo(BaseModel):
    id: str
    email: str | None
    plan: str
    monthly_used: int
    monthly_limit: int | None
