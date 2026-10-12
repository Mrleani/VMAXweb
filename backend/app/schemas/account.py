from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Entitlements(BaseModel):
    unlimited_scans: bool
    active_modules: bool
    scheduled_scans: bool
    alerts: bool
    webhooks: bool
    api_access: bool
    white_label_pdf: bool
    priority_support: bool


class AccountInfo(BaseModel):
    id: str
    email: str | None
    plan: str
    monthly_used: int
    monthly_limit: int | None
    entitlements: Entitlements
    brand_name: str | None = None
    logo_base64: str | None = None
    brand_color: str | None = None
    slack_webhook_url: str | None = None
    webhook_url: str | None = None
    webhook_secret_set: bool = False
    alert_email: str | None = None
    alert_min_severity: str
    priority_support: bool = False
    is_owner: bool = False


class AccountUpdate(BaseModel):
    brand_name: str | None = Field(default=None, max_length=80)
    logo_base64: str | None = Field(default=None, max_length=400_000)
    brand_color: str | None = Field(default=None, max_length=7)
    slack_webhook_url: str | None = Field(default=None, max_length=500)
    webhook_url: str | None = Field(default=None, max_length=500)
    webhook_secret: str | None = Field(default=None, max_length=200)
    alert_email: str | None = Field(default=None, max_length=200)
    alert_min_severity: str | None = None


class PlanUpdate(BaseModel):
    plan: str


class ApiKeyInfo(BaseModel):
    id: str
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None = None


class ApiKeyCreated(BaseModel):
    key: ApiKeyInfo
    secret: str
    warning: str = "Store this key now; it will not be shown again."


class ApiKeyCreate(BaseModel):
    name: str = Field(default="API key", max_length=60)


class ScheduleInfo(BaseModel):
    id: str
    url: str
    cadence: str
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None = None
    last_scan_id: str | None = None


class ScheduleCreate(BaseModel):
    url: str
    cadence: str = "daily"
    verification_token: str | None = None


class SupportRequest(BaseModel):
    subject: str = Field(..., max_length=120)
    message: str = Field(..., max_length=4000)


class SupportResponse(BaseModel):
    received: bool
    priority: bool
    reference: str
