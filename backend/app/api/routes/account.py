from __future__ import annotations

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.core.auth import CurrentUser, get_current_user
from app.core.config import Settings, get_settings
from app.core.entitlements import get_account, require_pro
from app.db import ScanRepository, get_repository
from app.db.account_store import Account, account_store
from app.schemas import (
    AccountInfo,
    AccountUpdate,
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyInfo,
    Entitlements,
    PlanUpdate,
    ScheduleCreate,
    ScheduleInfo,
    SupportRequest,
    SupportResponse,
)

router = APIRouter(prefix="/api/v1", tags=["account"])


def _month_start() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _entitlements(account: Account) -> Entitlements:
    pro = account.is_pro or account.is_owner
    return Entitlements(
        unlimited_scans=pro,
        active_modules=True,
        scheduled_scans=pro,
        alerts=pro,
        webhooks=pro,
        api_access=pro,
        white_label_pdf=pro,
        priority_support=pro,
    )


async def _account_info(
    user: CurrentUser, account: Account, repository: ScanRepository, settings: Settings
) -> AccountInfo:
    used = await repository.count_scans_since(user.id, _month_start())
    return AccountInfo(
        id=user.id,
        email=user.email,
        plan=account.plan,
        monthly_used=used,
        monthly_limit=None if account.is_pro else settings.free_monthly_scan_limit,
        entitlements=_entitlements(account),
        brand_name=account.brand_name,
        logo_base64=account.logo_base64,
        brand_color=account.brand_color,
        slack_webhook_url=account.slack_webhook_url,
        webhook_url=account.webhook_url,
        webhook_secret_set=bool(account.webhook_secret),
        alert_email=account.alert_email,
        alert_min_severity=account.alert_min_severity,
        priority_support=account.priority_support,
        is_owner=account.is_owner,
    )


def _api_key_info(key) -> ApiKeyInfo:
    return ApiKeyInfo(
        id=key.id,
        name=key.name,
        prefix=key.prefix,
        created_at=key.created_at,
        last_used_at=key.last_used_at,
    )


def _schedule_info(schedule) -> ScheduleInfo:
    return ScheduleInfo(
        id=schedule.id,
        url=schedule.url,
        cadence=schedule.cadence,
        enabled=schedule.enabled,
        next_run_at=schedule.next_run_at,
        last_run_at=schedule.last_run_at,
        last_scan_id=schedule.last_scan_id,
    )


@router.get("/account", response_model=AccountInfo)
async def get_account_info(
    user: CurrentUser = Depends(get_current_user),
    account: Account = Depends(get_account),
    repository: ScanRepository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> AccountInfo:
    return await _account_info(user, account, repository, settings)


@router.put("/account", response_model=AccountInfo)
async def update_account(
    payload: AccountUpdate,
    user: CurrentUser = Depends(get_current_user),
    account: Account = Depends(require_pro),
    repository: ScanRepository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> AccountInfo:
    fields = payload.model_dump(exclude_unset=True)
    if "alert_min_severity" in fields and fields["alert_min_severity"] is not None:
        if fields["alert_min_severity"] not in {"critical", "warning", "info"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="alert_min_severity must be critical, warning or info",
            )
    for name, value in fields.items():
        setattr(account, name, value)

    if account.webhook_url and not account.webhook_secret:
        account.webhook_secret = secrets.token_hex(24)

    return await _account_info(user, account, repository, settings)


@router.post("/account/plan", response_model=AccountInfo)
async def set_plan(
    payload: PlanUpdate,
    user: CurrentUser = Depends(get_current_user),
    repository: ScanRepository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> AccountInfo:
    if payload.plan not in {"free", "pro"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="plan must be free or pro"
        )
    account = account_store.set_plan(user.id, payload.plan)
    if account.is_pro:
        account.priority_support = True
    return await _account_info(user, account, repository, settings)


@router.get("/api-keys", response_model=list[ApiKeyInfo])
async def list_api_keys(account: Account = Depends(require_pro)) -> list[ApiKeyInfo]:
    return [_api_key_info(key) for key in account.api_keys]


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: ApiKeyCreate, account: Account = Depends(require_pro)
) -> ApiKeyCreated:
    key, raw = account_store.create_api_key(account.user_id, payload.name)
    return ApiKeyCreated(key=_api_key_info(key), secret=raw)


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def revoke_api_key(
    key_id: str, account: Account = Depends(require_pro)
) -> Response:
    if not account_store.revoke_api_key(account.user_id, key_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/schedules", response_model=list[ScheduleInfo])
async def list_schedules(account: Account = Depends(require_pro)) -> list[ScheduleInfo]:
    return [_schedule_info(s) for s in account.schedules]


@router.post("/schedules", response_model=ScheduleInfo, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScheduleCreate, account: Account = Depends(require_pro)
) -> ScheduleInfo:
    if payload.cadence not in {"daily", "weekly"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="cadence must be daily or weekly"
        )
    schedule = account_store.add_schedule(
        account.user_id,
        payload.url,
        payload.cadence,
        verification_token=payload.verification_token,
    )
    return _schedule_info(schedule)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def delete_schedule(
    schedule_id: str, account: Account = Depends(require_pro)
) -> Response:
    if not account_store.remove_schedule(account.user_id, schedule_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/support", response_model=SupportResponse)
async def submit_support(
    payload: SupportRequest, account: Account = Depends(get_account)
) -> SupportResponse:
    return SupportResponse(
        received=True,
        priority=account.is_pro,
        reference=f"VMAX-{secrets.token_hex(4).upper()}",
    )
