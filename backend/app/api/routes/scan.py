from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.core.auth import CurrentUser, get_current_user
from app.core.config import Settings, get_settings
from app.core.safety import TargetValidationError
from app.db import ScanRepository, get_repository
from app.db.account_store import account_store
from app.models import ScanResult
from app.schemas import (
    ModuleInfo,
    ProfileInfo,
    ScanHistoryItem,
    ScanRequest,
    ScanResponse,
    ScanSummary,
)
from app.scanners import SCANNER_REGISTRY
from app.services import ScanEngine
from app.services.alerts import dispatch_alerts
from app.services.pdf import ReportBranding, build_report
from app.services.verification import verify_domain

router = APIRouter(prefix="/api/v1", tags=["scan"])

_engine = ScanEngine()


def _to_response(scan_id: str, result: ScanResult) -> ScanResponse:
    return ScanResponse(
        scan_id=scan_id,
        target=result.target,
        summary=ScanSummary(
            score=result.score,
            grade=result.grade,
            grade_label=result.grade_label,
            critical=result.critical_count,
            warning=result.warning_count,
            passed=result.passed_count,
            info=sum(1 for f in result.findings if f.severity.value == "info"),
        ),
        findings=result.findings,
        started_at=result.started_at,
        finished_at=result.finished_at,
        duration_ms=result.duration_ms,
        engine_version=result.engine_version,
    )


def _month_start() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


async def _plan_for(repository: ScanRepository, user_id: str) -> str:
    """Account store is authoritative; repository is the legacy fallback."""
    plan = account_store.get(user_id).plan
    if plan == "pro":
        return "pro"
    return await repository.get_plan(user_id)


async def _enforce_plan_limit(
    repository: ScanRepository, user: CurrentUser, settings: Settings
) -> None:
    plan = await _plan_for(repository, user.id)
    if plan == "pro":
        return
    used = await repository.count_scans_since(user.id, _month_start())
    if used >= settings.free_monthly_scan_limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Free plan limit reached ({settings.free_monthly_scan_limit} scans/month). "
                "Upgrade to Pro for unlimited automated scans."
            ),
        )


@router.post("/scan", response_model=ScanResponse)
async def create_scan(
    payload: ScanRequest,
    user: CurrentUser = Depends(get_current_user),
    repository: ScanRepository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> ScanResponse:
    await _enforce_plan_limit(repository, user, settings)

    verified = False
    if payload.verification_token:
        verified = await verify_domain(_host_of(payload.url), payload.verification_token)

    try:
        result = await _engine.run(payload.url, verified=verified)
    except TargetValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    scan_id = await repository.save_scan(user.id, result)
    await dispatch_alerts(settings, account_store.get(user.id), result, scan_id)
    return _to_response(scan_id, result)


@router.get("/scans", response_model=list[ScanHistoryItem])
async def list_scans(
    limit: int = 25,
    user: CurrentUser = Depends(get_current_user),
    repository: ScanRepository = Depends(get_repository),
) -> list[ScanHistoryItem]:
    items = await repository.list_scans(user.id, limit=max(1, min(limit, 100)))
    return [
        ScanHistoryItem(
            id=item.id,
            url=item.url,
            host=item.host,
            score=item.score,
            grade=item.grade,
            grade_label=item.grade_label,
            trigger=item.trigger,
            finished_at=item.finished_at,
        )
        for item in items
    ]


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    user: CurrentUser = Depends(get_current_user),
    repository: ScanRepository = Depends(get_repository),
) -> ScanResponse:
    result = await repository.get_scan(scan_id, user_id=user.id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return _to_response(scan_id, result)


@router.get("/scans/{scan_id}/report")
async def get_report(
    scan_id: str,
    user: CurrentUser = Depends(get_current_user),
    repository: ScanRepository = Depends(get_repository),
) -> Response:
    result = await repository.get_scan(scan_id, user_id=user.id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    account = account_store.get(user.id)
    branding = None
    if account.is_pro:
        branding = ReportBranding(
            brand_name=account.brand_name,
            logo_base64=account.logo_base64,
            brand_color=_parse_color(account.brand_color),
        )
    pdf_bytes = build_report(result, branding)
    slot = (branding.brand_name if branding and branding.brand_name else "vmaxweb").lower()
    filename = f"{slot}-audit-{result.target.host}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/me", response_model=ProfileInfo)
async def get_me(
    user: CurrentUser = Depends(get_current_user),
    repository: ScanRepository = Depends(get_repository),
    settings: Settings = Depends(get_settings),
) -> ProfileInfo:
    plan = await _plan_for(repository, user.id)
    used = await repository.count_scans_since(user.id, _month_start())
    return ProfileInfo(
        id=user.id,
        email=user.email,
        plan=plan,
        monthly_used=used,
        monthly_limit=None if plan == "pro" else settings.free_monthly_scan_limit,
    )


@router.get("/modules", response_model=list[ModuleInfo])
async def list_modules() -> list[ModuleInfo]:
    return [
        ModuleInfo(
            id=scanner.id,
            module=scanner.module,
            title=scanner.title,
            requires_verified_target=scanner.requires_verified_target,
        )
        for scanner in (cls() for cls in SCANNER_REGISTRY)
    ]


def _host_of(url: str) -> str:
    candidate = url if "://" in url else f"https://{url}"
    return (urlsplit(candidate).hostname or "").lower()


def _parse_color(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    token = value.strip().lstrip("#")
    if len(token) != 6:
        return None
    try:
        return (int(token[0:2], 16), int(token[2:4], 16), int(token[4:6], 16))
    except ValueError:
        return None
