"""Outbound alert delivery for Pro accounts (Slack, email, webhooks)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage

import httpx

from app.core.config import Settings
from app.db.account_store import Account
from app.models import ScanResult, Severity

logger = logging.getLogger("vmaxweb.alerts")

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
    Severity.PASSED: 3,
}


def _summary_counts(result: ScanResult) -> dict[str, int]:
    return {
        "critical": result.critical_count,
        "warning": result.warning_count,
        "passed": result.passed_count,
        "info": sum(1 for f in result.findings if f.severity is Severity.INFO),
    }


def _meets_threshold(result: ScanResult, min_severity: str) -> bool:
    threshold = {
        "critical": 0,
        "warning": 1,
        "info": 2,
    }.get(min_severity, 0)
    return any(
        f.severity is not Severity.PASSED and _SEVERITY_RANK[f.severity] <= threshold
        for f in result.findings
    )


def _slack_text(result: ScanResult, scan_id: str, base_url: str) -> str:
    counts = _summary_counts(result)
    link = f"{base_url.rstrip('/')}/#scan-{scan_id}"
    return (
        f":rotating_light: *VMAXweb alert* — {result.target.host}\n"
        f"Grade *{result.grade}* ({result.score}/100) • "
        f"critical {counts['critical']}, warning {counts['warning']}\n"
        f"Report: {link}"
    )


async def _send_slack(
    client: httpx.AsyncClient, url: str, text: str
) -> None:
    try:
        await client.post(url, json={"text": text})
    except Exception as exc:  # noqa: BLE001 - alerts are best-effort
        logger.warning("Slack alert failed: %s", exc)


async def _send_webhook(
    client: httpx.AsyncClient,
    account: Account,
    result: ScanResult,
    scan_id: str,
) -> None:
    if not account.webhook_url:
        return
    payload = {
        "event": "scan.completed",
        "scan_id": scan_id,
        "url": result.target.url,
        "host": result.target.host,
        "score": result.score,
        "grade": result.grade,
        "summary": _summary_counts(result),
        "finished_at": result.finished_at.isoformat(),
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "X-VMAX-Event": "scan.completed"}
    if account.webhook_secret:
        signature = hmac.new(
            account.webhook_secret.encode("utf-8"), body, hashlib.sha256
        ).hexdigest()
        headers["X-VMAX-Signature"] = f"sha256={signature}"
    try:
        await client.post(account.webhook_url, content=body, headers=headers)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Webhook delivery failed: %s", exc)


def _send_email_sync(
    settings: Settings, to: str, subject: str, body: str
) -> None:
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
        if settings.smtp_starttls:
            server.starttls()
        if settings.smtp_user:
            server.login(settings.smtp_user, settings.smtp_password)
        server.send_message(message)


async def _send_email(
    settings: Settings, to: str, subject: str, body: str
) -> None:
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, _send_email_sync, settings, to, subject, body)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Email alert failed: %s", exc)


async def dispatch_alerts(
    settings: Settings,
    account: Account,
    result: ScanResult,
    scan_id: str,
) -> None:
    """Fire all configured channels for a completed Pro scan."""

    if not account.is_pro:
        return
    if not _meets_threshold(result, account.alert_min_severity):
        return

    async with httpx.AsyncClient(timeout=10.0) as client:
        if account.slack_webhook_url:
            await _send_slack(
                client,
                account.slack_webhook_url,
                _slack_text(result, scan_id, settings.public_base_url),
            )
        await _send_webhook(client, account, result, scan_id)

    if account.alert_email and settings.email_alerts_configured:
        counts = _summary_counts(result)
        await _send_email(
            settings,
            account.alert_email,
            f"VMAXweb alert: {result.target.host} scored {result.score}/100 ({result.grade})",
            (
                f"Scan of {result.target.url} completed at "
                f"{datetime.now(UTC).isoformat()}.\n"
                f"Grade {result.grade} ({result.score}/100)\n"
                f"critical={counts['critical']} warning={counts['warning']} "
                f"info={counts['info']}\n"
                f"Report: {settings.public_base_url.rstrip('/')}/#scan-{scan_id}"
            ),
        )
