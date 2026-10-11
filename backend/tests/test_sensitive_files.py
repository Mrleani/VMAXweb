"""Sensitive-file scanner accuracy tests.

The most important cases are the *negative* controls: catch-all (soft-404)
sites and read-only HTML endpoints must never be reported as leaks, while a
genuine artifact must be reported with high confidence.
"""

from __future__ import annotations

import httpx
import pytest

from app.models import Severity
from app.scanners.sensitive_files import SensitiveFileScanner
from tests.conftest import make_context


def _router(routes: dict[str, httpx.Response], default_status: int = 404):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in routes:
            return routes[path]
        return httpx.Response(default_status, text="not found")

    return handler


def _finding(findings, suffix):
    return next(f for f in findings if f.id == f"sensitive_files.{suffix}")


@pytest.mark.asyncio
async def test_real_env_file_is_critical_high_confidence():
    routes = {
        "/.env": httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            text="DB_PASSWORD=supersecret\nAPI_KEY=abc123\n",
        )
    }
    ctx = make_context(_router(routes))
    findings = await SensitiveFileScanner().scan(ctx)
    dotenv = _finding(findings, "dotenv")
    assert dotenv.severity is Severity.CRITICAL
    assert dotenv.confidence.value == "high"


@pytest.mark.asyncio
async def test_soft_404_catch_all_is_not_reported():
    # The site returns the same 200 body for every path, including /\.env.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            text="Oops, page not found",
        )

    ctx = make_context(handler)
    findings = await SensitiveFileScanner().scan(ctx)
    assert _finding(findings, "dotenv").severity is Severity.PASSED


@pytest.mark.asyncio
async def test_html_page_at_env_path_is_not_reported():
    routes = {
        "/.env": httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html><body>KEY=value</body></html>",
        )
    }
    ctx = make_context(_router(routes))
    findings = await SensitiveFileScanner().scan(ctx)
    assert _finding(findings, "dotenv").severity is Severity.PASSED


@pytest.mark.asyncio
async def test_invalid_json_config_is_not_reported():
    routes = {
        "/config.json": httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            text="{ not really json",
        )
    }
    ctx = make_context(_router(routes))
    findings = await SensitiveFileScanner().scan(ctx)
    assert _finding(findings, "config_json").severity is Severity.PASSED


@pytest.mark.asyncio
async def test_real_json_config_is_reported():
    routes = {
        "/config.json": httpx.Response(
            200,
            headers={"content-type": "application/json"},
            text='{"database": {"password": "x"}}',
        )
    }
    ctx = make_context(_router(routes))
    findings = await SensitiveFileScanner().scan(ctx)
    config = _finding(findings, "config_json")
    assert config.severity is Severity.CRITICAL
    assert config.confidence.value == "high"


@pytest.mark.asyncio
async def test_markerless_backup_is_reported_when_site_404s():
    routes = {
        "/backup.zip": httpx.Response(
            200,
            headers={"content-type": "application/zip"},
            content=b"PK\x03\x04binarydata",
        )
    }
    ctx = make_context(_router(routes))
    findings = await SensitiveFileScanner().scan(ctx)
    backup = _finding(findings, "backup_zip")
    assert backup.severity is Severity.CRITICAL


@pytest.mark.asyncio
async def test_markerless_html_catchall_backup_is_not_reported():
    routes = {
        "/backup.zip": httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html>no such file</html>",
        )
    }
    ctx = make_context(_router(routes))
    findings = await SensitiveFileScanner().scan(ctx)
    assert _finding(findings, "backup_zip").severity is Severity.PASSED


@pytest.mark.asyncio
async def test_cookie_flags_detected():
    routes = {
        "/": httpx.Response(
            200,
            headers={
                "content-type": "text/html",
                "set-cookie": "session=abc; SameSite=Lax",
            },
            text="<html></html>",
        )
    }
    ctx = make_context(_router(routes, default_status=404))
    findings = await SensitiveFileScanner().scan(ctx)
    cookie = _finding(findings, "cookie_flags")
    assert cookie.severity is Severity.WARNING
    assert "Secure" in cookie.meta["missing"]["session"]
