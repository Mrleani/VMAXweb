"""HTTP security header scanner accuracy tests."""

from __future__ import annotations

import httpx
import pytest

from app.models import Severity
from app.scanners.headers import HeaderScanner
from tests.conftest import make_context


def _handler(headers: dict[str, str], content_type: str = "text/html"):
    def handler(request: httpx.Request) -> httpx.Response:
        merged = {"content-type": content_type, **headers}
        return httpx.Response(200, headers=merged, text="<html></html>")

    return handler


@pytest.mark.asyncio
async def test_missing_hsts_is_critical_and_high_confidence():
    ctx = make_context(_handler({"server": "nginx"}))
    findings = {f.id: f for f in await HeaderScanner().scan(ctx)}
    hsts = findings["headers.hsts"]
    assert hsts.severity is Severity.CRITICAL
    assert hsts.confidence.value == "high"


@pytest.mark.asyncio
async def test_strong_hsts_passes():
    ctx = make_context(
        _handler(
            {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}
        )
    )
    findings = {f.id: f for f in await HeaderScanner().scan(ctx)}
    assert findings["headers.hsts"].severity is Severity.PASSED


@pytest.mark.asyncio
async def test_csp_unsafe_inline_is_warning():
    ctx = make_context(
        _handler({"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"})
    )
    findings = {f.id: f for f in await HeaderScanner().scan(ctx)}
    csp = findings["headers.csp"]
    assert csp.severity is Severity.WARNING
    assert "unsafe" in csp.status.lower()


@pytest.mark.asyncio
async def test_csp_not_applicable_for_non_html():
    ctx = make_context(
        _handler({}, content_type="application/json"),
    )
    findings = {f.id: f for f in await HeaderScanner().scan(ctx)}
    csp = findings["headers.csp"]
    assert csp.severity is Severity.PASSED
    assert "non-html" in csp.status.lower()


@pytest.mark.asyncio
async def test_server_version_disclosure_flagged():
    ctx = make_context(_handler({"server": "nginx/1.18.0"}))
    findings = {f.id: f for f in await HeaderScanner().scan(ctx)}
    assert findings["headers.server_version"].severity is Severity.WARNING
