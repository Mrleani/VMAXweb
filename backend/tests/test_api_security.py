"""API / CORS scanner accuracy tests."""

from __future__ import annotations

import httpx
import pytest

from app.models import Severity
from app.scanners.api_security import ApiSecurityScanner
from tests.conftest import make_context


def _finding(findings, suffix):
    return next(f for f in findings if f.id == f"api.{suffix}")


@pytest.mark.asyncio
async def test_wildcard_with_credentials_is_critical():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(
                204,
                headers={
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                },
            )
        return httpx.Response(200, text="ok")

    ctx = make_context(handler)
    findings = await ApiSecurityScanner().scan(ctx)
    cors = _finding(findings, "cors")
    assert cors.severity is Severity.CRITICAL
    assert cors.confidence.value == "high"


@pytest.mark.asyncio
async def test_arbitrary_origin_reflection_is_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(
                204,
                headers={
                    "access-control-allow-origin": request.headers.get("origin", ""),
                },
            )
        return httpx.Response(200, text="ok")

    ctx = make_context(handler)
    findings = await ApiSecurityScanner().scan(ctx)
    cors = _finding(findings, "cors")
    assert cors.severity in (Severity.WARNING, Severity.CRITICAL)
    assert "reflect" in cors.status.lower()


@pytest.mark.asyncio
async def test_no_cors_is_passed():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    ctx = make_context(handler)
    findings = await ApiSecurityScanner().scan(ctx)
    assert _finding(findings, "cors").severity is Severity.PASSED


@pytest.mark.asyncio
async def test_risky_methods_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(200, headers={"allow": "GET, POST, PUT, DELETE"})
        return httpx.Response(200, text="ok")

    ctx = make_context(handler)
    findings = await ApiSecurityScanner().scan(ctx)
    methods = _finding(findings, "http_methods")
    assert methods.severity is Severity.WARNING
    assert "PUT" in methods.status
