"""Subdomain scanner accuracy tests (network-free paths)."""

from __future__ import annotations

import httpx
import pytest

from app.models import Severity
from app.scanners.subdomains import SubdomainScanner
from tests.conftest import make_context


@pytest.mark.asyncio
async def test_ct_log_failure_is_low_confidence_not_false_pass():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    ctx = make_context(handler)
    findings = await SubdomainScanner().scan(ctx)
    discovery = next(f for f in findings if f.id == "subdomains.discovery")
    assert discovery.severity is Severity.INFO
    assert "unavailable" in discovery.status.lower()
    assert discovery.confidence.value == "low"


@pytest.mark.asyncio
async def test_empty_ct_result_passes_with_high_confidence():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    ctx = make_context(handler)
    findings = await SubdomainScanner().scan(ctx)
    discovery = next(f for f in findings if f.id == "subdomains.discovery")
    assert discovery.severity is Severity.PASSED
    assert discovery.confidence.value == "high"
