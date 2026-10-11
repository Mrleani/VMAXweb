"""Shared pytest fixtures and helpers.

Every test drives a scanner through an ``httpx.MockTransport`` so results are
fully deterministic — no live network, no flakiness. This is what lets us
assert *both* false-positive and false-negative behaviour precisely.
"""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from app.core.config import Settings
from app.models import Target
from app.scanners.base import ScanContext


def make_target(url: str = "https://example.com") -> Target:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = parsed.hostname or "example.com"
    port = parsed.port or (443 if scheme == "https" else 80)
    return Target(url=url, scheme=scheme, host=host, port=port, path=parsed.path or "/")


def make_context(handler, url: str = "https://example.com") -> ScanContext:
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    return ScanContext(target=make_target(url), client=client, settings=Settings())
