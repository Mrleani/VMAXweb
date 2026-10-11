"""URL validation and SSRF protection.

Every scan target must pass through :func:`normalize_target` before any
scanner touches the network. Private, loopback, link-local and cloud
metadata addresses are rejected to prevent the engine being abused as an
SSRF proxy.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from app.core.config import get_settings
from app.models import Target


class TargetValidationError(ValueError):
    """Raised when a target is malformed or unsafe to scan."""


_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
}


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def normalize_target(raw_url: str) -> Target:
    """Parse and validate a user-supplied URL into a :class:`Target`."""

    settings = get_settings()
    if not raw_url or not raw_url.strip():
        raise TargetValidationError("Target URL is required.")

    candidate = raw_url.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parts = urlsplit(candidate)
    scheme = (parts.scheme or "").lower()

    if scheme not in settings.allowed_schemes:
        raise TargetValidationError(
            f"Unsupported scheme '{scheme}'. Only http/https are allowed."
        )

    host = (parts.hostname or "").lower()
    if not host:
        raise TargetValidationError("Target host is missing.")

    if host in _BLOCKED_HOSTNAMES:
        raise TargetValidationError(f"Host '{host}' is not scannable.")

    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:  # invalid port in URL
        raise TargetValidationError("Invalid port in target URL.") from exc

    path = parts.path or "/"

    return Target(url=candidate, scheme=scheme, host=host, port=port, path=path)


async def assert_resolves_safely(host: str) -> None:
    """Resolve ``host`` and ensure none of its addresses are internal.

    Raises :class:`TargetValidationError` when DNS resolution fails or any
    resolved address falls into a blocked range.
    """

    try:
        ipaddress.ip_address(host)
        addresses = [host]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.run_in_executor(
                None, socket.getaddrinfo, host, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise TargetValidationError(f"Could not resolve host '{host}'.") from exc
        addresses = list({info[4][0] for info in infos})

    if not addresses:
        raise TargetValidationError(f"Host '{host}' did not resolve to any address.")

    for address in addresses:
        ip = ipaddress.ip_address(address)
        if _is_blocked_ip(ip):
            raise TargetValidationError(
                f"Host '{host}' resolves to a non-public address ({address})."
            )
