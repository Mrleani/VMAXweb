"""Domain ownership verification via DNS TXT records.

Active modules (port scan, subdomain resolution) only run once ownership is
proven. The owner publishes ``vmax-verify=<token>`` as a TXT record on the
target domain; we confirm the record exists before enabling active checks.
"""

from __future__ import annotations

import dns.asyncresolver
import dns.exception
import dns.rdatatype

_PREFIX = "vmax-verify="


async def verify_domain(host: str, token: str) -> bool:
    """Return True when ``host`` publishes the expected TXT token."""

    if not token:
        return False

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answers = await resolver.resolve(host, dns.rdatatype.TXT)
    except (dns.exception.DNSException, OSError):
        return False

    expected = f"{_PREFIX}{token}"
    for rdata in answers:
        value = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if value.strip() == expected:
            return True
    return False
