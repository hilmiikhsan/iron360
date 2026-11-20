"""Scope enforcement — the core safety invariant of Iron360.

The AI never decides what is in scope. Every host the executor is asked to
touch is checked here against the target's authorized scope. Out-of-scope or
unauthorized requests are hard-rejected before any process is spawned.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from ..models import Target

_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$")


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str


def normalize_host(raw: str) -> str:
    """Strip scheme/port/path, lowercase. Returns bare host or IP."""
    h = raw.strip().lower()
    h = re.sub(r"^[a-z]+://", "", h)          # strip scheme
    h = h.split("/")[0]                        # strip path
    h = h.split("?")[0]
    h = h.rsplit(":", 1)[0] if h.count(":") == 1 and not _is_ipv6(h) else h  # strip :port (keep ipv6)
    return h.strip(".")


def _is_ipv6(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv6Address)
    except ValueError:
        return False


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _host_in(host: str, scope_entry: str) -> bool:
    """A host matches a scope entry if equal, a subdomain of it, or inside its CIDR."""
    host = host.strip().lower().strip(".")
    entry = scope_entry.strip().lower().strip(".")
    if not host or not entry:
        return False
    # CIDR / IP range
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return _is_ip(host) and ipaddress.ip_address(host) in net
        except ValueError:
            return False
    # Exact or subdomain
    if host == entry:
        return True
    if host.endswith("." + entry):
        return True
    return False


def allowed_scope(target: Target) -> list[str]:
    scope = [target.value]
    scope += [s for s in (target.scope_extra or []) if s]
    return scope


def check(target: Target, raw_host: str) -> ScopeDecision:
    """Decide whether `raw_host` may be touched under `target`'s authorization."""
    if not target.authorized:
        return ScopeDecision(False, f"engagement '{target.label}' is not marked authorized (no NDA/SOW reference)")

    host = normalize_host(raw_host)
    if not host:
        return ScopeDecision(False, "empty/invalid host")
    if not (_is_ip(host) or _HOST_RE.match(host)):
        return ScopeDecision(False, f"'{host}' is not a valid hostname or IP")

    for entry in allowed_scope(target):
        if _host_in(host, entry):
            return ScopeDecision(True, f"'{host}' is within scope entry '{entry}'")

    return ScopeDecision(False, f"'{host}' is OUT OF SCOPE for '{target.label}' — executor refuses")
