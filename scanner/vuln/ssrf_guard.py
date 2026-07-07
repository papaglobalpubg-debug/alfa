"""
SEC-001 fix — Server-Side Request Forgery (SSRF) protection.

Runs BEFORE every outbound HTTP request the scanner makes:

    * Rejects `file://`, `gopher://`, `dict://`, `ftp://` and any non-http(s) scheme
    * Resolves the hostname to *all* A/AAAA records and blocks if any resolve to:
        - Loopback           (127.0.0.0/8, ::1)
        - Link-local         (169.254.0.0/16, fe80::/10)  ← incl. cloud metadata
        - Private RFC1918    (10/8, 172.16/12, 192.168/16, fc00::/7)
        - CGNAT              (100.64.0.0/10)
        - Reserved / unspec  (0.0.0.0/8, 224.0.0.0/4, ::, etc.)
    * Optional allow-list mode: only fetch if hostname is under a user-approved
      root domain (used when a scan is scoped to `example.com` and *.example.com).
    * Configurable escape hatch via env var `CYBERSCOPE_ALLOW_INTERNAL=1` for
      users legitimately scanning their own internal network (they opt in
      explicitly at container startup).

Public API:
    * `SSRFGuardError` — raised when a URL is blocked.
    * `is_url_safe(url, allow_internal=False) -> (bool, reason)`
    * `assert_safe(url, allow_internal=False)` — raises if unsafe.
    * `set_scope_allowlist(roots)` — restrict outbound to these root domains.
"""
from __future__ import annotations

import contextvars
import ipaddress
import os
import socket
from typing import Iterable, Optional, Tuple
from urllib.parse import urlparse


class SSRFGuardError(Exception):
    """Raised when an outbound request targets a blocked host."""


# Only allow http/https. Everything else (file, gopher, dict, ftp, ldap, ...)
# is a common SSRF vector for reading local files or pivoting.
_ALLOWED_SCHEMES = {'http', 'https'}

# Extra hostname-level blocks that dodge DNS resolution (e.g. `localhost.foo`).
_BLOCK_HOST_TOKENS = {
    'localhost', 'localhost.localdomain', 'ip6-localhost',
    'metadata.google.internal', 'metadata.goog', 'metadata',
    'instance-data.ec2.internal', 'instance-data',
}

# v7.6.1 · Per-scan scope allow-list. `contextvars.ContextVar` isolates each
# concurrent scan (asyncio task tree) so scan B can no longer overwrite or
# clear scan A's scope. Fixes the HIGH-severity concurrency defect flagged
# by the code review.
_SCOPE_CTX: contextvars.ContextVar[frozenset] = contextvars.ContextVar(
    'cyberscope_ssrf_scope', default=frozenset(),
)


def set_scope_allowlist(roots: Iterable[str]) -> None:
    """Register root domains for the CURRENT scan / task tree. Empty set
    disables the allow-list (fall back to category blocks only)."""
    cleaned = set()
    for r in roots or []:
        r = (r or '').strip().lower().lstrip('.')
        if r:
            cleaned.add(r)
    _SCOPE_CTX.set(frozenset(cleaned))


def clear_scope_allowlist() -> None:
    _SCOPE_CTX.set(frozenset())


def _in_scope(host: str) -> bool:
    scope = _SCOPE_CTX.get()
    if not scope:
        return True
    host = (host or '').lower()
    for root in scope:
        if host == root or host.endswith('.' + root):
            return True
    return False


def _ip_is_dangerous(ip: ipaddress._BaseAddress) -> Tuple[bool, str]:
    """Categorize an IP for SSRF protection. Returns (blocked, reason)."""
    try:
        if ip.is_loopback:
            return True, 'loopback address'
        if ip.is_link_local:  # 169.254.0.0/16 → includes cloud metadata
            return True, 'link-local address (cloud metadata range)'
        if ip.is_private:
            return True, 'RFC1918 private address'
        if ip.is_reserved or ip.is_unspecified:
            return True, 'reserved/unspecified address'
        if ip.is_multicast:
            return True, 'multicast address'
        # IPv4 specific: CGNAT (100.64.0.0/10) — often internal
        if isinstance(ip, ipaddress.IPv4Address):
            if ipaddress.IPv4Address('100.64.0.0') <= ip <= ipaddress.IPv4Address('100.127.255.255'):
                return True, 'CGNAT address'
            # Older AWS metadata mirror
            if str(ip) == '169.254.169.254':
                return True, 'AWS/GCP/Azure metadata endpoint'
        return False, ''
    except Exception:
        return True, 'unresolvable IP'


def _resolve_all(host: str) -> list[ipaddress._BaseAddress]:
    """Return every IP address the host resolves to. If it's already a literal
    IP, wrap it in a list. Uses socket.getaddrinfo which respects /etc/hosts."""
    try:
        # Try parsing as literal IP first (avoids DNS)
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    ips: list[ipaddress._BaseAddress] = []
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            addr = info[4][0]
            # Strip zone id (e.g. "fe80::1%eth0")
            if '%' in addr:
                addr = addr.split('%', 1)[0]
            try:
                ips.append(ipaddress.ip_address(addr))
            except ValueError:
                continue
    except (socket.gaierror, socket.herror, OSError):
        # Unresolvable host — treat as blocked (defense in depth).
        return []
    return ips


def is_url_safe(url: str, allow_internal: Optional[bool] = None) -> Tuple[bool, str]:
    """
    Return (True, '') if the URL is safe to fetch, otherwise (False, reason).

    * `allow_internal` — override the env-var escape hatch.
    """
    if allow_internal is None:
        allow_internal = os.environ.get('CYBERSCOPE_ALLOW_INTERNAL', '0') == '1'

    if not url or not isinstance(url, str):
        return False, 'empty URL'

    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or 'http').lower()
    if scheme not in _ALLOWED_SCHEMES:
        return False, f'blocked scheme: {scheme}'

    host = (parsed.hostname or '').strip()
    if not host:
        return False, 'missing hostname'

    host_lc = host.lower()
    if host_lc in _BLOCK_HOST_TOKENS:
        return False, f'blocked hostname: {host_lc}'

    # Scope allow-list — hard reject anything outside the current scan's scope.
    if not _in_scope(host_lc):
        return False, f'host {host_lc} outside scan scope'

    if allow_internal:
        return True, ''

    ips = _resolve_all(host)
    if not ips:
        return False, f'DNS resolution failed for {host_lc}'
    for ip in ips:
        blocked, reason = _ip_is_dangerous(ip)
        if blocked:
            return False, f'{host_lc} resolves to {ip} — {reason}'
    return True, ''


def assert_safe(url: str, allow_internal: Optional[bool] = None) -> None:
    ok, reason = is_url_safe(url, allow_internal=allow_internal)
    if not ok:
        raise SSRFGuardError(reason)
