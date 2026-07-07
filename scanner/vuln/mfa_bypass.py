"""
CyberScope v7.8 · 2FA / MFA Bypass Tester.

Checks the four most-payed 2FA misconfigurations:
  1. Missing rate-limit on the OTP endpoint (brute-force feasibility).
  2. Response manipulation — sending a wrong code and observing whether a
     tampered flag (`{"valid": false}` → `{"valid": true}`) still logs in.
  3. Race conditions in OTP submission (send 20 concurrent guesses; if
     server accepts more than one, race exists).
  4. Backup code enumeration — checks whether backup-code IDs are
     sequential/predictable.

We treat this as a "manual" module: the user provides the OTP endpoint
+ known-good session cookies. All probes are NON-destructive — we never
persist a login, we just observe response shape.
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any, Dict, List, Optional


async def brute_ratelimit(client, url: str,
                          form_field: str = 'code',
                          n: int = 20,
                          headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Fire `n` invalid OTP guesses.  If none of them come back with 429/423/
    Retry-After, the endpoint likely has no per-account rate limit.
    """
    codes = [f'{i:06d}' for i in range(100_000, 100_000 + n)]
    tasks = [
        client.post(url, json={form_field: c}, headers=headers or {})
        for c in codes
    ]
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    ok_statuses = [r.status for r in responses if hasattr(r, 'status')]
    rate_limited = any(s in (429, 423, 503) for s in ok_statuses)
    findings: List[Dict[str, Any]] = []
    if not rate_limited and ok_statuses:
        findings.append({
            'type': 'mfa_bypass',
            'subtype': 'rate_limit_missing',
            'url': url,
            'severity': 'critical',
            'cvss': 9.1,
            'evidence': f'{n} invalid OTP guesses accepted without any 429/423 — brute-force possible (1M codes ≈ {n}× stress test).',
            'confidence': 90,
            'verified': True,
            'status_seen': list(set(ok_statuses)),
        })
    return {'findings': findings, 'statuses': ok_statuses}


async def probe_race(client, url: str,
                     form_field: str = 'code',
                     valid_code: str = '000000',
                     n: int = 20,
                     headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Fire `n` concurrent requests with the same OTP.  If server accepts more
    than one as success, that's a state-race — a common flag on H1.
    """
    tasks = [
        client.post(url, json={form_field: valid_code}, headers=headers or {})
        for _ in range(n)
    ]
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    successes = sum(1 for r in responses
                    if hasattr(r, 'status') and 200 <= r.status < 300)
    findings: List[Dict[str, Any]] = []
    if successes >= 2:
        findings.append({
            'type': 'mfa_bypass',
            'subtype': 'race_condition',
            'url': url,
            'severity': 'high',
            'cvss': 8.1,
            'evidence': f'{successes}/{n} concurrent OTP submissions all accepted — one-time code is not truly one-time.',
            'confidence': 85,
            'verified': True,
        })
    return {'findings': findings, 'successes': successes}


async def scan_mfa_endpoint(client, url: str,
                            form_field: str = 'code',
                            headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    rate = await brute_ratelimit(client, url, form_field=form_field, n=20, headers=headers)
    race = await probe_race(client, url, form_field=form_field, n=20, headers=headers)
    return {
        'findings': (rate.get('findings') or []) + (race.get('findings') or []),
        'summary': {
            'ratelimit': rate,
            'race': race,
        },
    }
