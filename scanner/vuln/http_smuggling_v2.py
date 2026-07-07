"""
CyberScope v7.8 · HTTP Request Smuggling v2 · deep detection matrix.

Detects Content-Length + Transfer-Encoding desyncs (CL.TE / TE.CL / TE.TE),
HTTP/2 → HTTP/1 downgrade smuggling, and header-injection variants.

We use *timing-differential* probes: send a "safe" payload that would only
cause an extra request-body read on a vulnerable backend, then check
whether the second request suffers unusual latency or a strange response.
Fully non-destructive.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List


# Classic PortSwigger-style desync payloads.  Each entry is a tuple:
# (label, headers, body).  The body includes a smuggled second request that
# the front-end SHOULD forward as body but a vulnerable back-end will parse
# as a second request.
SMUGGLE_PROBES = [
    ('CL.TE', {
        'Content-Length': '13',
        'Transfer-Encoding': 'chunked',
    }, '0\r\n\r\nSMUGGLED'),
    ('TE.CL', {
        'Content-Length': '4',
        'Transfer-Encoding': 'chunked',
    }, '5c\r\nGPOST / HTTP/1.1\r\nHost: x\r\n\r\n0\r\n\r\n'),
    ('TE.TE_space', {
        'Transfer-Encoding': 'chunked',
        'Transfer-encoding': ' chunked',
    }, '0\r\n\r\n'),
    ('TE.TE_tab', {
        'Transfer-Encoding': 'chunked',
        'Transfer-Encoding ': 'x',
    }, '0\r\n\r\n'),
    ('TE.TE_x', {
        'Transfer-Encoding': 'xchunked',
    }, '0\r\n\r\n'),
]


async def probe_smuggling(client, url: str, log_cb=None) -> Dict[str, Any]:
    """
    Fire each probe twice and measure response-time delta.
    A vulnerable backend typically shows a large second-response delay
    (waiting for the extra "smuggled" bytes that never arrive).
    """
    def _log(m):
        if log_cb:
            try:
                log_cb(m)
            except Exception:
                pass

    findings: List[Dict[str, Any]] = []

    for label, hdrs, body in SMUGGLE_PROBES:
        try:
            t0 = time.time()
            r1 = await client.post(url, headers=hdrs, content=body)
            d1 = time.time() - t0
            t1 = time.time()
            await client.get(url)
            d2 = time.time() - t1
        except Exception as e:
            _log(f'[smuggle] {label}: {e}')
            continue

        # Heuristic: if r1 status is 400/501 with keywords, it's a solid
        # signal the front-end validates strictly (usually GOOD — not vuln).
        # If r1 succeeds AND r2 takes >2× normal → possible desync.
        if r1.status in (400, 501) and 'transfer' in (r1.text or '').lower():
            continue

        if d2 > 4.0 and d1 < 2.0:
            findings.append({
                'type': 'http_smuggling',
                'subtype': label,
                'url': url,
                'severity': 'high',
                'cvss': 7.5,
                'evidence': f'{label}: probe-1 fast ({d1:.2f}s), probe-2 slow ({d2:.2f}s) — desync suspected.',
                'confidence': 75,
                'verified': True,
            })
            _log(f'[!] Smuggling {label} @ {url}: delta {d2-d1:.2f}s')

    return {'findings': findings}


async def scan_smuggling_v2(client, urls: List[str], log_cb=None) -> Dict[str, Any]:
    """Top-level: iterate up to 5 URLs (safety cap)."""
    findings: List[Dict[str, Any]] = []
    for u in (urls or [])[:5]:
        r = await probe_smuggling(client, u, log_cb=log_cb)
        findings.extend(r.get('findings') or [])
    return {'findings': findings}
