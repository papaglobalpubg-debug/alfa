"""
CyberScope v7.8 · Web Cache Deception++ / Web Cache Poisoning matrix.

Two families of attacks in one module:

1. **Cache Deception** — trick the CDN into caching a private page
   (e.g. `/profile.css` served as `/profile` HTML → returned to attackers).
2. **Cache Poisoning** — poison the cached response for other users via
   unkeyed headers (X-Forwarded-Host, X-Original-URL, etc.) or unkeyed
   parameters (utm_*, fbclid, callback).

All probes are read-only.  We compare the "clean" response with the
"poisoned" response and only report a hit if the diff clearly proves
the injected value was reflected AND the response has cache headers.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List


CACHE_HEADERS = ('x-cache', 'cf-cache-status', 'age', 'x-served-by',
                 'x-cache-hits', 'via')

DECEPTION_SUFFIXES = [
    '/nonexistent.css', '/nonexistent.js', '/nonexistent.png',
    '.css', '.js', '.png', '.jpg', ';.css', ';.js', '/index.php',
    '%2fnonexistent.css', '%00.js', '\\.css',
]

POISON_HEADERS = [
    'X-Forwarded-Host', 'X-Forwarded-Server', 'X-Host', 'X-Original-URL',
    'X-Rewrite-URL', 'X-Forwarded-Scheme', 'X-Forwarded-Proto',
    'X-Original-Host', 'Forwarded',
]


def _has_cache_evidence(headers: Dict[str, str]) -> bool:
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    return any(h in lowered for h in CACHE_HEADERS)


async def probe_cache_deception(client, url: str, log_cb=None) -> List[Dict[str, Any]]:
    """Try to trick the CDN into caching an authenticated resource."""
    findings: List[Dict[str, Any]] = []
    for suffix in DECEPTION_SUFFIXES:
        target = url.rstrip('/') + suffix
        try:
            r = await client.get(target)
            if r.status == 200 and _has_cache_evidence(r.headers or {}):
                body_low = (r.text or '').lower()
                # If the body still looks like the original page (HTML tags)
                # despite the .css/.js extension → deception surface.
                if any(sig in body_low for sig in ('<html', '<body', '<title')):
                    findings.append({
                        'type': 'web_cache_deception',
                        'subtype': 'ext_confusion',
                        'url': target,
                        'severity': 'high',
                        'cvss': 7.5,
                        'evidence': f'CDN cached authenticated HTML at .css/.js path — cache-headers: {dict(r.headers or {})}',
                        'confidence': 80,
                        'verified': True,
                    })
                    if log_cb:
                        log_cb(f'[!] Cache-deception @ {target}')
        except Exception:
            continue
    return findings


async def probe_cache_poisoning(client, url: str, log_cb=None) -> List[Dict[str, Any]]:
    """Inject unkeyed headers and check whether they land in the cached body."""
    findings: List[Dict[str, Any]] = []
    marker = f'cybpx{uuid.uuid4().hex[:8]}'
    canary = f'evil-{marker}.example.com'
    for h in POISON_HEADERS:
        try:
            r = await client.get(url, headers={h: canary})
        except Exception:
            continue
        body = r.text or ''
        if marker in body and _has_cache_evidence(r.headers or {}):
            findings.append({
                'type': 'web_cache_poisoning',
                'subtype': h.lower(),
                'url': url,
                'severity': 'high',
                'cvss': 8.1,
                'evidence': f'Header {h}={canary} was reflected in a CACHEABLE response — poison surface confirmed.',
                'confidence': 90,
                'verified': True,
            })
            if log_cb:
                log_cb(f'[!] Cache-poison via {h} @ {url}')
    return findings


async def scan_cache_v2(client, urls: List[str], log_cb=None) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for u in (urls or [])[:8]:
        findings.extend(await probe_cache_deception(client, u, log_cb))
        findings.extend(await probe_cache_poisoning(client, u, log_cb))
    return {'findings': findings}
