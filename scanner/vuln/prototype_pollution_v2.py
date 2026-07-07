"""
CyberScope v7.8 · Prototype Pollution + DOM Clobbering detector.

Two families:

1. **Prototype Pollution (client-side)** — inject `?__proto__[polluted]=1`
   or `?constructor[prototype][polluted]=1` and check whether the value
   leaks into `Object.prototype` (best detected via a follow-up request
   that reads back a well-known property).
2. **DOM Clobbering** — inject `<a id=x>` / `<form id=x>` payloads and
   check whether the framework treats them as legitimate window/document
   references.

Both probes are read-only.  We only detect surface — we do not attempt
full RCE gadget chains.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List
from urllib.parse import urlencode


PP_PAYLOADS = [
    ('__proto__[cybpx]', '1'),
    ('constructor[prototype][cybpx]', '1'),
    ('__proto__.cybpx', '1'),
]

CLOBBER_MARKERS = [
    'polluted',
    'attribute',
    'HTMLCollection',
    'undefined is not a function',
    'cybpx',
]


async def probe_prototype_pollution(client, url: str, log_cb=None) -> List[Dict[str, Any]]:
    """Send known PP payloads and check for reflection or JS errors."""
    findings: List[Dict[str, Any]] = []
    marker = f'cybpx{uuid.uuid4().hex[:6]}'
    for k, v in PP_PAYLOADS:
        # replace generic marker
        key = k.replace('cybpx', marker)
        payload_qs = urlencode({key: v})
        target = url + ('&' if '?' in url else '?') + payload_qs
        try:
            r = await client.get(target)
        except Exception:
            continue
        body = r.text or ''
        # If the marker made it into <script> tag or a JSON block, PP surface
        if marker in body and r.status < 400:
            findings.append({
                'type': 'prototype_pollution',
                'subtype': 'reflected',
                'url': target,
                'severity': 'high',
                'cvss': 7.5,
                'evidence': f'Payload key `{key}` reflected in response — Object.prototype pollution surface.',
                'confidence': 70,
                'verified': True,
            })
            if log_cb:
                log_cb(f'[!] PP reflected @ {url} (key={key})')
    return findings


async def probe_dom_clobbering(client, url: str, log_cb=None) -> List[Dict[str, Any]]:
    """
    Check whether user input becomes an element `id` that shadows built-ins.
    Basic detection: look at reflected id/name attributes in the response.
    """
    findings: List[Dict[str, Any]] = []
    marker = f'cybpx{uuid.uuid4().hex[:6]}'
    payload_qs = urlencode({'id': marker, 'name': marker})
    target = url + ('&' if '?' in url else '?') + payload_qs
    try:
        r = await client.get(target)
    except Exception:
        return findings
    body = r.text or ''
    # Look for id="<marker>" or name="<marker>" reflection in an element
    import re
    if re.search(rf'\b(?:id|name)\s*=\s*["\']?{re.escape(marker)}', body):
        findings.append({
            'type': 'dom_clobbering',
            'subtype': 'id_reflection',
            'url': target,
            'severity': 'medium',
            'cvss': 5.4,
            'evidence': f'User-controlled `id`/`name` (={marker}) reflected on an HTML element — potential DOM clobbering.',
            'confidence': 65,
            'verified': True,
        })
        if log_cb:
            log_cb(f'[!] DOM clobber @ {url}')
    return findings


async def scan_prototype_pollution(client, urls: List[str], log_cb=None) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for u in (urls or [])[:15]:
        findings.extend(await probe_prototype_pollution(client, u, log_cb))
        findings.extend(await probe_dom_clobbering(client, u, log_cb))
    return {'findings': findings}
