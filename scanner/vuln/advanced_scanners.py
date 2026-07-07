"""
Advanced Web Attacks:
- HTTP Request Smuggling (heuristic detection)
- Web Cache Poisoning
- Prototype Pollution
- Deserialization detection
- GraphQL attacks
"""
import asyncio
import json
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from .http_client import AdaptiveHTTPClient, response_similarity
from .payloads import PAYLOADS


def _inject(url, param, value):
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


# ============================================================================
# HTTP REQUEST SMUGGLING (timing-based detection)
# ============================================================================
async def scan_smuggling(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    """
    Non-destructive timing-based smuggling detection.
    We measure response time when sending contradictory CL/TE headers.
    """
    findings = []
    # CL.TE probe
    try:
        headers = {'Transfer-Encoding': 'chunked', 'Content-Length': '4'}
        body = '1\r\nZ\r\nQ\r\n\r\n'
        t0 = time.time()
        r = await client.post(url, data=body, headers=headers)
        dt = time.time() - t0
        if not r.error and dt > 5.0:
            findings.append({
                'type': 'http_smuggling', 'subtype': 'clte_timeout',
                'url': url, 'delay': f'{dt:.1f}s',
                'severity': 'high', 'cvss': 7.5, 'confidence': 60,
                'note': 'Timeout with CL.TE payload — manual verification required',
            })
    except Exception:
        pass
    # TE.CL probe
    try:
        headers = {'Transfer-Encoding': 'chunked', 'Content-Length': '6'}
        body = '0\r\n\r\nX'
        t0 = time.time()
        r = await client.post(url, data=body, headers=headers)
        dt = time.time() - t0
        if not r.error and dt > 5.0:
            findings.append({
                'type': 'http_smuggling', 'subtype': 'tecl_timeout',
                'url': url, 'delay': f'{dt:.1f}s',
                'severity': 'high', 'cvss': 7.5, 'confidence': 60,
            })
    except Exception:
        pass
    return findings


# ============================================================================
# CACHE POISONING
# ============================================================================
async def scan_cache_poisoning(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    findings = []
    # Detect cache first
    r_base = await client.get(url)
    if r_base.error:
        return findings
    cache_headers = ['X-Cache', 'CF-Cache-Status', 'Age', 'X-Varnish', 'Fastly-Debug-Digest', 'Via']
    has_cache = any(h in r_base.headers for h in cache_headers)
    if not has_cache:
        return findings  # No cache — no poisoning

    # Test unkeyed headers
    for header in PAYLOADS.cache[:5]:
        # Poison
        r1 = await client.get(url, headers={header: 'evil.com'})
        if r1.error:
            continue
        # Check reflection
        if 'evil.com' in (r1.text or '')[:20000]:
            # Second unauth request to see if poisoned
            r2 = await client.get(url)
            if 'evil.com' in (r2.text or '')[:20000]:
                findings.append({
                    'type': 'cache_poisoning', 'subtype': 'unkeyed_header',
                    'url': url, 'header': header, 'value': 'evil.com',
                    'severity': 'high', 'cvss': 8.2, 'confidence': 90,
                    'evidence': 'Injected header value found in subsequent request',
                })
                return findings  # One is enough
    return findings


# ============================================================================
# PROTOTYPE POLLUTION (client-side heuristic + server-side test)
# ============================================================================
async def scan_prototype_pollution(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    findings = []
    marker = 'EmergentPP123'
    # Baseline WITHOUT pollution
    baseline_url = f'{url}{"&" if "?" in url else "?"}nopollute=1'
    await client.get(baseline_url)

    # Query string variant
    test_url = f'{url}{"&" if "?" in url else "?"}__proto__[polluted]={marker}'
    r = await client.get(test_url)
    if not r.error:
        ct = r.headers.get('Content-Type') or r.headers.get('content-type') or ''
        body = r.text or ''
        # False-positive suppression: if server just JSON-echoes the input
        # (e.g., httpbin), it's NOT prototype pollution.
        is_json = 'json' in ct.lower() or body.lstrip().startswith(('{', '['))
        raw_reflection = marker in body
        # Real pollution: marker must appear in a JS/prototype context, NOT just
        # as an echo of the query parameter.
        strong_evidence = (raw_reflection
                           and not is_json
                           and any(m in body for m in ['__proto__', 'Object.prototype',
                                                        '.constructor', 'prototype[',
                                                        'isAdmin', 'admin=true']))
        if strong_evidence:
            findings.append({
                'type': 'prototype_pollution', 'subtype': 'query_string',
                'url': test_url, 'severity': 'high', 'cvss': 7.5, 'confidence': 85,
                'evidence': body[:400],
                'content_type': ct,
                'verified': True,
            })

    # JSON body variant — probe with pollution, then GET a DIFFERENT endpoint
    # to see if pollution persisted across requests.
    r2 = await client.post(url, json={'__proto__': {'polluted': marker}},
                           headers={'Content-Type': 'application/json'})
    if not r2.error and r2.status < 500:
        # Follow-up GET to fresh URL (append unique param to bust cache)
        probe_url = f'{url}{"&" if "?" in url else "?"}_prtc=x'
        r3 = await client.get(probe_url)
        if not r3.error:
            ct3 = r3.headers.get('Content-Type') or r3.headers.get('content-type') or ''
            body3 = r3.text or ''
            # Real cross-request pollution: our unique marker appears in the
            # follow-up response even though we didn't send it in the follow-up.
            # If the response is JSON that echoes ONLY the current request, the
            # marker won't appear (since _prtc=x doesn't contain marker).
            is_json = 'json' in ct3.lower() or body3.lstrip().startswith(('{', '['))
            if marker in body3:
                # Require presence in NON-echo context. For JSON, we only trust
                # if response actually merges pollution state (marker as an
                # object key/property, not string value of an input echo).
                if is_json:
                    # Check if marker appears outside JSON string values
                    from .verifier import _appears_only_in_json_string
                    if _appears_only_in_json_string(marker, body3):
                        pass  # False positive — server just echoes what we sent
                    else:
                        findings.append({
                            'type': 'prototype_pollution', 'subtype': 'json_body_persistent',
                            'url': url, 'severity': 'high', 'cvss': 7.5, 'confidence': 80,
                            'evidence': body3[:400],
                            'content_type': ct3,
                            'verified': True,
                        })
                else:
                    # Non-JSON persistence → strong signal
                    findings.append({
                        'type': 'prototype_pollution', 'subtype': 'json_body_persistent',
                        'url': url, 'severity': 'high', 'cvss': 7.5, 'confidence': 85,
                        'evidence': body3[:400],
                        'content_type': ct3,
                        'verified': True,
                    })
    return findings


# ============================================================================
# GRAPHQL SCANNER
# ============================================================================
async def scan_graphql(client: AdaptiveHTTPClient, base_url: str) -> List[Dict]:
    findings = []
    # 1. Discover GraphQL endpoint
    endpoints = ['/graphql', '/api/graphql', '/v1/graphql', '/query', '/graphiql',
                 '/api/query', '/graphql/console']
    detected = None
    for ep in endpoints:
        url = base_url.rstrip('/') + ep
        r = await client.post(url, json={'query': '{__typename}'},
                              headers={'Content-Type': 'application/json'})
        if r.error:
            continue
        if r.status == 200 and '__typename' in (r.text or ''):
            detected = url
            findings.append({
                'type': 'graphql', 'subtype': 'endpoint_found',
                'url': url, 'severity': 'info', 'cvss': 0,
                'evidence': (r.text or '')[:200], 'confidence': 100,
            })
            break

    if not detected:
        return findings

    # 2. Introspection
    intro_query = PAYLOADS.graphql['introspection'][1]
    r = await client.post(detected, json={'query': intro_query})
    if not r.error and '__schema' in (r.text or ''):
        findings.append({
            'type': 'graphql', 'subtype': 'introspection_enabled',
            'url': detected, 'severity': 'medium', 'cvss': 5.3,
            'confidence': 100,
            'evidence': 'Full schema retrievable',
        })

    # 3. Batching
    batch_r = await client.post(detected, data=json.dumps([{'query': '{__typename}'}] * 20),
                                headers={'Content-Type': 'application/json'})
    if not batch_r.error and batch_r.status == 200 and '__typename' in (batch_r.text or ''):
        findings.append({
            'type': 'graphql', 'subtype': 'batching_enabled',
            'url': detected, 'severity': 'low', 'cvss': 3.7,
            'note': 'Batching enabled — usable for brute force / DoS', 'confidence': 90,
        })

    # 4. Field suggestions (leaks schema even when introspection off)
    r = await client.post(detected, json={'query': '{invalidFieldXYZ}'})
    if not r.error and 'did you mean' in (r.text or '').lower():
        findings.append({
            'type': 'graphql', 'subtype': 'field_suggestions',
            'url': detected, 'severity': 'low', 'cvss': 3.7,
            'note': 'Field suggestions leak schema info', 'confidence': 100,
        })
    return findings


# ============================================================================
# DESERIALIZATION DETECTION
# ============================================================================
DESER_MARKERS = {
    'java': [r'java\.io\.OptionalDataException', r'java\.io\.InvalidClassException',
             r'ClassNotFoundException', r'ObjectInputStream'],
    'php': [r'unserialize\(\)', r'PHP Notice.*unserialize', r'__PHP_Incomplete_Class'],
    'python': [r'pickle\.UnpicklingError', r'_pickle\.UnpicklingError'],
    'dotnet': [r'System\.Runtime\.Serialization', r'ObjectDataProvider'],
    'nodejs': [r'node-serialize', r'_$$ND_FUNC$$_'],
}


async def scan_deserialization(client: AdaptiveHTTPClient, url: str,
                               params: List[str]) -> List[Dict]:
    findings = []
    if not params:
        return findings
    # Probe with malformed base64 payload
    import base64
    probes = {
        'java_bad': base64.b64encode(b'\xac\xed\x00\x05sr\x00\x0cbad.class').decode(),
        'php_bad': base64.b64encode(b'O:8:"stdClass":0:{}').decode(),
        'pickle_bad': base64.b64encode(b'\x80\x03X\x03\x00\x00\x00badq\x00.').decode(),
    }
    for param in params:
        for name, probe in probes.items():
            r = await client.get(_inject(url, param, probe))
            if r.error:
                continue
            for lang, patterns in DESER_MARKERS.items():
                for pattern in patterns:
                    if re.search(pattern, r.text or '', re.IGNORECASE):
                        findings.append({
                            'type': 'deserialization', 'subtype': f'{lang}_error_leak',
                            'url': r.url, 'param': param, 'probe': name,
                            'severity': 'high', 'cvss': 8.1, 'confidence': 80,
                            'evidence': re.search(pattern, r.text, re.IGNORECASE).group(0)[:100],
                        })
                        return findings
    return findings
