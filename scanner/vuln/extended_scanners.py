"""
v7 Extended Scanners:
- Host Header Injection
- Web Cache Deception
- Client-side Prototype Pollution probe
- CSP misconfiguration audit
- Subresource Integrity audit
- Directory listing detection
- HTTP method tampering (PUT/DELETE)
- CORS with credentials misconfig deep test
"""
import asyncio
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .http_client import AdaptiveHTTPClient
from .payloads import PAYLOADS


async def scan_host_header(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    """Detects Host header reflection / password reset poisoning.

    Strict verification: pure body-echo (like httpbin) is NOT reported.
    Real host injection requires the injected host to appear in:
      - Location header (redirect)
      - <a href / <link href / <form action / <meta property URL contexts
      - Not just JSON echo of headers
    """
    findings: List[Dict] = []
    payloads = getattr(PAYLOADS, 'host_header', []) or []
    baseline = await client.get(url)
    if baseline.error:
        return findings

    def _in_url_context(body: str, host: str) -> bool:
        """Check host appears inside href/action/canonical/og:url etc — not JSON echo."""
        b = body[:20000]
        h = re.escape(host)
        patterns = [
            rf'<a[^>]+href=["\']?[^"\'>]*{h}',
            rf'<link[^>]+href=["\']?[^"\'>]*{h}',
            rf'<form[^>]+action=["\']?[^"\'>]*{h}',
            rf'<meta[^>]+content=["\']?[^"\'>]*{h}',
            rf'canonical[^>]*{h}',
            rf'og:url[^>]*{h}',
            rf'password[_ ]reset[^"\']*{h}',
        ]
        return any(re.search(p, b, re.IGNORECASE) for p in patterns)

    for p in payloads[:6]:
        # Skip payloads that contain \r\n — those break the http client
        if '\r' in p or '\n' in p:
            continue
        r = await client.get(url, headers={'Host': p})
        if r.error:
            continue

        # PRIORITY 1: Location header (real redirect abuse)
        loc = (r.headers.get('Location') or r.headers.get('location') or '')
        clean_host = p.split(':')[0].split('/')[0].split('@')[-1].split('%')[0]
        if clean_host and clean_host in loc:
            findings.append({
                'type': 'host_header_injection', 'subtype': 'redirect',
                'url': url, 'payload': p,
                'severity': 'high', 'cvss': 7.5, 'confidence': 92,
                'evidence': f'Location header contains injected host: {loc[:200]}',
                'verified': True,
            })
            return findings

        # PRIORITY 2: URL context in body (href/action/canonical)
        body = r.text or ''
        ct = r.headers.get('Content-Type') or r.headers.get('content-type') or ''
        if clean_host and _in_url_context(body, clean_host):
            findings.append({
                'type': 'host_header_injection', 'subtype': 'url_context',
                'url': url, 'payload': p,
                'severity': 'high', 'cvss': 7.2, 'confidence': 88,
                'evidence': 'Injected host appears in link/canonical URL context',
                'content_type': ct,
                'verified': True,
            })
            return findings

    return findings


async def scan_web_cache_deception(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    """Cache deception: /account/settings.css may return /account/settings cached."""
    findings: List[Dict] = []
    if url.rstrip('/').count('/') < 3:
        return findings
    base = url.rstrip('/')
    for ext in ('.css', '.js', '.jpg', '.png'):
        probe = base + '/nonexistent' + ext
        r = await client.get(probe)
        if r.error:
            continue
        body = r.text or ''
        # Response contains authenticated-looking content?
        if (len(body) > 500 and any(kw in body.lower() for kw in
                                     ['csrf', 'session', 'account', 'profile', 'logout', 'welcome '])):
            ct = r.headers.get('Content-Type', '')
            if 'html' in ct.lower() and r.status == 200:
                findings.append({
                    'type': 'web_cache_deception',
                    'url': probe,
                    'severity': 'high', 'cvss': 7.2, 'confidence': 70,
                    'evidence': f'{probe} returns HTML with sensitive-looking content',
                })
                return findings
    return findings


async def scan_client_proto_pollution(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    """Client-side proto pollution — probe via URL query.

    Strict: mere reflection of "polluted" (query echo) is NOT a finding.
    Requires marker to appear in a JS/script/prototype context, not just JSON echo.
    """
    findings: List[Dict] = []
    marker = 'ScopeCliPP_' + 'X' * 6
    for p in getattr(PAYLOADS, 'proto_extra', [])[:6]:
        if not p.startswith('{'):
            # Inject unique marker so we can distinguish from JSON echo
            probe_val = p.replace('yes', marker).replace('true', marker)
            probe = url + ('&' if '?' in url else '?') + probe_val
            r = await client.get(probe)
            if r.error:
                continue
            ct = (r.headers.get('Content-Type') or r.headers.get('content-type') or '').lower()
            body = r.text or ''
            # If server just JSON-echoes → false positive, skip
            if 'json' in ct or body.lstrip().startswith(('{', '[')):
                continue
            # Real client-side pollution requires marker in JS/prototype context
            if marker in body and (
                '<script' in body.lower()
                and any(k in body for k in ['__proto__', 'Object.prototype', 'prototype[', '.constructor'])
            ):
                findings.append({
                    'type': 'prototype_pollution',
                    'subtype': 'client_side_confirmed',
                    'url': probe,
                    'payload': probe_val,
                    'severity': 'high', 'cvss': 7.5, 'confidence': 82,
                    'evidence': f'Marker "{marker}" appears within JS/prototype context',
                    'content_type': ct,
                    'verified': True,
                })
                return findings
    return findings


async def scan_csp(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    """Audit CSP for known unsafe directives."""
    findings: List[Dict] = []
    r = await client.get(url)
    if r.error:
        return findings
    csp = r.headers.get('Content-Security-Policy') or r.headers.get('content-security-policy')
    if not csp:
        findings.append({
            'type': 'csp_missing',
            'url': url,
            'severity': 'medium', 'cvss': 5.3, 'confidence': 99,
            'evidence': 'No Content-Security-Policy header present',
        })
        return findings
    issues: List[str] = []
    csp_l = csp.lower()
    if "'unsafe-inline'" in csp_l:
        issues.append("'unsafe-inline' allowed — permits inline scripts")
    if "'unsafe-eval'" in csp_l:
        issues.append("'unsafe-eval' allowed — permits eval()")
    if 'data:' in csp_l and 'script-src' in csp_l:
        issues.append('data: scheme allowed in script-src')
    if '*' in re.sub(r"'[^']*'", '', csp_l):
        issues.append('wildcard * in a directive')
    if 'http:' in csp_l:
        issues.append('http: (insecure) allowed as source')
    if 'default-src' not in csp_l:
        issues.append('default-src missing (fallback vulnerable)')
    if issues:
        findings.append({
            'type': 'csp_weak',
            'url': url,
            'severity': 'medium', 'cvss': 5.3, 'confidence': 95,
            'evidence': '; '.join(issues),
            'csp_value': csp[:400],
        })
    return findings


async def scan_directory_listing(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    """Detect open directory listing."""
    findings: List[Dict] = []
    candidates = ['/', '/uploads/', '/files/', '/images/', '/backup/', '/static/',
                  '/media/', '/assets/', '/download/', '/tmp/', '/logs/']
    base = url.rstrip('/')
    sem = asyncio.Semaphore(6)

    async def _check(p):
        async with sem:
            r = await client.get(base + p)
            if r.error:
                return
            body = (r.text or '').lower()
            markers = ['index of /', '<title>index of', 'directory listing for',
                       'parent directory</a>', '[to parent directory]']
            if any(m in body for m in markers) and r.status == 200:
                findings.append({
                    'type': 'directory_listing',
                    'url': base + p,
                    'severity': 'medium', 'cvss': 5.3, 'confidence': 95,
                    'evidence': f'Open directory listing at {p}',
                })

    await asyncio.gather(*[_check(p) for p in candidates], return_exceptions=True)
    return findings


async def scan_http_methods(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    """Test for allowed dangerous methods: PUT, DELETE, TRACE, PATCH."""
    findings: List[Dict] = []
    # OPTIONS first
    r = await client.request('OPTIONS', url)
    allowed = ''
    if not r.error:
        allowed = (r.headers.get('Allow') or r.headers.get('allow') or '')
    dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH', 'PROPFIND']
    listed = [m for m in dangerous if m in allowed.upper()]
    if listed:
        findings.append({
            'type': 'dangerous_http_methods',
            'url': url,
            'severity': 'medium', 'cvss': 5.3, 'confidence': 90,
            'evidence': f'Allow header exposes: {", ".join(listed)}',
        })
    # Active probe: TRACE
    tr = await client.request('TRACE', url, headers={'X-Custom': 'xss-trace-probe'})
    if not tr.error and 'xss-trace-probe' in (tr.text or ''):
        findings.append({
            'type': 'http_trace_enabled',
            'url': url,
            'severity': 'medium', 'cvss': 5.4, 'confidence': 99,
            'evidence': 'TRACE method echoed custom header (XST risk)',
        })
    # Active probe: PUT
    pu = await client.request('PUT', url + '/vuln_test_v7_probe.txt', data='OK')
    if not pu.error and pu.status in (200, 201, 204):
        findings.append({
            'type': 'http_put_enabled',
            'url': url,
            'severity': 'critical', 'cvss': 9.8, 'confidence': 90,
            'evidence': f'PUT returned {pu.status} — file upload may be possible',
        })
    return findings


async def scan_sri(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    """Check that external scripts use SRI (Subresource Integrity)."""
    findings: List[Dict] = []
    r = await client.get(url)
    if r.error:
        return findings
    body = r.text or ''
    host = urlparse(url).netloc.lower()
    ext_scripts_no_sri = 0
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', body, re.IGNORECASE):
        src = m.group(1)
        tag = m.group(0)
        if src.startswith('http') and host not in src and 'integrity=' not in tag:
            ext_scripts_no_sri += 1
    if ext_scripts_no_sri >= 3:
        findings.append({
            'type': 'missing_sri',
            'url': url,
            'severity': 'low', 'cvss': 3.5, 'confidence': 95,
            'evidence': f'{ext_scripts_no_sri} external scripts loaded without SRI',
        })
    return findings
