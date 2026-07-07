"""
Logic & Access Vulnerability Scanners.
SSRF, Open Redirect, CORS, CRLF, IDOR, JWT
"""
import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
import random
import string
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from .http_client import AdaptiveHTTPClient, response_similarity
from .payloads import PAYLOADS


def _rand_token(n: int = 6) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _inject(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


# ============================================================================
# SSRF (with cloud metadata detection)
# ============================================================================
CLOUD_MARKERS = {
    'aws': [r'ami-id', r'instance-id', r'AccessKeyId', r'SecretAccessKey', r'ami-launch-index'],
    'gcp': [r'compute\.googleapis', r'project-id', r'default/token', r'access_token'],
    'azure': [r'azEnvironment', r'compute', r'"vmId"', r'"osType"'],
    'digitalocean': [r'droplet_id', r'hostname'],
    'alibaba': [r'meta-data'],
    'kubernetes': [r'"kind":\s*"APIVersions"', r'"apiVersion"'],
}


async def scan_ssrf(client: AdaptiveHTTPClient, url: str, params: List[str],
                    oob_host: Optional[str] = None) -> List[Dict]:
    findings = []
    if not params:
        params = ['url', 'uri', 'link', 'src', 'dest', 'redirect', 'callback', 'fetch',
                  'proxy', 'endpoint', 'file', 'load', 'target', 'to', 'return']

    for param in params:
        # 1. Localhost detection — require *distinct* response from baseline
        rand_probe = 'https://example.com/probe' + _rand_token(4)
        baseline = await client.get(_inject(url, param, rand_probe))
        for probe in ['http://127.0.0.1', 'http://localhost', 'http://[::1]']:
            r = await client.get(_inject(url, param, probe))
            if r.error:
                continue
            # SSRF is real only if response DIFFERS from baseline AND contains localhost signals
            if baseline and not baseline.error:
                if response_similarity(r, baseline) > 0.9:
                    continue  # Same as baseline — not exploiting SSRF
            hits = []
            body_l = (r.text or '').lower()
            strong_markers = ['welcome to nginx', 'apache/2', 'welcome to apache', 'phpmyadmin',
                              'directory listing', 'index of /', 'connection refused',
                              'connection reset', 'no route to host', 'network unreachable',
                              'default backend', 'not found on this server']
            if any(m in body_l for m in strong_markers):
                hits.append('localhost service response')
            if hits:
                findings.append({
                    'type': 'ssrf', 'subtype': 'localhost',
                    'url': r.url, 'param': param, 'payload': probe,
                    'severity': 'critical', 'cvss': 9.1, 'confidence': 85,
                    'evidence': (r.text or '')[:200],
                })
                break  # One is enough per param

        # 2. Cloud metadata
        for cloud, urls in PAYLOADS.ssrf['cloud_metadata'].items():
            for probe in urls[:2]:
                headers = {}
                if cloud == 'gcp':
                    headers['Metadata-Flavor'] = 'Google'
                elif cloud == 'azure':
                    headers['Metadata'] = 'true'
                r = await client.get(_inject(url, param, probe), headers=headers)
                if r.error:
                    continue
                body = r.text or ''
                # False-positive suppression: if the response merely echoes back
                # our probe URL (as many debug/echo endpoints do), the substring
                # "default/token" etc. will appear as INPUT ECHO, not as actual
                # metadata leak. We must verify the marker appears in a context
                # OTHER than the raw echoed probe URL.
                # Strategy: split body into (1) portions containing our probe
                # verbatim (echoes) and (2) other portions. Marker must appear
                # in (2) to count as a real leak.
                probe_urlencoded = probe.replace(':', '%3A').replace('/', '%2F')
                # Remove all substrings equal to the probe (raw + urlencoded)
                # from the body before searching for markers.
                stripped = body.replace(probe, '').replace(probe_urlencoded, '')
                for pattern in CLOUD_MARKERS.get(cloud, []):
                    if re.search(pattern, stripped, re.IGNORECASE):
                        findings.append({
                            'type': 'ssrf', 'subtype': f'cloud_metadata_{cloud}',
                            'url': r.url, 'param': param, 'payload': probe,
                            'severity': 'critical', 'cvss': 10.0, 'confidence': 99,
                            'evidence': (r.text or '')[:300],
                            'content_type': (r.headers.get('Content-Type') or ''),
                            'verified': True,
                        })
                        return findings

        # 3. OOB
        if oob_host:
            probe = f'http://{oob_host}/{param}-ssrf'
            await client.get(_inject(url, param, probe))
            findings.append({
                'type': 'ssrf', 'subtype': 'oob_probe',
                'url': url, 'param': param, 'payload': probe,
                'severity': 'unknown', 'cvss': 0,
                'note': f'OOB SSRF probe sent — check {oob_host}', 'confidence': 0,
            })
    return findings


# ============================================================================
# OPEN REDIRECT
# ============================================================================
async def scan_open_redirect(client: AdaptiveHTTPClient, url: str,
                             params: List[str]) -> List[Dict]:
    """
    Real open redirect: 3xx response whose Location header points to the
    ATTACKER host as the primary target — NOT the same domain with the
    payload preserved in a query string (canonicalization redirects).
    """
    findings = []
    if not params:
        params = ['redirect', 'url', 'next', 'return', 'return_url', 'returnUrl',
                  'continue', 'dest', 'destination', 'redir', 'redirect_uri', 'redirect_url',
                  'go', 'target', 'to', 'link', 'goto']

    target_host = (urlparse(url).hostname or '').lower().replace('www.', '')

    def _location_goes_to_evil(loc: str) -> bool:
        """
        Parse Location. Return True only if the PRIMARY host of the URL is evil.com
        (not just a query-string substring).
        """
        if not loc:
            return False
        # Handle scheme-relative //evil.com/...
        if loc.startswith('//'):
            loc_scheme = 'https:' + loc
        elif loc.startswith('/'):
            # Same-host relative — never open redirect (unless it's // which we
            # handled above)
            return False
        else:
            loc_scheme = loc
        try:
            parsed = urlparse(loc_scheme)
        except Exception:
            return False
        host = (parsed.hostname or '').lower().replace('www.', '')
        if not host:
            return False
        # If the redirect goes to a SAME-DOMAIN host (or a subdomain of target),
        # that's a canonicalization redirect — the payload in query string is
        # NOT exploitable.
        if host == target_host or host.endswith('.' + target_host):
            return False
        # Real open redirect: primary host is evil-controlled
        if host == 'evil.com' or host.endswith('.evil.com'):
            return True
        return False

    for param in params:
        for p in PAYLOADS.open_redirect[:15]:
            r = await client.get(_inject(url, param, p), follow_redirects=False)
            if r.error:
                continue
            loc = r.headers.get('Location') or r.headers.get('location') or ''
            if r.status in (301, 302, 303, 307, 308) and loc:
                if _location_goes_to_evil(loc):
                    findings.append({
                        'type': 'open_redirect', 'subtype': '3xx',
                        'url': _inject(url, param, p), 'param': param, 'payload': p,
                        'redirect_to': loc,
                        'severity': 'medium', 'cvss': 6.1, 'confidence': 98,
                        'evidence': f'Location: {loc[:200]}',
                        'verified': True,
                    })
                    break
            # Meta-refresh / JS redirect
            body = (r.text or '')[:5000]
            if re.search(r'<meta[^>]+http-equiv=[\'"]?refresh[^>]+evil\.com', body, re.IGNORECASE) or \
               re.search(r'(?:location\.href|location\.replace|window\.location)\s*=\s*[\'"][^\'"]*evil\.com', body):
                findings.append({
                    'type': 'open_redirect', 'subtype': 'meta_js',
                    'url': _inject(url, param, p), 'param': param, 'payload': p,
                    'severity': 'medium', 'cvss': 5.4, 'confidence': 90,
                    'verified': True,
                })
                break
    return findings


# ============================================================================
# CORS MISCONFIGURATION
# ============================================================================
async def scan_cors(client: AdaptiveHTTPClient, url: str) -> List[Dict]:
    findings = []
    target_domain = urlparse(url).hostname or ''
    origins = [
        'https://evil.com',
        'null',
        f'https://{target_domain}.evil.com',
        f'https://evil.{target_domain}',
        f'https://{target_domain}evil.com',
        'http://' + target_domain,
    ]
    for origin in origins:
        r = await client.get(url, headers={'Origin': origin})
        if r.error:
            continue
        aco = r.headers.get('Access-Control-Allow-Origin') or r.headers.get('access-control-allow-origin')
        acc = r.headers.get('Access-Control-Allow-Credentials') or r.headers.get('access-control-allow-credentials')
        if not aco:
            continue
        aco_v = aco.strip()
        # Wildcard * WITHOUT credentials is fine — skip
        if aco_v == '*' and (acc or '').lower() != 'true':
            continue
        if aco_v == origin:
            sev = 'high' if (acc or '').lower() == 'true' else 'medium'
            findings.append({
                'type': 'cors', 'subtype': 'origin_reflection',
                'url': url, 'origin_sent': origin,
                'aco': aco_v, 'credentials': acc or 'false',
                'severity': sev, 'cvss': 8.0 if sev == 'high' else 5.4,
                'confidence': 95,
            })
        elif aco_v == '*' and (acc or '').lower() == 'true':
            findings.append({
                'type': 'cors', 'subtype': 'wildcard_with_credentials',
                'url': url, 'aco': aco_v, 'credentials': acc,
                'severity': 'high', 'cvss': 8.0, 'confidence': 99,
            })
    return findings


# ============================================================================
# CRLF INJECTION
# ============================================================================
async def scan_crlf(client: AdaptiveHTTPClient, url: str, params: List[str]) -> List[Dict]:
    """
    CRLF injection: only report when the server ACTUALLY parses the injected
    CR/LF and produces a new header. String reflection in Location value
    (URL-encoded or double-encoded) is NOT injection.
    """
    findings = []
    if not params:
        params = ['redirect', 'url', 'lang', 'query', 'next']
    for param in params:
        for p in PAYLOADS.crlf[:5]:
            r = await client.get(_inject(url, param, p), follow_redirects=False)
            if r.error:
                continue
            # STRICT check: look for the injected header as an ACTUAL parsed
            # header in the response — meaning the server split on CR/LF.
            # The payloads inject headers like "X-Injected: 1", "Set-Cookie:
            # crlf=x", "crlf: injected".
            for hk, hv in r.headers.items():
                # Only accept if the header NAME itself is the injected marker,
                # OR the value is EXACTLY the injected marker (not just contains).
                hk_l = hk.lower()
                hv_l = str(hv).lower()
                if hk_l in ('x-injected', 'x-injected-header') and hv_l in ('1', 'yes', 'crlf'):
                    findings.append({
                        'type': 'crlf', 'subtype': 'header_injection',
                        'url': r.url, 'param': param, 'payload': p,
                        'severity': 'high', 'cvss': 7.4, 'confidence': 98,
                        'evidence': f'Injected header parsed by server: {hk}: {hv}',
                        'verified': True,
                    })
                    return findings
                if hk_l == 'set-cookie' and 'crlf' in hv_l and '=' in hv_l:
                    # Confirm it's OUR injection, not a normal cookie
                    if hv_l.startswith('crlf='):
                        findings.append({
                            'type': 'crlf', 'subtype': 'cookie_injection',
                            'url': r.url, 'param': param, 'payload': p,
                            'severity': 'high', 'cvss': 7.4, 'confidence': 95,
                            'evidence': f'Injected Set-Cookie via CRLF: {hv}',
                            'verified': True,
                        })
                        return findings
    return findings


# ============================================================================
# JWT VULN SCANNER
# ============================================================================
def _b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def analyze_jwt(token: str) -> Dict:
    """Static JWT analysis (no HTTP)."""
    parts = token.split('.')
    if len(parts) != 3:
        return {'valid_format': False}
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return {'valid_format': False}
    result = {
        'valid_format': True,
        'header': header, 'payload': payload,
        'alg': header.get('alg'),
        'issues': [],
    }
    alg = (header.get('alg') or '').lower()
    if alg == 'none':
        result['issues'].append({
            'issue': 'alg_none', 'severity': 'critical',
            'desc': 'JWT signed with "none" algorithm — bypass possible',
        })
    if alg == 'hs256':
        result['issues'].append({
            'issue': 'hs256_weak_secret_possible', 'severity': 'medium',
            'desc': 'HS256 — brute force secret with wordlist (jwt_tool / hashcat)',
        })
    if header.get('jku'):
        result['issues'].append({
            'issue': 'jku_present', 'severity': 'high',
            'desc': 'jku header — try SSRF/attacker-controlled JWKS URL',
        })
    if header.get('kid'):
        result['issues'].append({
            'issue': 'kid_present', 'severity': 'medium',
            'desc': 'kid header — test SQLi/path traversal in kid',
        })
    if not payload.get('exp'):
        result['issues'].append({
            'issue': 'no_expiry', 'severity': 'medium', 'desc': 'JWT has no exp claim',
        })
    return result


def try_bruteforce_hs256(token: str, wordlist: Optional[List[str]] = None) -> Optional[str]:
    """Try common secrets — returns secret if match."""
    words = wordlist or PAYLOADS.jwt['weak_secrets']
    parts = token.split('.')
    if len(parts) != 3:
        return None
    signing_input = f'{parts[0]}.{parts[1]}'.encode()
    given_sig = parts[2]
    for secret in words:
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if _b64url_encode(sig) == given_sig:
            return secret
    return None


def craft_none_algo_token(token: str) -> str:
    """Create a 'none' algo variant of a JWT."""
    parts = token.split('.')
    if len(parts) != 3:
        return ''
    try:
        header = json.loads(_b64url_decode(parts[0]))
        header['alg'] = 'none'
        new_h = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        return f'{new_h}.{parts[1]}.'
    except Exception:
        return ''


async def scan_jwt(client: AdaptiveHTTPClient, url: str, token: str) -> List[Dict]:
    findings = []
    analysis = analyze_jwt(token)
    if not analysis.get('valid_format'):
        return findings
    for issue in analysis['issues']:
        findings.append({
            'type': 'jwt', 'subtype': issue['issue'],
            'url': url, 'severity': issue['severity'],
            'desc': issue['desc'], 'confidence': 70,
        })
    # Brute force HS256
    if (analysis.get('alg') or '').lower() == 'hs256':
        secret = try_bruteforce_hs256(token)
        if secret is not None:
            findings.append({
                'type': 'jwt', 'subtype': 'weak_hs256_secret',
                'url': url, 'severity': 'critical', 'cvss': 9.8,
                'secret_found': secret, 'confidence': 100,
            })
    # None algo test
    none_token = craft_none_algo_token(token)
    if none_token:
        r = await client.get(url, headers={'Authorization': f'Bearer {none_token}'})
        r2 = await client.get(url, headers={'Authorization': f'Bearer {token}'})
        if r.status == r2.status and r.status < 400 and not r.error:
            findings.append({
                'type': 'jwt', 'subtype': 'none_algo_accepted',
                'url': url, 'severity': 'critical', 'cvss': 9.8,
                'evidence': f'status with none={r.status} status with original={r2.status}',
                'confidence': 90,
            })
    return findings


# ============================================================================
# IDOR (Insecure Direct Object Reference)
# ============================================================================
async def scan_idor(client: AdaptiveHTTPClient, url: str, session_a_cookies: Optional[Dict] = None,
                    session_b_cookies: Optional[Dict] = None,
                    id_params: Optional[List[str]] = None) -> List[Dict]:
    """
    Compare responses across two auth sessions. Requires user to supply two sets
    of cookies (session_a = victim, session_b = attacker).
    """
    findings = []
    if not (session_a_cookies and session_b_cookies):
        return findings  # Cannot IDOR-test without two sessions

    r_a = await client.get(url, cookies=session_a_cookies)
    r_b = await client.get(url, cookies=session_b_cookies)
    if r_a.error or r_b.error:
        return findings
    if r_a.status == 200 and r_b.status == 200:
        sim = response_similarity(r_a, r_b)
        if sim > 0.9:
            findings.append({
                'type': 'idor', 'subtype': 'cross_session_access',
                'url': url, 'severity': 'high', 'cvss': 7.5, 'confidence': 80,
                'evidence': f'Two distinct sessions return near-identical responses (sim={sim:.2f})',
            })
    return findings
