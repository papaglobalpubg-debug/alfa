"""
Intelligent Injection Scanners.
Each scanner:
1. Establishes baseline
2. Fingerprints context
3. Selects adaptive payloads
4. Verifies with multi-step logic (no false positives)
"""
import asyncio
import re
import string
import random
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from .http_client import AdaptiveHTTPClient, Response, response_similarity, different_enough
from .fingerprint import Fingerprint
from .payloads import PAYLOADS


def _rand_token(n: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _inject_url_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def _find_reflection(body: str, marker: str) -> List[str]:
    """Return contexts where the marker is reflected."""
    if not body or marker not in body:
        return []
    contexts = []
    idx = 0
    while True:
        pos = body.find(marker, idx)
        if pos < 0:
            break
        # Look at 40 chars before and 40 chars after
        pre = body[max(0, pos - 40):pos]
        post = body[pos + len(marker):pos + len(marker) + 40]
        contexts.append(f'{pre}<<HERE>>{post}')
        idx = pos + len(marker)
        if len(contexts) >= 10:
            break
    return contexts


def _detect_reflection_context(pre: str, post: str) -> str:
    """Return 'html' | 'attribute' | 'js' | 'js_string' | 'url' | 'css'"""
    pre_l = pre.lower()
    if '<script' in pre_l and '</script' not in pre_l:
        # Inside JS
        if pre.rstrip().endswith(("'", '"')):
            return 'js_string'
        return 'js'
    if 'href=' in pre_l[-30:] or 'src=' in pre_l[-30:] or 'action=' in pre_l[-30:]:
        return 'url'
    m = re.search(r'<\w+\s+[^>]*=["\'][^"\']*$', pre)
    if m:
        return 'attribute'
    if '<style' in pre_l or 'style=' in pre_l[-30:]:
        return 'css'
    return 'html'


# ============================================================================
# XSS SCANNER
# ============================================================================
async def scan_xss(client: AdaptiveHTTPClient, url: str, params: List[str],
                   fp: Optional[Fingerprint] = None,
                   waf_bypass: bool = True) -> List[Dict]:
    """
    Context-aware reflected XSS scanner.
    """
    findings = []
    if not params:
        # Try common params
        params = ['q', 'search', 'query', 'id', 'name', 'user', 'lang', 'callback', 'return', 'redirect']

    for param in params:
        marker = f'xz{_rand_token(6)}zx'
        # 1. Test reflection first
        probe_url = _inject_url_param(url, param, marker)
        r = await client.get(probe_url, follow_redirects=False)
        if r.error or marker not in (r.text or ''):
            continue

        # STRICT VERIFICATION #1: Content-Type MUST be HTML.
        # JSON/text/xml/plain responses cannot execute XSS even if reflected.
        ct = (r.headers.get('Content-Type') or r.headers.get('content-type') or '').lower()
        body_start = (r.text or '').lstrip()[:200].lower()
        is_html = ('html' in ct) or (not ct and (body_start.startswith('<!doctype')
                                                 or body_start.startswith('<html')
                                                 or '<body' in body_start))
        is_json = ('json' in ct) or (r.text or '').lstrip().startswith(('{', '['))
        if not is_html or is_json:
            continue  # Not exploitable — skip this param

        contexts = _find_reflection(r.text, marker)
        if not contexts:
            continue

        # 2. Determine context and select payloads
        first_ctx = contexts[0]
        pre, _, post = first_ctx.partition('<<HERE>>')
        context_type = _detect_reflection_context(pre, post)

        payload_pool = []
        if context_type in ('js', 'js_string'):
            payload_pool = PAYLOADS.xss['js_context']
        elif context_type == 'attribute':
            payload_pool = PAYLOADS.xss['attribute_context']
        elif context_type == 'url':
            payload_pool = PAYLOADS.xss['url_context']
        else:
            payload_pool = PAYLOADS.xss['html_context']

        # Always augment with WAF bypasses if there's ANY hint of WAF or filtering
        # (v7: try WAF bypasses even without explicit WAF detection — cheap, high value)
        if PAYLOADS.xss.get('waf_bypass'):
            payload_pool = list(payload_pool) + PAYLOADS.xss['waf_bypass']

        # 3. Verify with actual payload — v7 tries up to 25 payloads (was 15)
        for payload in payload_pool[:25]:
            unique_id = f'xss{_rand_token(4)}'
            testpayload = payload.replace('alert(1)', f'alert("{unique_id}")').replace('confirm(1)', f'confirm("{unique_id}")')
            test_url = _inject_url_param(url, param, testpayload)
            r2 = await client.get(test_url, follow_redirects=False)
            if r2.error:
                continue
            body = r2.text or ''
            # Verify: unencoded reflection AND HTML-executable
            if testpayload in body or (
                unique_id in body and any(t in body.lower() for t in
                                          ['<script', 'onerror=', 'onload=', 'javascript:', '<svg'])):
                findings.append({
                    'type': 'xss',
                    'subtype': 'reflected',
                    'url': test_url,
                    'param': param,
                    'context': context_type,
                    'payload': testpayload,
                    'severity': 'high',
                    'cvss': 6.1,
                    'evidence': body[max(0, body.find(unique_id) - 80):body.find(unique_id) + 80]
                                if unique_id in body else body[:200],
                    'content_type': (r2.headers.get('Content-Type') or r2.headers.get('content-type') or ''),
                    'confidence': 90,
                    'verified': True,
                })
                break  # one confirmed XSS per param is enough
    return findings


# ============================================================================
# SQL INJECTION SCANNER
# ============================================================================
SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySqlException",
    r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"PostgreSQL.*ERROR", r"Warning.*pg_", r"valid PostgreSQL result", r"Npgsql\.",
    r"Driver.* SQL[\-\_ ]*Server", r"OLE DB.* SQL Server", r"\bSQL Server[^&<]+Driver",
    r"Microsoft SQL Native Client error", r"System\.Data\.SqlClient\.SqlException",
    r"ORA-\d{5}", r"Oracle error", r"Oracle.*Driver", r"Warning.*oci_",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
    r"IBM DB2.*(SQL|LI)\-\d+", r"CLI Driver.*DB2", r"Warning.*db2_",
    r"unterminated quoted string", r"unclosed quotation mark",
    r"SQLSTATE\[[A-Z0-9]+\]", r"Uncaught PDOException",
]


async def scan_sqli(client: AdaptiveHTTPClient, url: str, params: List[str],
                    fp: Optional[Fingerprint] = None) -> List[Dict]:
    findings = []
    if not params:
        params = ['id', 'user', 'page', 'category', 'search', 'item', 'product',
                  'uid', 'pid', 'cid', 'gid', 'view', 'article', 'news', 'p']

    dbms_hints = list(fp.probable_dbms) if fp else ['mysql', 'postgresql', 'mssql']

    for param in params:
        # 1. Baseline
        b_val = _rand_token(6)
        r_base = await client.get(_inject_url_param(url, param, b_val))
        if r_base.error:
            continue

        # 2. Error-based — v7 tries 20 payloads (was 8) and uses full extended set
        for p in PAYLOADS.sqli['detection'][:20]:
            r = await client.get(_inject_url_param(url, param, b_val + p))
            if r.error:
                continue
            for pattern in SQL_ERRORS:
                if re.search(pattern, r.text or '', re.IGNORECASE):
                    findings.append({
                        'type': 'sqli', 'subtype': 'error_based',
                        'url': r.url, 'param': param, 'payload': p,
                        'severity': 'critical', 'cvss': 9.8,
                        'evidence': re.search(pattern, r.text, re.IGNORECASE).group(0)[:200],
                        'confidence': 95,
                    })
                    return findings  # short-circuit

        # 3. Boolean-based (compare true vs false response)
        true_r = await client.get(_inject_url_param(url, param, f"{b_val}' AND '1'='1"))
        false_r = await client.get(_inject_url_param(url, param, f"{b_val}' AND '1'='2"))
        if not true_r.error and not false_r.error:
            sim_tb = response_similarity(true_r, r_base)
            sim_fb = response_similarity(false_r, r_base)
            if sim_tb > 0.9 and sim_fb < 0.6:
                findings.append({
                    'type': 'sqli', 'subtype': 'boolean_based',
                    'url': true_r.url, 'param': param,
                    'payload_true': "' AND '1'='1", 'payload_false': "' AND '1'='2",
                    'severity': 'critical', 'cvss': 9.8,
                    'evidence': f'similarity_true={sim_tb:.2f} similarity_false={sim_fb:.2f}',
                    'confidence': 85,
                })
                continue

        # 4. Time-based (last resort — costly)
        for dbms in dbms_hints[:2]:
            payloads = PAYLOADS.sqli['time_based'].get(dbms, [])
            for p in payloads[:2]:
                t0 = time.time()
                r = await client.get(_inject_url_param(url, param, b_val + p))
                dt = time.time() - t0
                if r.error:
                    continue
                if dt > 4.5:  # sleep(5) triggered
                    # Confirm with non-sleep payload
                    t1 = time.time()
                    await client.get(_inject_url_param(url, param, b_val))
                    dt_ref = time.time() - t1
                    if dt > dt_ref + 3.0:
                        findings.append({
                            'type': 'sqli', 'subtype': 'time_based',
                            'url': r.url, 'param': param, 'payload': p,
                            'dbms': dbms, 'delay': f'{dt:.1f}s vs baseline {dt_ref:.1f}s',
                            'severity': 'critical', 'cvss': 9.8, 'confidence': 90,
                        })
                        break
    return findings


# ============================================================================
# NoSQL INJECTION
# ============================================================================
async def scan_nosqli(client: AdaptiveHTTPClient, url: str,
                      params: List[str], is_json: bool = False) -> List[Dict]:
    findings = []
    if not params:
        params = ['id', 'username', 'user', 'email']
    b_val = _rand_token(6)
    baseline = await client.get(_inject_url_param(url, params[0], b_val))
    if baseline.error:
        return findings
    for param in params:
        for p in PAYLOADS.nosqli['mongo_string'][:5]:
            r = await client.get(_inject_url_param(url, param, p))
            if r.error:
                continue
            if different_enough(r, baseline, threshold=0.7) and r.status == 200:
                # Verify negation
                neg = p.replace("'1'=='1", "'1'=='2").replace('true', 'false')
                rn = await client.get(_inject_url_param(url, param, neg))
                if response_similarity(rn, baseline) > 0.85:
                    findings.append({
                        'type': 'nosqli', 'subtype': 'mongo_string_bypass',
                        'url': r.url, 'param': param, 'payload': p,
                        'severity': 'critical', 'cvss': 9.1,
                        'evidence': 'authbypass suspected (200 with payload, distinct from baseline)',
                        'confidence': 80,
                    })
                    break
    return findings


# ============================================================================
# COMMAND INJECTION (time-based + OOB)
# ============================================================================
async def scan_cmd_injection(client: AdaptiveHTTPClient, url: str, params: List[str],
                             oob_host: Optional[str] = None) -> List[Dict]:
    findings = []
    if not params:
        params = ['cmd', 'exec', 'command', 'query', 'ip', 'host', 'domain', 'url', 'file']
    b_val = _rand_token(6)

    for param in params:
        # Time-based unix (must be very strict about network jitter)
        for p in PAYLOADS.cmd['blind_time']['unix'][:3]:
            # Two baselines to establish jitter range
            t_b1 = time.time()
            await client.get(_inject_url_param(url, param, b_val))
            base1 = time.time() - t_b1
            t_b2 = time.time()
            await client.get(_inject_url_param(url, param, b_val + '2'))
            base2 = time.time() - t_b2
            baseline_max = max(base1, base2)

            t0 = time.time()
            r = await client.get(_inject_url_param(url, param, b_val + p))
            dt = time.time() - t0
            if not r.error and dt > 4.8 and dt > baseline_max * 2.5:
                # Confirm with SECOND identical run (must consistently sleep)
                t1 = time.time()
                await client.get(_inject_url_param(url, param, b_val + p))
                dt2 = time.time() - t1
                if dt2 > 4.8:
                    findings.append({
                        'type': 'command_injection', 'subtype': 'time_based_unix',
                        'url': r.url, 'param': param, 'payload': p,
                        'delay': f'{dt:.1f}s / {dt2:.1f}s (baseline max {baseline_max:.1f}s)',
                        'severity': 'critical', 'cvss': 9.8, 'confidence': 95,
                    })
                    return findings

        # Reflected id output
        for p in ['; id', '| id', '&& id', '`id`', '$(id)']:
            r = await client.get(_inject_url_param(url, param, b_val + p))
            if r.error:
                continue
            if re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                findings.append({
                    'type': 'command_injection', 'subtype': 'reflected',
                    'url': r.url, 'param': param, 'payload': p,
                    'severity': 'critical', 'cvss': 9.8, 'confidence': 98,
                    'evidence': re.search(r'uid=\d+.*gid=\d+', r.text).group(0)[:100],
                })
                return findings

        # OOB
        if oob_host:
            for p in PAYLOADS.cmd['blind_oob'][:3]:
                pl = p.replace('{OOB}', oob_host)
                await client.get(_inject_url_param(url, param, b_val + pl))
                # Actual OOB check must be done externally; we record the request
                findings.append({
                    'type': 'command_injection', 'subtype': 'oob_probe',
                    'url': url, 'param': param, 'payload': pl,
                    'severity': 'unknown', 'cvss': 0,
                    'note': f'OOB probe sent — check {oob_host} for callback',
                    'confidence': 0,
                })
    return findings


# ============================================================================
# SSTI SCANNER
# ============================================================================
async def scan_ssti(client: AdaptiveHTTPClient, url: str, params: List[str]) -> List[Dict]:
    findings = []
    if not params:
        params = ['q', 'search', 'name', 'template', 'msg', 'msg', 'lang']

    for param in params:
        # 1. Detection with math — establish baseline to prevent FPs
        baseline_marker = f'ssti_{_rand_token(4)}'
        baseline_r = await client.get(_inject_url_param(url, param, baseline_marker))
        if baseline_r.error:
            continue
        # If baseline marker isn't reflected, param isn't in response — no reflected SSTI
        if baseline_marker not in (baseline_r.text or ''):
            continue

        for probe, expected in [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('<%= 7*7 %>', '49'),
            ('#{7*7}', '49'),
            ('{{7*"7"}}', '7777777'),  # jinja2
        ]:
            r = await client.get(_inject_url_param(url, param, probe))
            if r.error:
                continue
            body = r.text or ''
            # Must contain the evaluated result AND NOT contain the raw template
            if expected in body and probe not in body:
                engine = 'jinja2' if expected == '7777777' else 'unknown'
                findings.append({
                    'type': 'ssti', 'subtype': engine,
                    'url': r.url, 'param': param, 'payload': probe,
                    'expected': expected, 'severity': 'critical', 'cvss': 9.8,
                    'confidence': 95,
                    'evidence': f'{probe} evaluated to {expected}',
                })
                return findings
    return findings


# ============================================================================
# LFI / Path Traversal
# ============================================================================
LFI_MARKERS = [
    r'root:x:0:0:',
    r'root:!:0:0:',
    r'\[extensions\]',  # win.ini
    r'\[fonts\]',
    r'daemon:\*:\d+',
]


async def scan_lfi(client: AdaptiveHTTPClient, url: str, params: List[str]) -> List[Dict]:
    findings = []
    if not params:
        params = ['file', 'path', 'page', 'include', 'template', 'view', 'src', 'doc']

    for param in params:
        for p in PAYLOADS.lfi['unix'][:10]:
            r = await client.get(_inject_url_param(url, param, p))
            if r.error:
                continue
            for marker in LFI_MARKERS:
                if re.search(marker, r.text or ''):
                    findings.append({
                        'type': 'lfi', 'subtype': 'unix',
                        'url': r.url, 'param': param, 'payload': p,
                        'severity': 'critical', 'cvss': 9.8, 'confidence': 98,
                        'evidence': re.search(marker, r.text).group(0)[:100],
                    })
                    return findings
        # Windows
        for p in PAYLOADS.lfi['windows'][:5]:
            r = await client.get(_inject_url_param(url, param, p))
            if r.error:
                continue
            if '[extensions]' in (r.text or '').lower() or '[fonts]' in (r.text or '').lower():
                findings.append({
                    'type': 'lfi', 'subtype': 'windows',
                    'url': r.url, 'param': param, 'payload': p,
                    'severity': 'critical', 'cvss': 9.8, 'confidence': 98,
                })
                return findings
    return findings


# ============================================================================
# XXE (POST XML)
# ============================================================================
async def scan_xxe(client: AdaptiveHTTPClient, url: str,
                   xml_endpoints: Optional[List[str]] = None) -> List[Dict]:
    findings = []
    endpoints = xml_endpoints or [url]
    for ep in endpoints:
        for p in PAYLOADS.xxe['basic'][:3]:
            r = await client.post(ep, data=p, headers={'Content-Type': 'application/xml'})
            if r.error:
                continue
            if 'root:x:' in (r.text or '') or '[extensions]' in (r.text or '').lower():
                findings.append({
                    'type': 'xxe', 'subtype': 'file_read',
                    'url': ep, 'payload': p,
                    'severity': 'critical', 'cvss': 9.8, 'confidence': 98,
                    'evidence': 'File contents in response',
                })
                return findings
        # SVG XXE
        for p in PAYLOADS.xxe['svg_xxe'][:1]:
            r = await client.post(ep, data=p, headers={'Content-Type': 'image/svg+xml'})
            if not r.error and 'root:x:' in (r.text or ''):
                findings.append({
                    'type': 'xxe', 'subtype': 'svg',
                    'url': ep, 'severity': 'critical', 'cvss': 9.1, 'confidence': 95,
                })
                return findings
    return findings
