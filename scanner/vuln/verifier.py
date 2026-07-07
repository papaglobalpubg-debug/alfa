"""
v7.1 Strict Verifier — reduces false positives on echo/debug endpoints.

Every finding passes through `verify_finding()` which applies vulnerability-
specific verification rules. If a finding fails verification, it is either
downgraded to a lower severity, marked as unverified, or dropped.
"""
import re
from typing import Dict, List, Optional


def _content_type(f: Dict) -> str:
    """Extract content-type hint from finding if available."""
    return (f.get('content_type') or f.get('response_content_type') or '').lower()


def _is_html_response(body: str, content_type: str = '') -> bool:
    """Heuristic: is this response actually HTML?"""
    if 'html' in content_type:
        return True
    if not content_type and body:
        # Empty content-type — look at body
        b = body.lstrip()[:200].lower()
        if b.startswith('<!doctype') or b.startswith('<html'):
            return True
        if '<body' in b or '<script' in b or '<div' in b:
            return True
    return False


def _is_json_response(body: str, content_type: str = '') -> bool:
    if 'json' in content_type:
        return True
    if body:
        b = body.lstrip()[:50]
        if b.startswith('{') or b.startswith('['):
            try:
                import json
                json.loads(body[:2000])
                return True
            except Exception:
                return False
    return False


def _appears_only_in_json_string(payload: str, body: str) -> bool:
    """
    True if the payload appears in the response but ONLY inside JSON string
    values (safe — will not execute as HTML).
    """
    if not payload or payload not in body:
        return False
    # Find payload positions and check surrounding chars
    pos = 0
    all_in_string = True
    any_found = False
    while True:
        idx = body.find(payload, pos)
        if idx < 0:
            break
        any_found = True
        # Look at 30 chars before
        pre = body[max(0, idx - 30):idx]
        # Is it inside JSON string? Count quotes back.
        quote_count = pre.count('"') - pre.count('\\"')
        # If odd number of unescaped quotes, we're inside a string value
        if quote_count % 2 == 0:
            all_in_string = False
            break
        pos = idx + len(payload)
    return any_found and all_in_string


# ============================================================================
# Per-vulnerability verifiers
# ============================================================================
def _verify_xss(f: Dict) -> Optional[Dict]:
    """Strict XSS verification:
    - Response must be HTML (not JSON/text/XML/plain)
    - Payload must be unencoded (no &lt; / \\u003c / %3c around it)
    - Payload must NOT appear only as JSON string value
    """
    evidence = f.get('evidence') or ''
    payload = f.get('payload') or ''
    ct = _content_type(f)

    # If we have content-type info and it's not HTML, drop
    if ct and not _is_html_response(evidence, ct):
        return None

    # If evidence is JSON-shaped, drop
    if _is_json_response(evidence, ct):
        return None

    # If payload appears ONLY in JSON string context, drop
    if payload and _appears_only_in_json_string(payload, evidence):
        return None

    # Check for encoded reflection (safe)
    if payload:
        pl_l = payload.lower()
        for enc in ('&lt;', '&#60;', '&#x3c;', '\\u003c', '%3c'):
            if enc in evidence.lower() and pl_l.replace('<', '').lstrip() and \
               payload not in evidence:
                return None

    # Confidence boost: unique marker found in raw HTML context
    if payload and payload in evidence and any(t in evidence.lower() for t in
                                                ['<script', '<svg', 'onerror=', 'onload=', 'javascript:']):
        f['verified'] = True
        f['confidence'] = max(f.get('confidence', 0), 92)
        return f

    # Weak evidence — keep but downgrade
    f['confidence'] = min(f.get('confidence', 0), 70)
    f['verified'] = False
    return f


def _verify_prototype_pollution(f: Dict) -> Optional[Dict]:
    """
    Real prototype pollution requires PROOF that the pollution PERSISTED into
    a subsequent unrelated request or that JS code reflects the polluted
    property in a NON-echo context.

    If the evidence is just "payload reflected in body" (server echoes back
    query params like httpbin), this is a FALSE POSITIVE.
    """
    evidence = (f.get('evidence') or '').lower()
    ct = _content_type(f)
    # If server just JSON-echoes the input, this is a false positive
    if 'reflected in response' in evidence and _is_json_response(evidence, ct):
        return None
    # Explicit "echo" markers → FP
    if 'polluted marker appears in response body context' in evidence and _is_json_response(evidence, ct):
        return None
    # Weak evidence — downgrade
    if 'reflected in response' in evidence or 'reflection' in evidence:
        f['confidence'] = min(f.get('confidence', 70), 40)
        f['severity'] = 'info'
        f['note'] = ('Payload was reflected but not proven to modify prototype. '
                     'Likely a JSON echo endpoint. Manual verification required.')
        f['verified'] = False
        # Keep as info-level only
    return f


def _verify_host_header(f: Dict) -> Optional[Dict]:
    """
    Host header reflection in body IS NOT ENOUGH — many APIs echo headers back
    for debug (httpbin, /debug, etc). Real host header injection must land in:
      - A Location header (redirect)
      - A link href / form action / canonical URL
      - A password-reset URL
    """
    subtype = f.get('subtype', '')
    evidence = f.get('evidence') or ''

    if subtype == 'redirect':
        # Redirect variant is high-confidence (Location header)
        return f

    if subtype == 'reflected':
        # Check if evidence shows link/URL context, not just body echo
        html_hints = ['<a href=', '<link ', 'canonical', 'og:url', '<form action=', '<meta',
                      'Location:', 'passwordreset', 'password_reset']
        if not any(h.lower() in evidence.lower() for h in html_hints):
            # Just body echo → FALSE POSITIVE
            return None
        f['confidence'] = max(f.get('confidence', 0), 88)
        f['verified'] = True
    return f


WAF_BLOCKED_MARKERS = [
    'access denied', "you don't have permission", 'reference #',
    'blocked by', 'cloudfront', 'akamai', 'request blocked',
    'not authorized to view', 'your request has been blocked',
    'security policy violation', 'the request could not be satisfied',
    '<title>attention required',  # cloudflare
    'error 1020', 'error 1015', 'ray id:',
    'incapsula_resource', 'imperva', 'sucuri',
]


def _is_waf_blocked(text: str) -> bool:
    """Return True if the response body looks like a generic WAF/CDN block page."""
    if not text:
        return False
    tl = text.lower()[:5000]
    hits = sum(1 for m in WAF_BLOCKED_MARKERS if m in tl)
    return hits >= 1


def _verify_cve(f: Dict) -> Optional[Dict]:
    """
    Many CVE templates match on body content. But if the response is a WAF
    Access-Denied page that echoes the requested URL, the match is bogus.
    We drop the finding when:
      - Evidence contains ONLY 'body_match=<X>' where X is a substring of the URL
      - AND the response body indicates a WAF/CDN block
    """
    evidence = (f.get('evidence') or '').strip()
    url = (f.get('url') or '').lower()

    # 1) If evidence includes a body_match, check whether the matched string is
    # merely a substring of the requested URL (WAF echo).
    m = re.search(r'body_match=([^\s|]+)', evidence)
    if m:
        matched = m.group(1).lower().rstrip(',.')
        # If the matched token is present in the URL path itself, it's very
        # likely an echo. Combined with WAF markers → drop.
        if matched and matched in url:
            # Check response snapshot if we have it (some scanners attach it)
            body_snap = (f.get('response_body') or f.get('body') or '').lower()
            if _is_waf_blocked(body_snap) or _is_waf_blocked(evidence):
                return None  # Drop — pure WAF echo false positive
            # Even without body snap, matched-in-URL is suspicious
            f['confidence'] = min(f.get('confidence', 88), 45)
            f['severity'] = 'info'
            f['verified'] = False
            f['note'] = ('CVE body_match token also appears in the URL path — '
                         'likely a WAF/CDN error page echoing the request. '
                         'Requires manual verification.')
            return f

    # 2) If evidence has no content (status-only), keep unverified
    if not evidence and f.get('subtype') not in ('actuator_heapdump', 'git_config', 'env_file'):
        f['confidence'] = min(f.get('confidence', 90), 55)
        f['severity'] = 'medium' if f.get('severity') == 'critical' else f.get('severity')
        f['verified'] = False
        f['note'] = 'CVE template matched by path only. Manual verification required.'
        return f

    f['verified'] = True
    return f


def _verify_exposed_path(f: Dict) -> Optional[Dict]:
    """
    A path returning 403/401 with a generic WAF "Access Denied" page is NOT
    an exposed path — it's the OPPOSITE. Drop such findings.

    A path returning 200 with same content as homepage is a false positive
    (SPA routing catch-all).
    """
    ev = f.get('evidence') or ''
    status = f.get('status', 0)

    # WAF/CDN block page — path is BLOCKED, not exposed
    if _is_waf_blocked(ev):
        return None  # Drop — WAF false positive

    # Interesting statuses (401/403) with distinguishing content only
    if status in (401, 403):
        # Ensure evidence isn't just a generic message
        if len(ev) < 40:
            f['confidence'] = min(f.get('confidence', 0), 45)
            f['severity'] = 'info'
            f['verified'] = False
            return f
        return f

    # 200 with no evidence content → downgrade
    if status == 200 and len(ev) < 30:
        f['confidence'] = min(f.get('confidence', 0), 40)
        f['severity'] = 'info'
        f['verified'] = False
        f['note'] = 'Path returned 200 but no distinguishing content — possibly SPA fallback.'
    return f


def _verify_cors(f: Dict) -> Optional[Dict]:
    """CORS is fine — header-based verification is deterministic."""
    f['verified'] = True
    return f


def _verify_ssrf(f: Dict) -> Optional[Dict]:
    """SSRF cloud_metadata requires specific marker match — already strict."""
    subtype = f.get('subtype', '')
    if subtype.startswith('cloud_metadata_'):
        f['verified'] = True
        return f
    if subtype == 'localhost':
        # Already requires baseline diff + strong markers — trust it
        f['verified'] = True
        return f
    if subtype == 'oob_probe':
        f['verified'] = False  # Can't confirm without OOB callback service
        return f
    return f


def _verify_sqli(f: Dict) -> Optional[Dict]:
    """SQLi error/time/boolean already require strong evidence."""
    f['verified'] = True
    return f


def _verify_cmd(f: Dict) -> Optional[Dict]:
    """cmd injection reflected (uid=X gid=X) is high-confidence."""
    if f.get('subtype') == 'reflected':
        f['verified'] = True
        return f
    if f.get('subtype', '').startswith('time_based'):
        f['verified'] = True
        return f
    if f.get('subtype') == 'oob_probe':
        f['verified'] = False
        return f
    return f


def _verify_open_redirect(f: Dict) -> Optional[Dict]:
    """
    Real open redirect: Location's PRIMARY HOST is attacker-controlled.
    Canonicalization redirects (foo.com → www.foo.com with query preserved)
    are NOT open redirect even if evil.com appears as substring in query.
    """
    redirect_to = f.get('redirect_to') or ''
    ev = f.get('evidence') or ''
    haystack = (redirect_to or ev)
    if not haystack:
        return f  # No evidence to verify — keep as-is

    from urllib.parse import urlparse as _urlparse
    # Extract Location value from evidence like "Location: https://..."
    m = re.search(r'(?:location:\s*)?(https?://[^\s]+|//[^\s]+)', haystack, re.IGNORECASE)
    if not m:
        return f
    loc = m.group(1)
    if loc.startswith('//'):
        loc = 'https:' + loc
    try:
        p = _urlparse(loc)
        host = (p.hostname or '').lower().replace('www.', '')
    except Exception:
        return f
    # Extract target host from finding URL
    try:
        t = _urlparse(f.get('url') or '')
        target = (t.hostname or '').lower().replace('www.', '')
    except Exception:
        target = ''
    if not host:
        return f
    # If Location host equals or is subdomain of target — canonicalization only
    if target and (host == target or host.endswith('.' + target)):
        return None  # DROP false positive
    # Only accept if attacker host is evil.com family
    if host == 'evil.com' or host.endswith('.evil.com'):
        f['verified'] = True
        return f
    # Other cross-domain redirects — keep but downgrade
    f['confidence'] = min(f.get('confidence', 98), 60)
    f['verified'] = False
    return f


def _verify_crlf(f: Dict) -> Optional[Dict]:
    """
    Real CRLF requires the server to PARSE the injected CR/LF into a new header.
    If evidence is just a Location header containing URL-encoded (%0d%0a) or
    double-encoded (%250d%250a) sequences — NOT injection.
    """
    evidence = f.get('evidence') or ''
    ev_l = evidence.lower()
    if 'location:' in ev_l:
        if '%25' in evidence and ('%250d' in evidence or '%250a' in evidence):
            return None
        if ('%0d' in ev_l or '%0a' in ev_l) and '\r\n' not in evidence:
            return None
        if 'injected' not in ev_l and 'set-cookie:' not in ev_l:
            f['confidence'] = min(f.get('confidence', 95), 40)
            f['severity'] = 'info'
            f['verified'] = False
            f['note'] = ('CRLF payload reflected in Location header but the server '
                         'did not parse the injected CR/LF. Not exploitable.')
            return f
    return f


def _verify_secret_leak(f: Dict) -> Optional[Dict]:
    """Secrets found by regex — verify format."""
    val = f.get('value_snippet') or ''
    # Filter common false positives
    if 'test' in val.lower() or 'example' in val.lower() or 'placeholder' in val.lower():
        f['confidence'] = min(f.get('confidence', 90), 50)
        f['severity'] = 'info'
        f['verified'] = False
        f['note'] = 'Secret value contains "test"/"example"/"placeholder" — likely dummy.'
    elif len(val) < 15:
        f['confidence'] = min(f.get('confidence', 90), 55)
        f['verified'] = False
    else:
        f['verified'] = True
    return f


# ============================================================================
# Dispatcher
# ============================================================================
VERIFIERS = {
    'xss': _verify_xss,
    'prototype_pollution': _verify_prototype_pollution,
    'host_header_injection': _verify_host_header,
    'cve': _verify_cve,
    'exposed_path': _verify_exposed_path,
    'crlf': _verify_crlf,
    'cors': _verify_cors,
    'ssrf': _verify_ssrf,
    'sqli': _verify_sqli,
    'command_injection': _verify_cmd,
    'open_redirect': _verify_open_redirect,
    'secret_leak': _verify_secret_leak,
}


def verify_finding(f: Dict) -> Optional[Dict]:
    """
    Apply strict verification. Returns None if false positive should be dropped,
    else returns the (possibly modified) finding dict with 'verified' field.
    """
    if not isinstance(f, dict):
        return f
    vtype = f.get('type', '')
    verifier = VERIFIERS.get(vtype)
    if verifier is None:
        # Unknown type — leave as-is but mark as not explicitly verified
        f.setdefault('verified', False)
        return f
    try:
        return verifier(f)
    except Exception:
        return f  # Never lose findings due to verifier bugs


def verify_all(findings: List[Dict]) -> List[Dict]:
    """Apply verification to a list of findings. Drops false positives."""
    out = []
    dropped = 0
    for f in findings:
        r = verify_finding(f)
        if r is None:
            dropped += 1
            continue
        out.append(r)
    return out


def verification_stats(findings: List[Dict]) -> Dict:
    """Summary stats: verified count, unverified count, by-type."""
    verified = sum(1 for f in findings if f.get('verified') is True)
    unverified = sum(1 for f in findings if f.get('verified') is False)
    unknown = sum(1 for f in findings if 'verified' not in f)
    return {
        'verified': verified, 'unverified': unverified, 'unknown': unknown,
        'total': len(findings),
    }
