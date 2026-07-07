"""
CyberScope v7.7 · AI Destroyer Mode.

A single LLM-powered pipeline that:
  * Verifies every finding by having Claude Sonnet 4.6 read the actual
    request + response and return {status: 'confirmed'|'needs_manual'|'false_positive',
                                    reason, burp_steps}.
  * Builds novel exploit chains from independent findings.
  * Infers tech stack + WAF + version from headers/body/timings.
  * Crafts context-aware bypass payloads on demand.

Design contract:
  * Every function is graceful when the LLM is unavailable — heuristic
    fallbacks return conservative defaults.
  * Every LLM call is capped in tokens (findings are trimmed before send).
  * Session IDs are unique per finding so LLM caching helps latency.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional


try:
    from emergentintegrations.llm.chat import LlmChat, UserMessage
    _LLM_AVAILABLE = True
except Exception:
    _LLM_AVAILABLE = False


def _api_key() -> Optional[str]:
    return os.environ.get('EMERGENT_LLM_KEY') or None


def _slim(f: Dict, max_evidence: int = 400) -> Dict:
    """Trim a finding down to what the LLM actually needs."""
    return {
        'type': f.get('type'),
        'subtype': f.get('subtype'),
        'severity': f.get('severity'),
        'url': (f.get('url') or '')[:200],
        'method': f.get('method'),
        'param': f.get('param'),
        'payload': (f.get('payload') or '')[:200],
        'evidence': (f.get('evidence') or '')[:max_evidence],
        'response_snippet': (f.get('response_snippet') or '')[:max_evidence],
        'verified': f.get('verified'),
        'confidence': f.get('confidence'),
    }


# ═══════════════════════════ Auto-Verification ═══════════════════════════

_VERIFY_SYSTEM = (
    'You are a senior web-app pentester. Given the raw REQUEST + RESPONSE '
    'evidence of a single finding, grade whether the vulnerability is real. '
    'Return ONE JSON object exactly matching:\n'
    '{"status": "confirmed"|"needs_manual"|"false_positive", '
    '"confidence": 0-100, '
    '"why": "≤200-char explanation", '
    '"burp_steps": "≤500-char step-by-step for Burp Suite Repeater/Intruder", '
    '"manual_curl": "one-line curl to reproduce"}'
)


async def verify_finding(finding: Dict, session_id: str = None) -> Dict:
    """Call the LLM to grade a finding. Heuristic-only fallback if no key."""
    key = _api_key()
    if not (_LLM_AVAILABLE and key):
        # Heuristic fallback
        conf = int(finding.get('confidence') or 0)
        verified = bool(finding.get('verified'))
        if verified and conf >= 80:
            status = 'confirmed'
        elif conf >= 50:
            status = 'needs_manual'
        else:
            status = 'false_positive'
        return {'status': status, 'confidence': conf,
                'why': 'heuristic (no LLM key)',
                'burp_steps': '', 'manual_curl': '',
                'source': 'heuristic'}
    try:
        chat = (LlmChat(api_key=key,
                        session_id=(session_id or 'verify')[:80],
                        system_message=_VERIFY_SYSTEM)
                .with_model('anthropic', 'claude-sonnet-4-6'))
        resp = await chat.send_message(UserMessage(
            text=json.dumps({'finding': _slim(finding)}, ensure_ascii=False)))
        text = str(resp).strip()
        if '```' in text:
            text = text.split('```', 1)[1].split('```', 1)[0]
            if text.lstrip().startswith('json'):
                text = text.split('\n', 1)[1]
        data = json.loads(text)
        data['source'] = 'llm'
        return data
    except Exception as e:
        return {'status': 'needs_manual', 'confidence': 50,
                'why': f'LLM verification failed: {str(e)[:120]}',
                'burp_steps': '', 'manual_curl': '',
                'source': 'error'}


# ═══════════════════════════ Chain Builder ═══════════════════════════

_CHAIN_SYSTEM = (
    'You are an offensive security expert. Given a list of independent web '
    'vulnerabilities on the same target, propose realistic attack chains '
    'that combine them (e.g. XSS + CSRF + IDOR → account takeover). '
    'Return JSON: {"chains": [{"name":"...", "severity":"critical|high|medium", '
    '"steps": ["step1","step2","step3"], "impact":"...", "used_findings":[idx,idx]}]} '
    'Only propose chains where each step is plausibly reachable from the previous. '
    'Do NOT invent findings that were not provided.'
)


async def build_ai_chains(findings: List[Dict], lang: str = 'en') -> Dict:
    key = _api_key()
    if not (_LLM_AVAILABLE and key and findings):
        return {'chains': [], 'source': 'unavailable'}
    slim = [{'id': i, **_slim(f, max_evidence=120)} for i, f in enumerate(findings[:40])]
    try:
        chat = (LlmChat(api_key=key, session_id='chains',
                        system_message=_CHAIN_SYSTEM)
                .with_model('anthropic', 'claude-sonnet-4-6'))
        resp = await chat.send_message(UserMessage(
            text=json.dumps({'findings': slim, 'output_lang': lang},
                            ensure_ascii=False)))
        text = str(resp).strip()
        if '```' in text:
            text = text.split('```', 1)[1].split('```', 1)[0]
            if text.lstrip().startswith('json'):
                text = text.split('\n', 1)[1]
        data = json.loads(text)
        data['source'] = 'llm'
        return data
    except Exception as e:
        return {'chains': [], 'source': 'error', 'error': str(e)[:120]}


# ═══════════════════════════ Auto Payload Crafter ═══════════════════════════

_CRAFT_SYSTEM = (
    'You are an expert exploit developer. Given a target context (WAF, tech '
    'stack, filter behaviour, an initial failed payload), craft 5 alternative '
    'payloads that are LIKELY to bypass the observed filter. Return JSON: '
    '{"payloads": [{"value":"...", "why":"why this bypasses the filter", '
    '"encoding":"raw|url|unicode|comment|other"}]}'
)


async def craft_payload(vulnerability_type: str, waf: str = '', tech: str = '',
                         original_payload: str = '',
                         observed_response: str = '') -> Dict:
    key = _api_key()
    if not (_LLM_AVAILABLE and key):
        # Fallback: generate a canned WAF-bypass set
        from .mutation_engine import bypass
        variants = bypass(original_payload or '<script>alert(1)</script>', waf)
        return {'source': 'heuristic',
                'payloads': [{'value': v, 'why': 'mutation-engine variant',
                               'encoding': 'mixed'} for v in variants[:5]]}
    ctx = json.dumps({
        'vulnerability_type': vulnerability_type,
        'waf': waf, 'tech': tech,
        'original_payload': original_payload[:200],
        'observed_response': observed_response[:600],
    }, ensure_ascii=False)
    try:
        chat = (LlmChat(api_key=key, session_id='craft',
                        system_message=_CRAFT_SYSTEM)
                .with_model('anthropic', 'claude-sonnet-4-6'))
        resp = await chat.send_message(UserMessage(text=ctx))
        text = str(resp).strip()
        if '```' in text:
            text = text.split('```', 1)[1].split('```', 1)[0]
            if text.lstrip().startswith('json'):
                text = text.split('\n', 1)[1]
        data = json.loads(text)
        data['source'] = 'llm'
        return data
    except Exception as e:
        return {'source': 'error', 'error': str(e)[:120], 'payloads': []}


# ═══════════════════════════ Auto-Triage ═══════════════════════════

_TRIAGE_SYSTEM = (
    'You are a bug-bounty triage lead. Given a list of findings, rank each '
    'by real-world exploitability considering: authentication requirement, '
    'user interaction, blast radius, chain potential, and known WAF/tech. '
    'Return JSON: {"triage":[{"id":N,"rank":1..N,"exploitability":0-100,'
    '"tier":"P0|P1|P2|P3","rationale":"..."}]} sorted by rank ascending.'
)


async def auto_triage(findings: List[Dict]) -> Dict:
    """LLM-graded exploitability ranking. Falls back to severity+confidence
    sort if the LLM is unavailable."""
    key = _api_key()
    if not (_LLM_AVAILABLE and key and findings):
        # Heuristic tier ranking
        weight = {'critical': 100, 'high': 80, 'medium': 50, 'low': 30, 'info': 10}
        graded = []
        for i, f in enumerate(findings[:100]):
            e = weight.get(f.get('severity'), 20) + (f.get('confidence') or 0) / 3
            if bool(f.get('verified')):
                e += 20
            e = min(int(e), 100)
            tier = 'P0' if e >= 85 else ('P1' if e >= 65 else ('P2' if e >= 40 else 'P3'))
            graded.append({'id': i, 'exploitability': e, 'tier': tier,
                            'rationale': 'heuristic (no LLM key)'})
        graded.sort(key=lambda x: -x['exploitability'])
        for rank, g in enumerate(graded, 1):
            g['rank'] = rank
        return {'triage': graded, 'source': 'heuristic'}
    slim = [{'id': i, **_slim(f, max_evidence=80)} for i, f in enumerate(findings[:50])]
    try:
        chat = (LlmChat(api_key=key, session_id='triage',
                        system_message=_TRIAGE_SYSTEM)
                .with_model('anthropic', 'claude-sonnet-4-6'))
        resp = await chat.send_message(UserMessage(text=json.dumps({'findings': slim})))
        text = str(resp).strip()
        if '```' in text:
            text = text.split('```', 1)[1].split('```', 1)[0]
            if text.lstrip().startswith('json'):
                text = text.split('\n', 1)[1]
        data = json.loads(text)
        data['source'] = 'llm'
        return data
    except Exception as e:
        return {'triage': [], 'source': 'error', 'error': str(e)[:120]}


# ═══════════════════════════ Response Inference ═══════════════════════════

def infer_from_response(headers: Dict[str, str], body: str = '',
                        timings_ms: Dict[str, float] = None) -> Dict:
    """Pure-Python (no LLM) tech/WAF fingerprinting from response signals."""
    result: Dict[str, Any] = {'tech': [], 'waf': None, 'version_hints': []}
    server = (headers.get('server') or headers.get('Server') or '').lower()
    powered = (headers.get('x-powered-by') or headers.get('X-Powered-By') or '').lower()
    combined = server + '|' + powered
    for waf_name, sig in (
        ('cloudflare', ('cf-ray', 'cloudflare', '__cf_bm')),
        ('akamai', ('akamai', 'x-akamai')),
        ('imperva', ('incap_ses', 'visid_incap')),
        ('awswaf', ('awselb', 'aws-')),
        ('sucuri', ('sucuri',)),
        ('barracuda', ('barra',)),
        ('modsecurity', ('mod_security',)),
    ):
        header_dump = ' '.join([f'{k}: {v}' for k, v in headers.items()]).lower()
        if any(s in header_dump for s in sig):
            result['waf'] = waf_name
            break
    for tech, sig in (
        ('nginx', ('nginx',)), ('apache', ('apache',)),
        ('iis', ('iis', 'microsoft-httpapi')),
        ('php', ('php',)), ('django', ('django',)),
        ('rails', ('rails', 'ruby')), ('express', ('express',)),
        ('nextjs', ('__next_data__',)),
        ('wordpress', ('wp-content', 'wp-json')),
    ):
        if any(s in combined or s in (body or '')[:20000].lower() for s in sig):
            result['tech'].append(tech)
    # Version leaks
    import re
    m = re.search(r'nginx/([0-9.]+)', combined)
    if m:
        result['version_hints'].append(f'nginx/{m.group(1)}')
    m = re.search(r'apache/([0-9.]+)', combined)
    if m:
        result['version_hints'].append(f'apache/{m.group(1)}')
    m = re.search(r'php/([0-9.]+)', combined)
    if m:
        result['version_hints'].append(f'php/{m.group(1)}')
    if timings_ms:
        result['latency_median_ms'] = timings_ms.get('median')
    return result
