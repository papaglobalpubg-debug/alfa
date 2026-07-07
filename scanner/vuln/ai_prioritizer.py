"""
AI Vulnerability Prioritizer + False-Positive Killer (v7.9.2)

Triple-model voting: sends the same finding to Claude Sonnet 4.6, GPT-5.2, and
Gemini 3 Flash. Each returns a JSON verdict {is_real, severity, priority, why}.
We aggregate the three votes to produce a final `confidence` score (0..1) plus
a resolved severity and priority tier (P0/P1/P2/P3).

All 3 models are called concurrently via asyncio.gather to keep latency low.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from emergentintegrations.llm.chat import LlmChat, UserMessage

_MODELS = [
    ('claude', 'anthropic', 'claude-sonnet-4-6'),
    ('openai', 'openai',    'gpt-5.4-mini'),
    ('gemini', 'gemini',    'gemini-2.5-flash'),
]

_SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']
_PRIORITY_ORDER = ['P3', 'P2', 'P1', 'P0']


SYSTEM_PROMPT = """You are a senior application security engineer triaging web
vulnerability findings. Given a JSON finding, produce ONLY compact JSON:

{
 "is_real": true|false,
 "confidence": 0.0..1.0,
 "severity": "info|low|medium|high|critical",
 "priority": "P0|P1|P2|P3",
 "why": "<one sentence>"
}

Rules:
- If the evidence is a WAF block page, cloudflare challenge, or generic HTML
  error without security impact → is_real=false, severity="info", priority="P3".
- Reflected content that is user-controlled + rendered without escaping is XSS.
- SQLi requires either error strings, boolean-based diff, or time delay.
- SSRF that reaches cloud metadata (169.254.169.254) is always P0.
- RCE / auth bypass / data exposure of PII → P0.
- Missing security headers alone → P3.
- If unsure, is_real=false with confidence<0.5.
- Return ONLY the JSON object. No prose, no code fences."""


def _norm(v: Optional[str], allowed: List[str]) -> Optional[str]:
    if not v:
        return None
    v = str(v).strip().lower()
    for a in allowed:
        if a.lower() == v:
            return a
    return None


async def _vote(model_slug: str, provider: str, model: str, finding: Dict[str, Any]) -> Dict[str, Any]:
    api_key = os.environ.get('EMERGENT_LLM_KEY')
    if not api_key:
        return {'model': model_slug, 'error': 'no_llm_key'}
    try:
        chat = LlmChat(api_key=api_key, session_id=f'triage-{model_slug}',
                       system_message=SYSTEM_PROMPT).with_model(provider, model)
        payload = {
            'type':     finding.get('type'),
            'subtype':  finding.get('subtype'),
            'url':      finding.get('url'),
            'param':    finding.get('param'),
            'severity_hint': finding.get('severity'),
            'evidence': (finding.get('evidence') or '')[:2000],
            'request':  (finding.get('request') or '')[:800],
            'response': (finding.get('response') or '')[:1200],
        }
        resp = await chat.send_message(UserMessage(
            text=json.dumps(payload, ensure_ascii=False)))
        text = str(resp).strip()
        if '```json' in text:
            text = text.split('```json', 1)[1].split('```', 1)[0]
        elif '```' in text:
            text = text.split('```', 1)[1].split('```', 1)[0]
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {'model': model_slug, 'error': 'json_parse', 'raw': text[:200]}
        return {
            'model':      model_slug,
            'is_real':    bool(data.get('is_real', False)),
            'confidence': max(0.0, min(1.0, float(data.get('confidence', 0.5) or 0.5))),
            'severity':   _norm(data.get('severity'), _SEVERITY_ORDER) or 'medium',
            'priority':   _norm(data.get('priority'), _PRIORITY_ORDER) or 'P2',
            'why':        (data.get('why') or '')[:280],
        }
    except Exception as e:
        return {'model': model_slug, 'error': str(e)[:180]}


def _aggregate(votes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Combine 3 model votes into a single verdict.
    Uses majority-of-valid-votes so the endpoint still works when 1 or 2
    providers fail (rate limit / outage)."""
    valid = [v for v in votes if 'error' not in v]
    if not valid:
        return {
            'is_real': False, 'confidence': 0.0, 'severity': 'info',
            'priority': 'P3', 'consensus': 'no_valid_votes',
            'votes_real': 0, 'votes_total': 0,
            'reasoning': 'All models failed to return a valid verdict.',
        }
    real_votes = sum(1 for v in valid if v['is_real'])
    # Majority of the models that actually voted
    threshold = (len(valid) // 2) + 1
    is_real = real_votes >= threshold
    avg_conf = sum(v['confidence'] for v in valid) / len(valid)
    # Reduce confidence if the models disagreed
    consensus_strength = 1.0 if real_votes in (0, len(valid)) else 0.7
    # Also slightly reduce confidence when we lost providers
    availability_factor = len(valid) / len(_MODELS)
    final_conf = avg_conf * consensus_strength * (0.7 + 0.3 * availability_factor)

    def _mode(values, order):
        counts = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        # highest count; break ties by picking the higher position in `order`
        return max(counts.items(), key=lambda kv: (kv[1], order.index(kv[0])))[0]

    sev = _mode([v['severity'] for v in valid], _SEVERITY_ORDER)
    pri = _mode([v['priority'] for v in valid], _PRIORITY_ORDER)
    return {
        'is_real': is_real,
        'confidence': round(final_conf, 2),
        'severity': sev,
        'priority': pri,
        'votes_real': real_votes,
        'votes_total': len(valid),
        'consensus': 'unanimous' if real_votes in (0, len(valid)) else 'split',
        'reasoning': ' · '.join([v.get('why', '') for v in valid if v.get('why')])[:400],
    }


async def triple_vote_verdict(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Run all 3 models concurrently and return the aggregated verdict + raw votes."""
    tasks = [_vote(slug, provider, model, finding) for slug, provider, model in _MODELS]
    votes = await asyncio.gather(*tasks, return_exceptions=False)
    verdict = _aggregate(votes)
    return {'verdict': verdict, 'votes': votes}


async def triage_findings(findings: List[Dict[str, Any]], max_items: int = 20) -> Dict[str, Any]:
    """Batch-triage up to `max_items` findings and split them into P0/P1/P2/P3
    buckets. Runs in parallel across findings but caps concurrency at 4 to keep
    LLM cost predictable."""
    items = (findings or [])[:max_items]
    if not items:
        return {'buckets': {'P0': [], 'P1': [], 'P2': [], 'P3': []},
                'false_positives': [], 'total': 0}
    sem = asyncio.Semaphore(4)

    async def _one(i, f):
        async with sem:
            r = await triple_vote_verdict(f)
            return i, r

    results = await asyncio.gather(*[_one(i, f) for i, f in enumerate(items)])
    buckets: Dict[str, List[Dict[str, Any]]] = {'P0': [], 'P1': [], 'P2': [], 'P3': []}
    fps: List[Dict[str, Any]] = []
    for idx, res in results:
        v = res['verdict']
        row = {
            'index': idx,
            'type':  items[idx].get('type'),
            'url':   items[idx].get('url'),
            'severity': v['severity'],
            'confidence': v['confidence'],
            'consensus': v['consensus'],
            'votes': f"{v['votes_real']}/{v['votes_total']}",
            'reasoning': v['reasoning'],
        }
        if not v['is_real']:
            fps.append(row)
        else:
            buckets[v['priority']].append(row)
    return {
        'buckets': buckets,
        'false_positives': fps,
        'total': len(items),
    }
