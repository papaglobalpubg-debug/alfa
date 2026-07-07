"""
AI False-Positive Predictor — hybrid heuristic + LLM scoring.

Layer 1 (fast, always on):
  * Reuses `fp_predictor_score()` from ai_explainer for rule-based signals.

Layer 2 (LLM, opt-in per request):
  * Sends compact evidence blocks to Claude Sonnet 4.6 and asks it to grade
    each finding on a 0.0 – 1.0 FP scale with a one-line justification.
  * Falls back to layer 1 if the LLM key is missing or the call fails.

Returned shape (per finding):
  {
    'fp_score': 0.0-1.0,      # combined
    'fp_layer': 'heuristic' | 'llm',
    'fp_reason': 'short human-readable justification',
  }
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from .ai_explainer import fp_predictor_score


try:
    from emergentintegrations.llm.chat import LlmChat, UserMessage
    _LLM_AVAILABLE = True
except Exception:
    _LLM_AVAILABLE = False


HEURISTIC_REASONS = [
    (0.85, 'Very strong FP markers (WAF page, same-domain redirect, JSON XSS).'),
    (0.65, 'Multiple FP signals — likely a false positive.'),
    (0.40, 'Some FP signals present — worth manual review.'),
    (0.20, 'Weak FP signals — probably real.'),
    (0.00, 'No FP signals — high confidence real.'),
]


def _heuristic_reason(score: float) -> str:
    for threshold, reason in HEURISTIC_REASONS:
        if score >= threshold:
            return reason
    return HEURISTIC_REASONS[-1][1]


def heuristic_predict(findings: List[Dict]) -> List[Dict]:
    """Layer-1 scoring — pure Python, zero network."""
    out = []
    for f in findings:
        s = fp_predictor_score(f)
        out.append({
            **f,
            'fp_score': round(s, 3),
            'fp_layer': 'heuristic',
            'fp_reason': _heuristic_reason(s),
        })
    return out


async def llm_predict(findings: List[Dict], lang: str = 'en',
                     max_findings: int = 40) -> List[Dict]:
    """
    Layer-2 scoring — sends a compact batch to Claude and blends its scores
    with the heuristic ones (average). If the LLM is unavailable, returns
    the heuristic result unchanged.
    """
    scored = heuristic_predict(findings)
    api_key = os.getenv('EMERGENT_LLM_KEY')
    if not (_LLM_AVAILABLE and api_key and findings):
        return scored

    compact = []
    for i, f in enumerate(scored[:max_findings]):
        compact.append({
            'id': i,
            'type': f.get('type'),
            'subtype': f.get('subtype'),
            'severity': f.get('severity'),
            'url': (f.get('url') or '')[:150],
            'evidence': (f.get('evidence') or '')[:300],
            'verified': f.get('verified'),
            'confidence': f.get('confidence'),
        })

    sys = (
        'You are a senior web pentester grading whether each finding is a false '
        'positive. For each finding return an fp_score between 0.0 (definitely real) '
        'and 1.0 (definitely FP) plus a ≤80-char reason. '
        'Reply ONLY with JSON: {"scores":[{"id":0,"fp_score":0.1,"reason":"..."}]}'
    )

    try:
        chat = (LlmChat(api_key=api_key, session_id='fp-predict', system_message=sys)
                .with_model('anthropic', 'claude-sonnet-4-6'))
        resp = await chat.send_message(UserMessage(
            text=json.dumps({'findings': compact}, ensure_ascii=False)))
        text = str(resp).strip()
        # Strip code fences
        if '```json' in text:
            text = text.split('```json', 1)[1].split('```', 1)[0]
        elif '```' in text:
            text = text.split('```', 1)[1].split('```', 1)[0]
        data = json.loads(text)
        llm_scores = {item['id']: item for item in data.get('scores', [])}
    except Exception as e:
        # Any parse error → return heuristic only
        for f in scored:
            f['fp_layer'] = 'heuristic'
            f['fp_llm_error'] = str(e)[:120]
        return scored

    # Blend heuristic + LLM (equal weight); LLM reason overrides heuristic one.
    for i, f in enumerate(scored):
        if i in llm_scores:
            llm = llm_scores[i]
            try:
                llm_s = max(0.0, min(1.0, float(llm.get('fp_score', 0.5))))
            except Exception:
                llm_s = 0.5
            f['fp_score_heuristic'] = f['fp_score']
            f['fp_score_llm'] = round(llm_s, 3)
            f['fp_score'] = round((f['fp_score'] + llm_s) / 2, 3)
            f['fp_layer'] = 'llm'
            f['fp_reason'] = str(llm.get('reason', ''))[:200]
    return scored


def bucket(score: float) -> str:
    """UI helper — categorize an fp_score."""
    if score >= 0.7:
        return 'likely_fp'
    if score >= 0.4:
        return 'review'
    return 'likely_real'
