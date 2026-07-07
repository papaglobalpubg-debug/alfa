"""CyberScope v7.9.x - Confidence Scoring & Dedupe."""
import hashlib
from typing import Any, Dict, Iterable, List


_WEIGHTS = {
    'retest_hits':     30,
    'time_blind':      20,
    'semantic_diff':   15,
    'oob_callback':    20,
    'signature_clean': 10,
    'manual_review':    5,
}


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, v))


def compute_confidence(
    *,
    retest_hits: int = 0,
    retest_total: int = 0,
    time_blind_confirmed: bool = False,
    time_blind_delta_s: float = 0.0,
    semantic_diff_score: float = 0.0,
    oob_callback_seen: bool = False,
    waf_signature_seen: bool = False,
    soft_404_seen: bool = False,
) -> Dict[str, Any]:
    score = 0.0
    reasons: List[str] = []
    if retest_total > 0:
        ratio = retest_hits / max(1, retest_total)
        if ratio >= 0.8:
            score += _WEIGHTS['retest_hits']
            reasons.append(f'retest {retest_hits}/{retest_total}')
        elif ratio >= 0.5:
            score += _WEIGHTS['retest_hits'] * 0.6
            reasons.append(f'retest {retest_hits}/{retest_total} (partial)')
    if time_blind_confirmed:
        score += _WEIGHTS['time_blind']
        reasons.append(f'time-blind delta={time_blind_delta_s:.2f}s')
    if semantic_diff_score >= 0.85:
        score += _WEIGHTS['semantic_diff']
        reasons.append(f'strong diff {semantic_diff_score:.2f}')
    elif semantic_diff_score >= 0.5:
        score += _WEIGHTS['semantic_diff'] * 0.5
        reasons.append(f'moderate diff {semantic_diff_score:.2f}')
    if oob_callback_seen:
        score += _WEIGHTS['oob_callback']
        reasons.append('OOB callback')
    if not waf_signature_seen and not soft_404_seen:
        score += _WEIGHTS['signature_clean']
        reasons.append('clean signature')
    score += _WEIGHTS['manual_review']
    reasons.append('base credit')
    score = round(_clamp(score), 1)
    if score >= 85:
        level = 'critical'
    elif score >= 65:
        level = 'high'
    elif score >= 40:
        level = 'medium'
    else:
        level = 'low'
    return {'score': score, 'level': level, 'reasons': reasons}


def attach_confidence(finding: Dict[str, Any], **signals: Any) -> Dict[str, Any]:
    c = compute_confidence(**signals)
    finding['confidence'] = c
    finding['confidence_score'] = c['score']
    return finding


def fingerprint_payload(payload: str) -> str:
    if not payload:
        return ''
    return hashlib.sha1(payload.encode('utf-8', errors='ignore')).hexdigest()[:10]


def dedupe_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for f in findings:
        key = (
            f.get('type', ''),
            f.get('url', ''),
            fingerprint_payload(str(f.get('payload', '') or '')),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
