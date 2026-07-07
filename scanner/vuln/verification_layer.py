"""
CyberScope v7.7 · 100% Verification Layer.

Three complementary techniques the scanner applies AFTER a candidate
finding is produced, to remove false positives and reach production-grade
certainty:

  1. `retest_with_variants` — hit the same endpoint with N different
     encoded/mutated payloads and require ≥2 successes before promoting.
  2. `time_blind_statistical` — for time-based injections, hit the target
     20 times (10 with payload, 10 baseline) and compare *median* latencies.
     Only promote if median delta > 2× baseline stddev.
  3. `semantic_diff` — instead of naive text compare, we hash a normalised
     response (strip whitespace, comments, timestamps, csrf tokens) so
     WAF-generated identical challenge pages don't trigger false positives.

The layer also owns an *out-of-band* stub for interactsh-style callbacks
which the caller can wire up to a real interactsh domain via env var
`CYBERSCOPE_OOB_DOMAIN`.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import statistics
import time
from typing import Any, Callable, Dict, List, Optional


# ─────────────── semantic diff ───────────────

_NOISE_PATTERNS = [
    re.compile(r'csrf[_\-]?token["\']?\s*[:=]\s*["\'][^"\']+["\']', re.IGNORECASE),
    re.compile(r'authenticity_token["\']?\s*[:=]\s*["\'][^"\']+["\']', re.IGNORECASE),
    re.compile(r'"?_?ts"?\s*[:=]\s*\d+', re.IGNORECASE),
    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[Z0-9:+\-.]*'),
    re.compile(r'\b[0-9a-f]{32}\b'),  # md5-like
    re.compile(r'\b[0-9a-f]{40}\b'),  # sha1-like
    re.compile(r'<script[^>]*nonce=["\'][^"\']+["\']', re.IGNORECASE),
    re.compile(r'\s+'),
]


def normalize_response(text: str) -> str:
    """Strip volatile bits so unrelated re-renders (timestamps, CSRF tokens,
    nonces, whitespace) don't create false-positive diffs."""
    if not text:
        return ''
    out = text
    for i, pat in enumerate(_NOISE_PATTERNS):
        out = pat.sub(' ' if i == len(_NOISE_PATTERNS) - 1 else 'X', out)
    return out.strip()[:200_000]


def semantic_hash(text: str) -> str:
    return hashlib.sha256(normalize_response(text).encode('utf-8', errors='ignore')).hexdigest()


def semantic_diff(a: str, b: str) -> Dict[str, Any]:
    """Return {'identical': bool, 'similarity': 0..1, 'delta_len': int}."""
    na, nb = normalize_response(a), normalize_response(b)
    if na == nb:
        return {'identical': True, 'similarity': 1.0, 'delta_len': 0}
    # Cheap Jaccard on 4-gram shingles (fast + robust)
    if not na or not nb:
        return {'identical': False, 'similarity': 0.0, 'delta_len': abs(len(a) - len(b))}
    shingles_a = {na[i:i+4] for i in range(len(na) - 3)}
    shingles_b = {nb[i:i+4] for i in range(len(nb) - 3)}
    union = shingles_a | shingles_b
    if not union:
        return {'identical': False, 'similarity': 0.0, 'delta_len': 0}
    inter = shingles_a & shingles_b
    return {'identical': False, 'similarity': round(len(inter) / len(union), 3),
            'delta_len': abs(len(a) - len(b))}


# ─────────────── statistical time-blind ───────────────

async def time_blind_statistical(
    client, url: str, method: str,
    baseline_data: Dict, payload_data: Dict,
    n: int = 10, delay_seconds: int = 5,
    log_cb: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    Fire `n` baseline requests + `n` payload requests. Compare medians and
    stddevs. Return whether the payload consistently added ~delay_seconds.
    """
    async def _one(data):
        t0 = time.time()
        try:
            await client.request(method, url, data=data)
        except Exception:
            pass
        return time.time() - t0

    base_times: List[float] = []
    pl_times: List[float] = []
    for _ in range(n):
        base_times.append(await _one(baseline_data))
        pl_times.append(await _one(payload_data))
    base_med = statistics.median(base_times) if base_times else 0.0
    pl_med = statistics.median(pl_times) if pl_times else 0.0
    base_stdev = statistics.pstdev(base_times) if len(base_times) > 1 else 0.5
    delta = pl_med - base_med
    # Confirm only if delta ≥ 80% of expected AND ≥ 2x baseline stddev
    threshold = max(delay_seconds * 0.8, base_stdev * 2)
    confirmed = delta >= threshold
    result = {
        'confirmed': bool(confirmed),
        'baseline_median_s': round(base_med, 3),
        'payload_median_s': round(pl_med, 3),
        'delta_s': round(delta, 3),
        'baseline_stdev_s': round(base_stdev, 3),
        'expected_delay_s': delay_seconds,
        'threshold_s': round(threshold, 3),
        'samples': n,
    }
    if log_cb:
        log_cb(f'[time-blind] Δ={delta:.2f}s (need≥{threshold:.2f}s) → '
               f'{"CONFIRMED" if confirmed else "reject"}')
    return result


# ─────────────── retest with mutations ───────────────

async def retest_with_variants(
    tester_fn: Callable, base_payload: str,
    min_hits_required: int = 2,
    waf: Optional[str] = None,
    log_cb: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """
    `tester_fn(payload) -> True|False` must be an async callable that
    replays the vulnerability check for ONE payload variant. We generate
    ~10 variants via the mutation engine and require min_hits_required
    successes to promote.
    """
    from .mutation_engine import mutate, bypass
    variants: List[str] = [base_payload]
    variants.extend(bypass(base_payload, waf))
    variants.extend(v['value'] for v in mutate(base_payload,
                    ['url', 'url2', 'html_num', 'js_unicode', 'mixed_case']))
    # Dedupe while preserving order
    seen, ordered = set(), []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            ordered.append(v)

    results = []
    hits = 0
    for v in ordered[:12]:
        try:
            ok = await tester_fn(v)
        except Exception:
            ok = False
        results.append({'payload': v[:120], 'hit': bool(ok)})
        if ok:
            hits += 1
    verdict = hits >= min_hits_required
    if log_cb:
        log_cb(f'[retest] {hits}/{len(results)} variants hit → '
               f'{"CONFIRMED" if verdict else "reject"}')
    return {'confirmed': verdict, 'hits': hits, 'total': len(results),
            'results': results}


# ─────────────── OOB (interactsh-style) ───────────────

OOB_DOMAIN = os.environ.get('CYBERSCOPE_OOB_DOMAIN', '').strip()


def oob_available() -> bool:
    """True if the user configured an interactsh-style callback domain."""
    return bool(OOB_DOMAIN)


def oob_payload(finding_id: str, kind: str = 'http') -> str:
    """
    Return a callback URL the scanner can inject into blind-SSRF/XXE/RCE
    payloads. If no OOB domain is configured, returns a well-known placeholder
    so the finding gets tagged "needs OOB verification".
    """
    if not OOB_DOMAIN:
        return f'https://interactsh.example.invalid/{finding_id}'
    slug = hashlib.sha1(finding_id.encode()).hexdigest()[:12]
    return (f'https://{slug}.{OOB_DOMAIN}/{kind}'
            if kind != 'dns' else f'{slug}.{OOB_DOMAIN}')


async def oob_poll(finding_id: str, timeout_seconds: int = 30) -> Dict[str, Any]:
    """
    Poll the OOB collector for hits on the callback URL. This is a stub —
    integrators can plug in a real interactsh client via the
    `CYBERSCOPE_OOB_POLL_URL` env var (returns JSON list of interactions).
    """
    poll_url = os.environ.get('CYBERSCOPE_OOB_POLL_URL', '').strip()
    if not poll_url:
        return {'available': False, 'hits': [], 'note': 'no OOB collector configured'}
    import httpx
    slug = hashlib.sha1(finding_id.encode()).hexdigest()[:12]
    end = time.time() + timeout_seconds
    hits: List[Dict] = []
    async with httpx.AsyncClient(timeout=5.0) as client:
        while time.time() < end:
            try:
                r = await client.get(f'{poll_url}?slug={slug}')
                if r.status_code == 200:
                    j = r.json()
                    if isinstance(j, list) and j:
                        hits.extend(j)
                        break
            except Exception:
                pass
            await asyncio.sleep(3)
    return {'available': True, 'hits': hits, 'confirmed': bool(hits)}
