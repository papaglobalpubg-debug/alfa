"""
CyberScope v7.7.2 · Race Condition Exploiter.

Sends N (default 50) truly-parallel POST/GET requests to a target endpoint
and compares response bodies + status codes to detect race-condition
sensitive endpoints — the poor-man's version of PortSwigger's single-packet
attack (which needs raw HTTP/2 stream control).

Public API:
  race_probe(client, url, method='POST', json_body=None, n=50)
    -> {findings, evidence}
"""
from __future__ import annotations

import asyncio
import hashlib
from typing import Any, Dict, List, Optional


async def _one(client, method: str, url: str,
               json_body: Optional[Dict], headers: Optional[Dict]) -> Dict[str, Any]:
    try:
        if method.upper() == 'POST':
            r = await client.post(url, json=json_body, headers=headers or {})
        else:
            r = await client.get(url, headers=headers or {})
        return {
            'status': r.status,
            'len': len(r.text or ''),
            'hash': hashlib.sha1((r.text or '').encode('utf-8', errors='ignore')).hexdigest()[:12],
            'snippet': (r.text or '')[:200],
        }
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}


async def race_probe(client, url: str, *,
                     method: str = 'POST',
                     json_body: Optional[Dict] = None,
                     headers: Optional[Dict] = None,
                     n: int = 50) -> Dict[str, Any]:
    """
    Fire n concurrent requests via asyncio.gather.  Analyse the responses:
    * If more than one returns HTTP 200 (or 2xx success) when the endpoint
      should be idempotent → potential race
    * If the response hashes vary meaningfully → potential race
    """
    n = max(2, min(n, 200))
    tasks = [_one(client, method, url, json_body, headers) for _ in range(n)]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    ok = [r for r in results if r.get('status') and 200 <= r['status'] < 300]
    hashes = {r.get('hash') for r in results if r.get('hash')}
    status_counts: Dict[int, int] = {}
    for r in results:
        s = r.get('status') or 0
        status_counts[s] = status_counts.get(s, 0) + 1

    findings: List[Dict[str, Any]] = []
    # Heuristic 1: ≥2 successful "create/apply/redeem" responses = classic
    # coupon-double-spend / duplicate-signup / balance-race pattern.
    if len(ok) >= 2 and len(hashes) > 1:
        findings.append({
            'type': 'race_condition',
            'subtype': 'multi_success',
            'url': url,
            'severity': 'high',
            'cvss': 7.5,
            'evidence': f'{len(ok)}/{n} requests returned 2xx with {len(hashes)} distinct response bodies — race surface.',
            'confidence': 78,
            'verified': True,
            'status_counts': status_counts,
        })
    # Heuristic 2: any distinct response body when they should all match
    elif len(ok) == n and len(hashes) > 1:
        findings.append({
            'type': 'race_condition',
            'subtype': 'response_divergence',
            'url': url,
            'severity': 'medium',
            'cvss': 5.4,
            'evidence': f'All {n} concurrent responses succeeded but bodies diverge ({len(hashes)} distinct hashes) — state race probable.',
            'confidence': 65,
            'verified': True,
        })

    return {
        'attempts': n,
        'status_counts': status_counts,
        'unique_hashes': len(hashes),
        'findings': findings,
        'sample_snippet': next((r.get('snippet') for r in results if r.get('snippet')), ''),
    }
