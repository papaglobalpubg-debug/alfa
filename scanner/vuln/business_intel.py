"""
CyberScope v7.8 · Business Impact & Bounty Estimator.

Two calculators in one file (they share the severity → dollar mapping):

  1. `estimate_bounty(findings)` — projects expected bug-bounty earnings
     based on HackerOne / Bugcrowd public payout data. Uses a conservative
     median payout per severity + subtype modifier.
  2. `estimate_business_impact(findings)` — projects breach-scenario cost
     (GDPR fine + remediation + reputation).  Based on IBM 2024 Cost of
     Breach Report ($4.88M average).

Both functions are pure — no network calls.
"""
from __future__ import annotations

from typing import Any, Dict, List


# H1/Bugcrowd public medians (rounded, February 2026).
BOUNTY_MEDIAN = {
    'critical': 5000,
    'high': 1500,
    'medium': 500,
    'low': 100,
    'info': 0,
}

# Subtype multipliers — some bugs pay far more than the raw severity says.
BOUNTY_SUBTYPE_MULT = {
    'jwt_cracker':        3.0,   # auth bypass pays a lot
    'graphql':            1.4,   # introspection is a fast win
    'ssrf_deep':          4.0,   # cloud credential leak
    'race_condition':     2.5,   # $$$ on financial platforms
    'sqli':               2.0,
    'cmd':                3.5,
    'xxe':                2.0,
    'http_smuggling':     3.0,
    'mfa_bypass':         3.0,
    'web_cache_poisoning': 2.5,
    'prototype_pollution': 1.5,
}


# Business impact per severity (GDPR average fine + IBM avg + response cost).
IMPACT_USD = {
    'critical': 250_000,
    'high':     50_000,
    'medium':   10_000,
    'low':      1_000,
    'info':     0,
}


def estimate_bounty(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Returns:
      {
        total_min, total_median, total_max,
        breakdown: [{finding_id, severity, subtype, median, min, max}]
      }
    """
    breakdown: List[Dict[str, Any]] = []
    total_min = total_med = total_max = 0
    for i, f in enumerate(findings):
        sev = (f.get('severity') or 'info').lower()
        subtype = (f.get('type') or '').lower()
        med = BOUNTY_MEDIAN.get(sev, 0)
        mult = BOUNTY_SUBTYPE_MULT.get(subtype, 1.0)
        med *= mult
        lo, hi = int(med * 0.4), int(med * 2.5)
        breakdown.append({
            'finding_index': i,
            'type': subtype,
            'severity': sev,
            'estimated_min': lo,
            'estimated_median': int(med),
            'estimated_max': hi,
            'multiplier': mult,
        })
        total_min += lo
        total_med += int(med)
        total_max += hi
    return {
        'total_min_usd': total_min,
        'total_median_usd': total_med,
        'total_max_usd': total_max,
        'breakdown': breakdown,
        'currency': 'USD',
        'source': 'HackerOne + Bugcrowd public medians · Feb 2026',
    }


def estimate_business_impact(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregates GDPR fine risk + breach remediation cost + reputation damage
    into a single "worst-case exposure" figure.
    """
    total = 0
    breakdown: List[Dict[str, Any]] = []
    for f in findings:
        sev = (f.get('severity') or 'info').lower()
        base = IMPACT_USD.get(sev, 0)
        breakdown.append({
            'type': f.get('type'),
            'severity': sev,
            'impact_usd': base,
        })
        total += base
    # Reputation multiplier — 10 critical findings = massive news story.
    critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
    reputation_mult = 1.0 + min(critical_count * 0.15, 3.0)
    reputation_impact = int(total * (reputation_mult - 1.0))

    return {
        'direct_exposure_usd': total,
        'reputation_impact_usd': reputation_impact,
        'total_worst_case_usd': total + reputation_impact,
        'critical_count': critical_count,
        'reputation_multiplier': round(reputation_mult, 2),
        'breakdown': breakdown,
        'source': 'IBM Cost of Breach 2024 + GDPR fines median',
    }
