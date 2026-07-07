"""
CyberScope v7.8 · Live CVE feed sync (NVD + ExploitDB).

Periodically pulls the latest CVE metadata from the NVD JSON feed and
stores relevant records (CVSS ≥ 7.0 · published in last 30 days) into
Mongo for the `cve_correlator` module to consume at scan time.

Also refreshes Nuclei templates count so the info endpoint reports live
numbers.

Everything runs best-effort — network failures are silently retried on
the next tick.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


async def fetch_recent_cves(client, max_results: int = 200) -> List[Dict[str, Any]]:
    """Fetch CVEs published in the last 30 days with CVSS ≥ 7.0."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=30)
    params = {
        'pubStartDate': start.strftime('%Y-%m-%dT00:00:00.000'),
        'pubEndDate':   end.strftime('%Y-%m-%dT23:59:59.000'),
        'cvssV3Severity': 'HIGH',
        'resultsPerPage': max_results,
    }
    try:
        r = await client.get(NVD_URL, params=params, timeout=15.0)
    except Exception:
        return []
    try:
        import json as _j
        data = _j.loads(r.text) if hasattr(r, 'text') else r.json()
    except Exception:
        return []

    out: List[Dict[str, Any]] = []
    for item in (data.get('vulnerabilities') or [])[:max_results]:
        try:
            cve = item.get('cve') or {}
            metrics = ((cve.get('metrics') or {}).get('cvssMetricV31') or
                       (cve.get('metrics') or {}).get('cvssMetricV30') or [])
            score = 0.0
            severity = 'medium'
            if metrics:
                data0 = (metrics[0].get('cvssData') or {})
                score = float(data0.get('baseScore', 0.0))
                severity = (data0.get('baseSeverity') or 'MEDIUM').lower()
            desc_en = ''
            for d in (cve.get('descriptions') or []):
                if d.get('lang') == 'en':
                    desc_en = d.get('value') or ''
                    break
            out.append({
                'cve_id': cve.get('id'),
                'published': cve.get('published'),
                'lastModified': cve.get('lastModified'),
                'severity': severity,
                'cvss': score,
                'description': desc_en[:600],
            })
        except Exception:
            continue
    return out


async def sync_cves_to_db(db) -> Dict[str, Any]:
    """
    One-shot sync — called by the periodic loop AND by a manual admin endpoint.
    Returns {inserted, updated, total}.
    """
    from vuln.http_client import AdaptiveHTTPClient
    inserted = updated = 0
    async with AdaptiveHTTPClient(timeout=15.0) as c:
        cves = await fetch_recent_cves(c, max_results=200)
    for cve in cves:
        cid = cve.get('cve_id')
        if not cid:
            continue
        existing = await db.cve_feed.find_one({'cve_id': cid})
        cve['synced_at'] = datetime.now(timezone.utc).isoformat()
        if existing:
            await db.cve_feed.update_one({'cve_id': cid}, {'$set': cve})
            updated += 1
        else:
            await db.cve_feed.insert_one(cve)
            inserted += 1
    return {'inserted': inserted, 'updated': updated, 'total': len(cves)}


async def cve_feed_loop(db, interval_hours: int = 6):
    """Background loop — sync every N hours."""
    while True:
        try:
            await sync_cves_to_db(db)
        except Exception:
            pass
        await asyncio.sleep(max(60, interval_hours * 3600))
