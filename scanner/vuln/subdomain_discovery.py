"""
Deep Subdomain Discovery — passive OSINT sources.
Aggregates subdomains from multiple free sources:
  - crt.sh (Certificate Transparency logs)
  - AlienVault OTX
  - Wayback Machine
  - HackerTarget (rate-limited)
  - RapidDNS
  - anubis-db.threatminer.org
Returns deduplicated list + per-source counts.
"""
import asyncio
import re
import json
from typing import Dict, List, Set

import httpx


UA = 'Mozilla/5.0 (CyberScope/7.2 SubdomainDiscovery)'
TIMEOUT = httpx.Timeout(15.0, connect=10.0)


async def _fetch(client: httpx.AsyncClient, url: str, **kw):
    try:
        r = await client.get(url, timeout=TIMEOUT, headers={'User-Agent': UA, **kw.get('headers', {})})
        if r.status_code < 400:
            return r.text
    except Exception:
        pass
    return ''


async def source_crtsh(client, domain: str) -> Set[str]:
    text = await _fetch(client, f'https://crt.sh/?q=%25.{domain}&output=json')
    subs = set()
    try:
        data = json.loads(text)
        for entry in data:
            name = entry.get('name_value', '')
            for line in name.splitlines():
                if line and domain in line and '*' not in line:
                    subs.add(line.strip().lower())
    except Exception:
        pass
    return subs


async def source_otx(client, domain: str) -> Set[str]:
    subs = set()
    text = await _fetch(client, f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns')
    try:
        data = json.loads(text)
        for entry in data.get('passive_dns', []):
            h = entry.get('hostname', '').lower()
            if h and h.endswith('.' + domain):
                subs.add(h)
    except Exception:
        pass
    return subs


async def source_wayback(client, domain: str) -> Set[str]:
    subs = set()
    text = await _fetch(client, f'http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=2000')
    for line in text.splitlines():
        m = re.match(r'https?://([^/]+)', line.strip())
        if m:
            h = m.group(1).lower().split(':')[0]
            if domain in h:
                subs.add(h)
    return subs


async def source_hackertarget(client, domain: str) -> Set[str]:
    subs = set()
    text = await _fetch(client, f'https://api.hackertarget.com/hostsearch/?q={domain}')
    for line in text.splitlines():
        h = line.split(',')[0].strip().lower()
        if h and domain in h:
            subs.add(h)
    return subs


async def source_rapiddns(client, domain: str) -> Set[str]:
    subs = set()
    text = await _fetch(client, f'https://rapiddns.io/subdomain/{domain}?full=1')
    for m in re.finditer(r'<td>([a-z0-9\-.]+\.' + re.escape(domain) + r')</td>', text, re.IGNORECASE):
        subs.add(m.group(1).lower())
    return subs


async def source_threatminer(client, domain: str) -> Set[str]:
    subs = set()
    text = await _fetch(client, f'https://api.threatminer.org/v2/domain.php?q={domain}&rt=5')
    try:
        data = json.loads(text)
        for r in data.get('results', []) or []:
            r = str(r).lower()
            if domain in r:
                subs.add(r)
    except Exception:
        pass
    return subs


async def discover_subdomains(domain: str, max_per_source: int = 500) -> Dict:
    """
    Aggregate subdomains from all sources.
    Returns:
      {
        'total': N,
        'unique': [list of subdomains sorted],
        'sources': {'crtsh': N, 'otx': N, 'wayback': N, ...}
      }
    """
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        results = await asyncio.gather(
            source_crtsh(client, domain),
            source_otx(client, domain),
            source_wayback(client, domain),
            source_hackertarget(client, domain),
            source_rapiddns(client, domain),
            source_threatminer(client, domain),
            return_exceptions=True,
        )
    names = ['crtsh', 'otx', 'wayback', 'hackertarget', 'rapiddns', 'threatminer']
    per_source = {}
    all_subs: Set[str] = set()
    for name, r in zip(names, results):
        if isinstance(r, set):
            per_source[name] = len(r)
            all_subs |= r
        else:
            per_source[name] = 0

    # Filter obvious junk
    clean = set()
    for s in all_subs:
        s = s.strip('.').lower()
        if not s or ' ' in s or ',' in s:
            continue
        if not re.match(r'^[a-z0-9._-]+$', s):
            continue
        if s.endswith(domain) or s == domain:
            clean.add(s)

    return {
        'total': len(clean),
        'unique': sorted(clean)[:5000],
        'sources': per_source,
    }
