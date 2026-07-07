"""
Deep Crawler v7 — intelligent site crawler.

- BFS crawl with configurable depth and page limit
- Same-origin & subdomain scope enforcement
- Discovers: internal links, forms (with inputs), JS URLs, API endpoints, hidden params
- Parses robots.txt + sitemap.xml
- Follows redirects intelligently
- Respects timeouts and concurrency
- De-duplicates URLs by normalized form
"""
import asyncio
import re
from collections import deque
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

from .http_client import AdaptiveHTTPClient
from .recon_engine import extract_from_html


def _normalize(url: str) -> str:
    """Normalize URL: strip fragment, sort query params, lowercase host."""
    try:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return url.rstrip('/')
        # Remove fragment; sort query
        q = parse_qsl(p.query, keep_blank_values=True)
        q.sort()
        return urlunparse(p._replace(
            netloc=p.netloc.lower(),
            fragment='',
            query=urlencode(q, doseq=True),
        )).rstrip('/')
    except Exception:
        return url


def _in_scope(url: str, root_host: str, allow_subs: bool = True) -> bool:
    try:
        h = urlparse(url).netloc.lower().split(':')[0]
        if not h:
            return False
        if h == root_host:
            return True
        if allow_subs and h.endswith('.' + root_host.split('.', 1)[-1] if '.' in root_host else False):
            return True
        return False
    except Exception:
        return False


async def _parse_robots(client: AdaptiveHTTPClient, base_url: str) -> Dict[str, List[str]]:
    """Parse robots.txt for Disallow entries and Sitemap URLs."""
    out = {'disallow': [], 'allow': [], 'sitemaps': []}
    r = await client.get(base_url.rstrip('/') + '/robots.txt')
    if r.error or r.status != 200 or not r.text:
        return out
    for line in r.text.splitlines():
        s = line.strip()
        if s.lower().startswith('disallow:'):
            v = s.split(':', 1)[1].strip()
            if v and v != '/':
                out['disallow'].append(v)
        elif s.lower().startswith('allow:'):
            v = s.split(':', 1)[1].strip()
            if v:
                out['allow'].append(v)
        elif s.lower().startswith('sitemap:'):
            v = s.split(':', 1)[1].strip()
            if v:
                out['sitemaps'].append(v)
    return out


async def _parse_sitemap(client: AdaptiveHTTPClient, sitemap_url: str,
                         seen: Optional[Set[str]] = None,
                         depth: int = 0) -> List[str]:
    """Recursively parse sitemap.xml (also handles sitemap index files)."""
    seen = seen if seen is not None else set()
    if depth > 3 or sitemap_url in seen:
        return []
    seen.add(sitemap_url)
    urls: List[str] = []
    r = await client.get(sitemap_url)
    if r.error or not r.text:
        return urls
    body = r.text
    # Sitemap index
    for loc in re.findall(r'<sitemap>.*?<loc>([^<]+)</loc>.*?</sitemap>', body, re.DOTALL | re.IGNORECASE):
        urls.extend(await _parse_sitemap(client, loc.strip(), seen, depth + 1))
    # Regular URLs
    for loc in re.findall(r'<url>.*?<loc>([^<]+)</loc>.*?</url>', body, re.DOTALL | re.IGNORECASE):
        urls.append(loc.strip())
    return urls[:2000]


async def deep_crawl(
    client: AdaptiveHTTPClient,
    base_url: str,
    max_depth: int = 3,
    max_pages: int = 250,
    concurrency: int = 15,
    allow_subs: bool = True,
    respect_robots: bool = False,
    log_cb=None,
) -> Dict:
    """
    Perform breadth-first crawl.
    Returns dict with: visited (list), forms, params_found, endpoints (dedup), js_urls, robots, sitemaps
    """
    root = urlparse(base_url)
    root_host = root.netloc.lower().split(':')[0]
    if not root_host:
        return {'visited': [], 'forms': [], 'params_found': [], 'endpoints': [], 'js_urls': []}

    def _log(m):
        if log_cb:
            try:
                log_cb(m)
            except Exception:
                pass

    seen: Set[str] = set()
    visited: List[str] = []
    all_forms: List[Dict] = []
    all_params: Set[str] = set()
    all_endpoints: Set[str] = set()
    all_js: Set[str] = set()

    q: deque = deque()
    start = _normalize(base_url)
    q.append((start, 0))
    seen.add(start)

    # robots + sitemap
    robots = await _parse_robots(client, base_url)
    sitemap_urls: List[str] = []
    for sm in robots.get('sitemaps', []) + [base_url.rstrip('/') + '/sitemap.xml']:
        try:
            urls = await _parse_sitemap(client, sm)
            sitemap_urls.extend(urls)
        except Exception:
            continue
    # Enqueue sitemap URLs (depth=1) — enormous discovery lift
    for u in sitemap_urls[:500]:
        n = _normalize(u)
        if n not in seen and _in_scope(n, root_host, allow_subs):
            seen.add(n)
            q.append((n, 1))

    disallowed = set(robots.get('disallow', []))
    if not respect_robots:
        # Even if we're not respecting them, still probe them (often the juicy stuff)
        for path in list(disallowed)[:30]:
            u = urljoin(base_url, path)
            n = _normalize(u)
            if n not in seen and _in_scope(n, root_host, allow_subs):
                seen.add(n)
                q.append((n, 1))

    sem = asyncio.Semaphore(concurrency)

    async def _fetch(url: str, depth: int):
        async with sem:
            r = await client.get(url, follow_redirects=True)
            if r.error:
                return
            visited.append(url)
            if len(visited) % 25 == 0:
                _log(f'[crawl] {len(visited)} pages, {len(all_forms)} forms, {len(all_params)} params')
            body = r.text or ''
            data = extract_from_html(body, url)
            all_forms.extend(data.get('forms', []))
            for p in data.get('params', []):
                all_params.add(p)
            for j in data.get('js_urls', []):
                all_js.add(j)
            # Endpoints from body via URL patterns
            for m in re.findall(r'["\'](/[a-zA-Z0-9_\-./]{2,150})["\']', body):
                all_endpoints.add(m)
            # Enqueue links
            if depth < max_depth and len(seen) < max_pages:
                for link in data.get('links', []):
                    n = _normalize(link)
                    if (n not in seen
                            and _in_scope(n, root_host, allow_subs)
                            and len(seen) < max_pages):
                        seen.add(n)
                        q.append((n, depth + 1))

    while q and len(visited) < max_pages:
        batch = []
        # Grab up to `concurrency` URLs of similar depth to fan out
        while q and len(batch) < concurrency and len(visited) + len(batch) < max_pages:
            u, d = q.popleft()
            batch.append(_fetch(u, d))
        if batch:
            await asyncio.gather(*batch, return_exceptions=True)

    return {
        'visited': visited,
        'visited_count': len(visited),
        'forms': all_forms[:200],
        'params_found': sorted(all_params)[:200],
        'endpoints': sorted(all_endpoints)[:500],
        'js_urls': sorted(all_js)[:200],
        'robots': robots,
        'sitemap_urls_count': len(sitemap_urls),
    }
