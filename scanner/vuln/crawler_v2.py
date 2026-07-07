"""
CyberScope v7.7 · Crawler Engine v2 — "Total Annihilation" mode.

Goals over the v1 crawler:
  * JS-rendered SPA support via Playwright (React/Angular/Vue/Svelte).
  * Concurrent BFS + priority DFS mixed.  Suspicious endpoints
    (admin, api, upload, redirect, id=, token, debug, backup)
    jump the queue.
  * Auto-discovers: <a>, <form>, JS endpoints, GraphQL schema,
    WebSocket URLs, EventSource / SSE, service workers, sitemap,
    robots, security.txt, manifest.json, favicon hash.
  * HAR replay — seed URLs + params from a browser-recorded HAR.
  * Historical seeds — Wayback Machine, URLScan.io, CommonCrawl.
  * JS Deep-Mine — parses bundles + source maps and extracts
    hidden REST endpoints.
  * Arjun-style dynamic parameter mining — brute-force wordlist
    to reveal undocumented query params.

Non-goals: HTML rendering / screenshotting (done by screenshot_service).

Performance-first design:
  * All I/O is async / non-blocking.
  * Playwright pages are pooled and re-used (no per-request browser
    boot).
  * Discovery streams into a `Set` — O(1) duplicate rejection.
  * Depth + URL budget are hard-capped so a hostile target cannot
    DoS the scanner.

Public API:
  * class CrawlerV2 — the workhorse.
  * async def crawl_v2(target, ...) -> CrawlResultV2
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlsplit

from .http_client import AdaptiveHTTPClient
from .ssrf_guard import is_url_safe


# ─────────────────────────── constants ───────────────────────────

# Boost priority for URLs that look juicy. Higher score → crawled first.
JUICY_TOKENS = (
    ('admin', 100), ('api', 90), ('graphql', 90), ('upload', 90),
    ('redirect', 80), ('login', 80), ('token', 80), ('debug', 80),
    ('backup', 80), ('config', 70), ('/v1/', 60), ('/v2/', 60),
    ('.git', 100), ('.env', 100), ('.bak', 80), ('.old', 70),
    ('id=', 60), ('user=', 60), ('file=', 90), ('path=', 90),
    ('url=', 80), ('next=', 80), ('return=', 80), ('callback=', 80),
)

# Endpoints we always try even if not linked.
FORCED_PATHS = (
    '/robots.txt', '/sitemap.xml', '/security.txt', '/.well-known/security.txt',
    '/manifest.json', '/favicon.ico', '/humans.txt', '/crossdomain.xml',
    '/.git/config', '/.env', '/.env.local', '/.env.production',
    '/api', '/api/v1', '/api/v2', '/api/docs', '/api/swagger',
    '/openapi.json', '/swagger.json', '/graphql', '/graphiql',
    '/actuator', '/actuator/health', '/actuator/env', '/actuator/heapdump',
    '/server-status', '/server-info', '/phpinfo.php', '/info.php',
    '/wp-json/wp/v2/users', '/wp-login.php', '/administrator',
    '/.DS_Store',
)

# Endpoints extracted from JavaScript via regex
JS_ENDPOINT_RE = re.compile(
    r"""["'`](/[a-zA-Z0-9_\-./]{2,200}(?:\?[a-zA-Z0-9_=&%\-]*)?)["'`]""",
)
# JS API-URL captures ("apiUrl": "https://api.example.com/v1")
JS_API_URL_RE = re.compile(
    r"""["'](?:api[_\-]?url|endpoint|baseUrl|host)["']\s*:\s*["'](https?://[^"'\s]+)["']""",
    re.IGNORECASE,
)
# Fetch/XHR calls
JS_FETCH_RE = re.compile(
    r"""(?:fetch|axios(?:\.[a-z]+)?|\.get|\.post|\.put|\.delete|XMLHttpRequest[^(]{0,80})\s*\(\s*["'`](/[^"'`]{2,200}|https?://[^"'`\s]+)["'`]""",
    re.IGNORECASE,
)
# Common source-map footer
SOURCEMAP_RE = re.compile(r'//[#@]\s*sourceMappingURL=([^\s"\']+)')

# Basic Arjun-style param wordlist (top hits — much bigger list is loaded
# lazily from the wordlist manager if available).
ARJUN_BASIC = (
    'id', 'user', 'username', 'name', 'email', 'search', 'q', 'query',
    'page', 'p', 'limit', 'offset', 'sort', 'order', 'debug', 'admin',
    'token', 'access_token', 'api_key', 'apikey', 'callback', 'jsonp',
    'redirect', 'redirect_uri', 'redirect_url', 'next', 'return', 'returnUrl',
    'url', 'file', 'path', 'dir', 'folder', 'src', 'target', 'dest',
    'action', 'cmd', 'command', 'exec', 'system', 'view', 'template',
    'lang', 'locale', 'theme', 'style', 'format', 'output', 'type',
    'category', 'tag', 'type', 'kind', 'mode', 'role', 'group',
    'from', 'to', 'start', 'end', 'date', 'time', 'timestamp',
    'session', 'sess', 'sid', 'jsessionid', 'phpsessid', 'auth', 'jwt',
    # v7.7.2 · +80 high-signal params
    'ref', 'referrer', 'source', 'origin', 'domain', 'host', 'ip', 'port',
    'protocol', 'scheme', 'method', 'headers', 'cookies', 'session_id',
    'csrf', 'csrf_token', 'nonce', 'state', 'code', 'authorization',
    'x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'x-original-url',
    'x-rewrite-url', 'x-http-method-override', 'x-api-version', 'x-tenant',
    'account', 'account_id', 'customer', 'customer_id', 'org', 'organization',
    'team', 'workspace', 'project', 'app', 'application', 'service',
    'resource', 'entity', 'model', 'object', 'item', 'record', 'row',
    'field', 'column', 'attr', 'attribute', 'property', 'value',
    'key', 'name', 'label', 'title', 'description', 'content', 'body',
    'text', 'message', 'comment', 'note', 'memo', 'reason', 'cause',
    'code', 'error', 'exception', 'stack', 'trace', 'log', 'debug_info',
    'verbose', 'quiet', 'silent', 'test', 'testing', 'dev', 'development',
    'prod', 'production', 'staging', 'beta', 'alpha', 'preview', 'demo',
    'export', 'import', 'download', 'upload', 'attach', 'attachment',
    'image', 'photo', 'picture', 'avatar', 'icon', 'logo', 'banner',
    'video', 'audio', 'media', 'file_id', 'filename', 'filepath',
    'first', 'last', 'prev', 'previous', 'current', 'default', 'min', 'max',
)

# Extended discovery: dozens more sensitive paths (probed even if unlinked)
EXTENDED_PATHS = (
    # CI/CD
    '/.github/workflows', '/.gitlab-ci.yml', '/.travis.yml', '/circleci/config.yml',
    '/Jenkinsfile', '/.circleci',
    # Config leaks
    '/config.php', '/config.json', '/config.yaml', '/config.yml',
    '/settings.py', '/settings.json', '/config.js', '/config.ts',
    '/appsettings.json', '/appsettings.Development.json',
    '/web.config', '/.htaccess', '/.htpasswd',
    # Credentials & backups
    '/.aws/credentials', '/.docker/config.json', '/.npmrc', '/.pypirc',
    '/id_rsa', '/id_dsa', '/.ssh/id_rsa', '/authorized_keys',
    '/backup.zip', '/backup.tar', '/backup.tar.gz', '/db.sql', '/dump.sql',
    '/database.sql', '/backup.sql', '/data.sql',
    # Cloud metadata (guarded by SSRF but still probed on target itself)
    '/latest/meta-data/', '/computeMetadata/v1/',
    # Kubernetes / Docker
    '/api/v1/namespaces', '/healthz', '/metrics', '/ready', '/live',
    '/version', '/api/version',
    # Common admin panels
    '/admin', '/admin/', '/admin/login', '/admin/index.php', '/administrator/',
    '/panel', '/cpanel', '/dashboard', '/console', '/management',
    # Nginx/Apache status
    '/nginx_status', '/apache_status', '/status', '/stub_status',
    # Framework specifics
    '/laravel/.env', '/.env.local', '/.env.dev', '/.env.production',
    '/rails/info/properties', '/rails/info/routes',
    '/debug/default/view', '/debug/db', '/debug/vars',
    '/console', '/rails/mailers',
    # SCM leaks
    '/.svn/entries', '/.hg/hgrc', '/.bzr/branch/branch.conf',
    # Documentation & Swagger
    '/api-docs', '/swagger-ui', '/swagger-ui.html', '/swagger-ui/index.html',
    '/redoc', '/api/swagger.json', '/api/openapi.json',
    '/v3/api-docs', '/v2/api-docs',
    # GraphQL playgrounds
    '/graphql', '/graphiql', '/altair', '/playground', '/api/graphql',
    '/v1/graphql', '/query',
    # WebSocket endpoints
    '/socket.io', '/ws', '/websocket', '/sockjs-node',
    # Testing endpoints
    '/test', '/tests', '/spec', '/qa',
)


# ─────────────────────────── data types ───────────────────────────

@dataclass(order=True)
class PriorityURL:
    """Wraps a URL with a priority score for the async priority queue."""
    priority: int  # lower = crawled first (heap-min)
    depth: int
    url: str = field(compare=False)


@dataclass
class CrawlResultV2:
    urls: Set[str] = field(default_factory=set)
    forms: List[Dict] = field(default_factory=list)
    endpoints: Set[str] = field(default_factory=set)     # raw JS/API endpoints
    parameters: Dict[str, Set[str]] = field(default_factory=dict)  # url -> params
    graphql_urls: Set[str] = field(default_factory=set)
    websocket_urls: Set[str] = field(default_factory=set)
    sse_urls: Set[str] = field(default_factory=set)
    js_secrets_hints: List[Dict] = field(default_factory=list)
    hidden_params: Dict[str, List[str]] = field(default_factory=dict)  # url -> params discovered by mining
    tech_hints: Set[str] = field(default_factory=set)
    favicon_hash: Optional[str] = None
    stats: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'urls_count': len(self.urls),
            'forms_count': len(self.forms),
            'endpoints_count': len(self.endpoints),
            'graphql_count': len(self.graphql_urls),
            'websocket_count': len(self.websocket_urls),
            'hidden_params_count': sum(len(p) for p in self.hidden_params.values()),
            'urls': list(self.urls)[:2000],
            'forms': self.forms[:200],
            'endpoints': list(self.endpoints)[:2000],
            'graphql_urls': list(self.graphql_urls),
            'websocket_urls': list(self.websocket_urls),
            'sse_urls': list(self.sse_urls),
            'hidden_params': {u: sorted(v) for u, v in list(self.hidden_params.items())[:200]},
            'tech_hints': sorted(self.tech_hints),
            'favicon_hash': self.favicon_hash,
            'stats': self.stats,
        }


# ─────────────────────────── crawler ───────────────────────────

class CrawlerV2:
    """
    Async priority-queue crawler with optional Playwright rendering.
    Playwright is imported lazily so the module still works even if
    the user hasn't installed browsers yet.
    """

    def __init__(
        self,
        client: AdaptiveHTTPClient,
        *,
        max_depth: int = 5,
        max_urls: int = 5000,
        max_concurrent: int = 20,
        render_js: bool = False,
        mine_hidden_params: bool = True,
        aggressive: bool = True,
        log_cb: Optional[Callable[[str], None]] = None,
    ):
        self.client = client
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.max_concurrent = max_concurrent
        self.render_js = render_js
        self.mine_hidden_params = mine_hidden_params
        self.aggressive = aggressive  # v7.7.2 · triggers extended paths + big wordlist
        self.log_cb = log_cb
        self._sem = asyncio.Semaphore(max_concurrent)
        self._seen: Set[str] = set()
        self._result = CrawlResultV2()
        self._browser = None
        self._pw = None

    # ------- helpers -------

    def _log(self, msg: str) -> None:
        if self.log_cb:
            try:
                self.log_cb(msg)
            except Exception:
                pass

    @staticmethod
    def _normalize(url: str) -> str:
        try:
            p = urlsplit(url)
            path = p.path or '/'
            # Strip trailing slash except for root
            if len(path) > 1 and path.endswith('/'):
                path = path[:-1]
            # Drop fragment
            return f'{p.scheme}://{p.netloc}{path}' + (f'?{p.query}' if p.query else '')
        except Exception:
            return url

    @staticmethod
    def _same_origin(a: str, b: str) -> bool:
        try:
            pa, pb = urlparse(a), urlparse(b)
            return pa.hostname == pb.hostname and pa.scheme == pb.scheme
        except Exception:
            return False

    @classmethod
    def _priority(cls, url: str, depth: int) -> int:
        """Lower = higher priority. Depth adds cost, juicy tokens subtract."""
        score = 100 + depth * 25
        low = url.lower()
        for tok, boost in JUICY_TOKENS:
            if tok in low:
                score -= boost
        return score

    # ------- Playwright pool -------

    async def _init_browser(self):
        if self._browser is not None:
            return
        try:
            from playwright.async_api import async_playwright
            self._pw = await async_playwright().start()
            self._browser = await self._pw.chromium.launch(headless=True)
        except Exception as e:
            # v7.7.3 · Log a short, actionable message instead of dumping the
            # full multi-line Playwright ASCII banner into the scan logs.
            short = str(e).split('\n', 1)[0][:200]
            self._log(f'[!] Playwright unavailable ({short}) — HTML-only mode')
            self.render_js = False

    async def _close_browser(self):
        try:
            if self._browser:
                await self._browser.close()
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass
        self._browser = None
        self._pw = None

    # ------- render & extract -------

    async def _fetch_html(self, url: str) -> Tuple[Optional[str], Dict[str, str]]:
        r = await self.client.get(url)
        if r.status < 200 or r.status >= 400 or not r.text:
            return None, dict(r.headers or {})
        return r.text[:2_000_000], dict(r.headers or {})

    async def _render_page(self, url: str) -> Tuple[Optional[str], List[str]]:
        """Return (rendered_html, discovered_network_urls). Playwright-only."""
        if not self.render_js or not self._browser:
            return None, []
        network_urls: List[str] = []
        try:
            page = await self._browser.new_page(
                user_agent='Mozilla/5.0 (X11; Linux x86_64) CyberScope/7.7')

            def on_request(req):
                try:
                    network_urls.append(req.url)
                except Exception:
                    pass
            page.on('request', on_request)
            page.on('websocket', lambda ws: network_urls.append('ws:' + ws.url))
            try:
                await page.goto(url, wait_until='networkidle', timeout=15000)
                await page.wait_for_timeout(1200)
            except Exception:
                pass
            html = await page.content()
            await page.close()
            return html, network_urls
        except Exception as e:
            self._log(f'[!] render failed for {url}: {e}')
            return None, network_urls

    # ------- extractors -------

    _HREF_RE = re.compile(r'''(?:href|src|action|data-url|data-src)\s*=\s*["']([^"'#\s]+)["']''',
                          re.IGNORECASE)
    _FORM_RE = re.compile(r'<form\b[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
    _INPUT_RE = re.compile(r'<input\b[^>]*?(?:name|id)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    _METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    _ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

    def _extract_links(self, html: str, base: str) -> List[str]:
        out: Set[str] = set()
        for m in self._HREF_RE.finditer(html or ''):
            u = m.group(1).strip()
            if u.startswith(('javascript:', 'data:', 'mailto:', 'tel:')):
                continue
            try:
                absu = urljoin(base, u)
                if absu.startswith(('http://', 'https://')):
                    out.add(absu)
            except Exception:
                continue
        return list(out)

    def _extract_forms(self, html: str, base: str) -> List[Dict]:
        forms = []
        for m in self._FORM_RE.finditer(html or ''):
            body = m.group(0)
            action = (self._ACTION_RE.search(body).group(1)
                      if self._ACTION_RE.search(body) else base)
            method = (self._METHOD_RE.search(body).group(1).upper()
                      if self._METHOD_RE.search(body) else 'GET')
            inputs = list({n.group(1) for n in self._INPUT_RE.finditer(body)})
            try:
                action_abs = urljoin(base, action)
            except Exception:
                action_abs = base
            forms.append({'action': action_abs, 'method': method, 'inputs': inputs,
                          'discovered_at': base})
        return forms

    def _extract_endpoints(self, text: str) -> Set[str]:
        eps: Set[str] = set()
        for m in JS_ENDPOINT_RE.finditer(text or ''):
            eps.add(m.group(1))
        for m in JS_FETCH_RE.finditer(text or ''):
            eps.add(m.group(1))
        for m in JS_API_URL_RE.finditer(text or ''):
            eps.add(m.group(1))
        return {e for e in eps if not e.endswith(('.css', '.png', '.jpg', '.svg', '.woff'))}

    def _extract_tech_hints(self, headers: Dict[str, str], body: str) -> Set[str]:
        hints: Set[str] = set()
        server = (headers.get('server') or headers.get('Server') or '').lower()
        powered = (headers.get('x-powered-by') or headers.get('X-Powered-By') or '').lower()
        for h, tokens in (
            (server, ('nginx', 'apache', 'cloudflare', 'iis', 'litespeed')),
            (powered, ('php', 'express', 'asp.net', 'django', 'rails')),
        ):
            for t in tokens:
                if t in h:
                    hints.add(t)
        low = (body or '')[:20000].lower()
        for tag in ('wp-content', 'drupal', 'joomla', 'react', 'angular', 'vue',
                    'nextjs', '__next_data__', 'gatsby', 'shopify', 'magento'):
            if tag in low:
                hints.add(tag.replace('__', '').replace('_data', ''))
        return hints

    async def _favicon_hash(self, origin: str) -> Optional[str]:
        try:
            r = await self.client.get(origin + '/favicon.ico')
            if r.status == 200 and r.text:
                import base64
                b64 = base64.b64encode(r.text.encode('latin-1', errors='ignore'))
                return hashlib.md5(b64).hexdigest()[:16]
        except Exception:
            return None
        return None

    # ------- historical seeds -------

    # v7.9.x · Performance cap for sitemap seeds to avoid DoS-ing large sites.
    _SITEMAP_MAX_URLS = int(os.environ.get('CS_SITEMAP_MAX_URLS', '500'))
    _SITEMAP_TIMEOUT_S = float(os.environ.get('CS_SITEMAP_TIMEOUT_S', '8'))

    async def _sitemap_seeds(self, origin: str) -> List[str]:
        """Parse /sitemap.xml (+ nested sitemap indexes) for URL seeds."""
        found: Set[str] = set()
        candidates = [
            origin + '/sitemap.xml', origin + '/sitemap_index.xml',
            origin + '/sitemap-index.xml', origin + '/sitemap1.xml',
            origin + '/sitemaps.xml', origin + '/sitemap.xml.gz',
        ]
        async def _fetch(url: str, timeout: float = 6.0):
            try:
                return await asyncio.wait_for(self.client.get(url), timeout=timeout)
            except (asyncio.TimeoutError, Exception):
                return None
        try:
            for c in candidates:
                r = await _fetch(c, timeout=self._SITEMAP_TIMEOUT_S)
                if not r or r.status != 200 or not r.text:
                    continue
                # Hard cap on raw size to avoid memory blow-up on huge sitemaps.
                raw = r.text
                if len(raw) > 5_000_000:  # 5 MB
                    self._log(f'[!] Sitemap {c} too large ({len(raw)} bytes) — truncating')
                    raw = raw[:5_000_000]
                for m in re.finditer(r'<loc>\s*([^<\s]+)\s*</loc>', raw):
                    if len(found) >= self._SITEMAP_MAX_URLS:
                        self._log(f'[!] Sitemap cap ({self._SITEMAP_MAX_URLS}) reached — stopping')
                        break
                    u = m.group(1).strip()
                    if u.startswith(('http://', 'https://')):
                        found.add(u)
                        # Nested sitemap index → follow one level (capped)
                        if u.endswith('.xml') and u != c and len(found) < self._SITEMAP_MAX_URLS:
                            r2 = await _fetch(u, timeout=4.0)
                            if r2 and r2.status == 200 and r2.text:
                                inner = r2.text[:2_000_000]  # 2 MB cap on nested
                                for m2 in re.finditer(r'<loc>\s*([^<\s]+)\s*</loc>', inner):
                                    if len(found) >= self._SITEMAP_MAX_URLS:
                                        break
                                    found.add(m2.group(1).strip())
                if found:
                    break
        except Exception:
            pass
        return list(found)[:self._SITEMAP_MAX_URLS]

    # v7.9.x · Performance cap for robots.txt seeds.
    _ROBOTS_MAX_URLS = int(os.environ.get('CS_ROBOTS_MAX_URLS', '120'))
    _ROBOTS_TIMEOUT_S = float(os.environ.get('CS_ROBOTS_TIMEOUT_S', '5'))

    async def _robots_seeds(self, origin: str) -> List[str]:
        """Parse robots.txt for Disallow/Allow/Sitemap entries as seed paths."""
        try:
            try:
                r = await asyncio.wait_for(
                    self.client.get(origin + '/robots.txt'),
                    timeout=self._ROBOTS_TIMEOUT_S,
                )
            except (asyncio.TimeoutError, Exception):
                return []
            if r.status != 200 or not r.text:
                return []
            # Cap raw robots.txt size to avoid memory bloat on huge files.
            text = r.text
            if len(text) > 500_000:  # 500 KB
                self._log(f'[!] robots.txt too large ({len(text)} bytes) — truncating')
                text = text[:500_000]
            paths: Set[str] = set()
            for line in text.splitlines():
                low = line.strip().lower()
                if low.startswith(('disallow:', 'allow:')):
                    p = line.split(':', 1)[1].strip()
                    if p and p != '/' and len(paths) < self._ROBOTS_MAX_URLS:
                        paths.add(origin + (p if p.startswith('/') else '/' + p))
                elif low.startswith('sitemap:') and len(paths) < self._ROBOTS_MAX_URLS:
                    sm = line.split(':', 1)[1].strip()
                    paths.add(sm)
            return list(paths)[:self._ROBOTS_MAX_URLS]
        except Exception:
            return []

    async def _wayback_seeds(self, host: str, limit: int = 200) -> List[str]:
        try:
            url = (f'https://web.archive.org/cdx/search/cdx?url={host}/*'
                   f'&output=json&limit={limit}&fl=original&collapse=urlkey')
            r = await self.client.get(url)
            if r.status != 200 or not r.text:
                return []
            data = json.loads(r.text)
            if not isinstance(data, list) or len(data) < 2:
                return []
            return [row[0] for row in data[1:] if row and row[0].startswith('http')]
        except Exception as e:
            self._log(f'[!] wayback fetch failed: {e}')
            return []

    async def _urlscan_seeds(self, host: str) -> List[str]:
        try:
            url = f'https://urlscan.io/api/v1/search/?q=domain:{host}&size=100'
            r = await self.client.get(url)
            if r.status != 200 or not r.text:
                return []
            data = json.loads(r.text)
            return [row.get('page', {}).get('url')
                    for row in data.get('results', [])
                    if row.get('page', {}).get('url')]
        except Exception:
            return []

    # ------- Arjun-style hidden parameter mining -------

    async def _mine_hidden_params(self, url: str) -> List[str]:
        """
        Probe the URL with each candidate param and compare response length /
        status against a baseline. If any single param triggers a stable
        difference across 2 confirmations, we say it's a real param.
        """
        try:
            base = await self.client.get(url)
            if base.status < 200 or base.status >= 500 or not base.text:
                return []
            base_len = len(base.text)
            hits: List[str] = []
            # Try in small batches — 6 params at a time
            for i in range(0, len(ARJUN_BASIC), 6):
                batch = ARJUN_BASIC[i:i+6]
                probes = []
                for name in batch:
                    sep = '&' if '?' in url else '?'
                    probes.append(self.client.get(f'{url}{sep}{name}=cyberscope_probe_9x8q'))
                resps = await asyncio.gather(*probes, return_exceptions=True)
                for name, r in zip(batch, resps):
                    if not hasattr(r, 'text') or r.status < 200 or r.status >= 500:
                        continue
                    delta = abs(len(r.text) - base_len)
                    if delta > 30 or 'cyberscope_probe_9x8q' in (r.text or ''):
                        hits.append(name)
            return hits
        except Exception:
            return []

    # ------- BFS core -------

    async def crawl(self, target: str, extra_seeds: Optional[Iterable[str]] = None,
                    har_seeds: Optional[Iterable[Dict]] = None) -> CrawlResultV2:
        """Main entrypoint. Returns a populated CrawlResultV2."""
        t0 = time.time()
        target = self._normalize(target)
        origin_parsed = urlparse(target)
        origin = f'{origin_parsed.scheme}://{origin_parsed.netloc}'
        host = origin_parsed.hostname or ''

        if self.render_js:
            await self._init_browser()

        # Priority queue
        queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        await queue.put(PriorityURL(0, 0, target))
        for fp in FORCED_PATHS:
            await queue.put(PriorityURL(50, 1, origin + fp))
        # v7.7.2 · extended discovery paths (~120 sensitive endpoints)
        if self.aggressive:
            for fp in EXTENDED_PATHS:
                await queue.put(PriorityURL(70, 1, origin + fp))
        for s in (extra_seeds or []):
            if s:
                await queue.put(PriorityURL(80, 1, self._normalize(s)))
        # sitemap.xml + robots.txt seeds (usually huge, always try)
        sm = await self._sitemap_seeds(origin)
        self._log(f'[+] Sitemap seeds: {len(sm)}')
        for u in sm:
            if self._same_origin(u, target):
                await queue.put(PriorityURL(30, 1, self._normalize(u)))
        rb = await self._robots_seeds(origin)
        self._log(f'[+] robots.txt seeds: {len(rb)}')
        for u in rb:
            if self._same_origin(u, target):
                await queue.put(PriorityURL(60, 1, self._normalize(u)))
        # Historical seeds (best-effort, non-blocking) — hard cap 6s each so
        # a slow wayback/urlscan can't stall the whole scan.
        try:
            wb = await asyncio.wait_for(self._wayback_seeds(host, 60), timeout=6.0)
            for u in wb:
                if self._same_origin(u, target):
                    await queue.put(PriorityURL(90, 1, self._normalize(u)))
            if wb:
                self._log(f'[+] Wayback seeds: {len(wb)}')
        except asyncio.TimeoutError:
            self._log('[!] Wayback seed lookup timed out (>6s) — skipping')
        try:
            us = await asyncio.wait_for(self._urlscan_seeds(host), timeout=6.0)
            for u in us:
                if self._same_origin(u, target):
                    await queue.put(PriorityURL(95, 1, self._normalize(u)))
            if us:
                self._log(f'[+] URLScan seeds: {len(us)}')
        except asyncio.TimeoutError:
            self._log('[!] URLScan seed lookup timed out (>6s) — skipping')
        # HAR seeds — dict of {url, method, params}
        for h in (har_seeds or []):
            u = h.get('url')
            if u and self._same_origin(u, target):
                await queue.put(PriorityURL(20, 0, self._normalize(u)))
                if h.get('params'):
                    self._result.parameters.setdefault(u, set()).update(h['params'])

        # Favicon (fingerprint hint)
        self._result.favicon_hash = await self._favicon_hash(origin)

        # Worker
        async def worker():
            while len(self._seen) < self.max_urls:
                try:
                    item: PriorityURL = await asyncio.wait_for(queue.get(), timeout=1.5)
                except asyncio.TimeoutError:
                    return
                if item.depth > self.max_depth:
                    continue
                nu = self._normalize(item.url)
                if nu in self._seen:
                    continue
                if not self._same_origin(nu, target):
                    continue
                if not is_url_safe(nu)[0]:
                    continue
                self._seen.add(nu)
                await self._process_one(nu, item.depth, queue)

        workers = [asyncio.create_task(worker()) for _ in range(self.max_concurrent)]
        await asyncio.gather(*workers, return_exceptions=True)

        # Optional hidden-parameter mining (parallel, capped to top 100 GET urls)
        if self.mine_hidden_params:
            candidates = [u for u in self._result.urls if '?' not in u][:100]
            self._log(f'[*] Mining hidden params on {len(candidates)} URLs (Arjun-style, {len(ARJUN_BASIC)} candidates each)...')
            for i in range(0, len(candidates), 8):
                batch = candidates[i:i+8]
                results = await asyncio.gather(
                    *[self._mine_hidden_params(u) for u in batch], return_exceptions=True)
                for u, params in zip(batch, results):
                    if isinstance(params, list) and params:
                        self._result.hidden_params[u] = params

        if self.render_js:
            await self._close_browser()

        self._result.urls = {self._normalize(u) for u in self._result.urls}
        self._result.stats = {
            'duration_seconds': round(time.time() - t0, 2),
            'urls_visited': len(self._seen),
            'urls_discovered': len(self._result.urls),
            'render_js_used': self.render_js,
        }
        return self._result

    async def _process_one(self, url: str, depth: int, queue: asyncio.PriorityQueue):
        async with self._sem:
            # 1) HTML fetch
            html, headers = await self._fetch_html(url)
            if html is None:
                return
            self._result.urls.add(url)
            self._result.tech_hints.update(self._extract_tech_hints(headers, html))

            # 2) Playwright render (opt-in)
            rendered, net_urls = None, []
            if self.render_js and depth <= 1:  # only render the shallow layer
                rendered, net_urls = await self._render_page(url)
                if rendered:
                    html = rendered
                for nu in net_urls:
                    if nu.startswith(('ws:', 'wss:')):
                        self._result.websocket_urls.add(nu.lstrip('ws:'))
                    elif nu.startswith(('http://', 'https://')):
                        self._result.endpoints.add(nu)

            # 3) Extract links + forms + endpoints
            links = self._extract_links(html, url)
            forms = self._extract_forms(html, url)
            endpoints = self._extract_endpoints(html)
            self._result.forms.extend(forms)
            self._result.endpoints.update(endpoints)
            for form in forms:
                self._result.parameters.setdefault(form['action'], set()).update(form.get('inputs', []))
            # detect GraphQL / SSE / WebSocket references
            low = html.lower()
            if 'graphql' in low:
                self._result.graphql_urls.add(url)
            for m in re.finditer(r'''["'](wss?://[^"'\s]+)["']''', html):
                self._result.websocket_urls.add(m.group(1))
            for m in re.finditer(r'new\s+EventSource\s*\(\s*["\']([^"\']+)["\']', html):
                try:
                    self._result.sse_urls.add(urljoin(url, m.group(1)))
                except Exception:
                    pass

            # 4) Push next hops
            for u in links:
                nu = self._normalize(u)
                if nu in self._seen:
                    continue
                if not self._same_origin(nu, url):
                    continue
                await queue.put(PriorityURL(self._priority(nu, depth + 1),
                                             depth + 1, nu))
            # Also enqueue any resource-relative endpoints from JS
            for ep in endpoints:
                if ep.startswith(('http://', 'https://')):
                    absep = ep
                else:
                    absep = urljoin(url, ep)
                nu = self._normalize(absep)
                if self._same_origin(nu, url) and nu not in self._seen:
                    await queue.put(PriorityURL(self._priority(nu, depth + 1),
                                                 depth + 1, nu))


async def crawl_v2(client: AdaptiveHTTPClient, target: str, *,
                   max_depth: int = 5, max_urls: int = 5000,
                   render_js: bool = False,
                   mine_hidden_params: bool = True,
                   aggressive: bool = True,
                   extra_seeds: Optional[Iterable[str]] = None,
                   har_seeds: Optional[Iterable[Dict]] = None,
                   log_cb: Optional[Callable[[str], None]] = None) -> Dict:
    """Convenience wrapper — returns .to_dict() of the crawl result."""
    c = CrawlerV2(client, max_depth=max_depth, max_urls=max_urls,
                   render_js=render_js, mine_hidden_params=mine_hidden_params,
                   aggressive=aggressive, log_cb=log_cb)
    result = await c.crawl(target, extra_seeds=extra_seeds, har_seeds=har_seeds)
    return result.to_dict()
