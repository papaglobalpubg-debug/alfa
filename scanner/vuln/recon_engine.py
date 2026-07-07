"""
Intelligent Recon Engine.
- URL discovery from Wayback Machine, CommonCrawl, AlienVault OTX, URLScan
- JS file analysis for endpoints & secrets
- Parameter mining
- Content discovery (heuristic-driven, not brute-force)
"""
import asyncio
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, unquote

from .http_client import AdaptiveHTTPClient, Response
from .payloads import PAYLOADS


# ============================================================================
# External URL sources
# ============================================================================
async def _wayback_urls(client: AdaptiveHTTPClient, domain: str) -> Set[str]:
    urls = set()
    url = f'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000'
    r = await client.get(url)
    if r.error:
        return urls
    try:
        import json
        data = json.loads(r.text)
        for row in data[1:]:
            if row:
                urls.add(row[0])
    except Exception:
        pass
    return urls


async def _otx_urls(client: AdaptiveHTTPClient, domain: str) -> Set[str]:
    urls = set()
    url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page=1'
    r = await client.get(url)
    if r.error:
        return urls
    try:
        import json
        data = json.loads(r.text)
        for u in data.get('url_list', []):
            if u.get('url'):
                urls.add(u['url'])
    except Exception:
        pass
    return urls


async def _commoncrawl_urls(client: AdaptiveHTTPClient, domain: str) -> Set[str]:
    urls = set()
    # First, get latest index
    idx_r = await client.get('https://index.commoncrawl.org/collinfo.json')
    if idx_r.error:
        return urls
    try:
        import json
        indices = json.loads(idx_r.text)
        if not indices:
            return urls
        latest = indices[0]['id']
        url = f'https://index.commoncrawl.org/{latest}-index?url=*.{domain}/*&output=json&limit=2000'
        r = await client.get(url)
        if r.error:
            return urls
        for line in (r.text or '').splitlines():
            try:
                d = json.loads(line)
                if d.get('url'):
                    urls.add(d['url'])
            except Exception:
                continue
    except Exception:
        pass
    return urls


async def _urlscan_urls(client: AdaptiveHTTPClient, domain: str) -> Set[str]:
    urls = set()
    url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100'
    r = await client.get(url)
    if r.error:
        return urls
    try:
        import json
        data = json.loads(r.text)
        for res in data.get('results', []):
            u = (res.get('task') or {}).get('url') or (res.get('page') or {}).get('url')
            if u:
                urls.add(u)
    except Exception:
        pass
    return urls


# ============================================================================
# JS file analysis
# ============================================================================
JS_URL_REGEXES = [
    r'["\']([\w./?=&:%\-]{4,}\.(?:php|asp|aspx|jsp|do|action|cgi))["\']',
    r'["\'](/[\w./?=&:%\-]{2,})["\']',
    r'(?:url|href|action|src|endpoint|route|api|path)\s*[:=]\s*["\'](/[^\s"\']{2,})["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
    r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
]

PARAM_REGEXES = [
    r'(?:params?|data|body)\s*[:=]\s*\{[^}]{0,500}\}',
    r'name=["\']([\w\-]+)["\']',
    r'\?([\w\-]+)=',
    r'&([\w\-]+)=',
]


async def _fetch_js(client: AdaptiveHTTPClient, url: str) -> Optional[str]:
    r = await client.get(url)
    if r.error or r.status != 200:
        return None
    return r.text


async def mine_js_files(client: AdaptiveHTTPClient, base_url: str,
                        js_urls: List[str]) -> Dict[str, List]:
    """Extract endpoints, params, and secrets from JS files."""
    endpoints: Set[str] = set()
    params: Set[str] = set()
    secrets: List[Dict] = []

    sem = asyncio.Semaphore(10)

    async def _mine(u):
        async with sem:
            code = await _fetch_js(client, u)
            if not code:
                return
            # Endpoints
            for rx in JS_URL_REGEXES:
                try:
                    for m in re.findall(rx, code):
                        val = m if isinstance(m, str) else m[0]
                        if 1 < len(val) < 250:
                            endpoints.add(val)
                except Exception:
                    continue
            # Params
            for m in re.findall(r'[?&]([\w\-]{2,40})=', code):
                params.add(m)
            for m in re.findall(r'name=[\'"]([\w\-]{2,40})[\'"]', code):
                params.add(m)
            # Secrets
            for name, pattern in PAYLOADS.secrets.items():
                try:
                    for hit in re.findall(pattern, code)[:5]:
                        val = hit if isinstance(hit, str) else (hit[0] if hit else '')
                        if val and len(val) < 500:
                            secrets.append({
                                'type': name, 'value': val[:200],
                                'source_url': u,
                            })
                except Exception:
                    continue

    await asyncio.gather(*[_mine(u) for u in js_urls[:100]], return_exceptions=True)
    return {
        'endpoints': sorted(endpoints),
        'params': sorted(params),
        'secrets': secrets,
    }


# ============================================================================
# HTML parsing (extract JS URLs, forms, params)
# ============================================================================
def extract_from_html(html: str, base_url: str) -> Dict[str, List[str]]:
    result = {'js_urls': [], 'forms': [], 'links': [], 'params': set()}
    if not html:
        return result

    for m in re.finditer(r'<script[^>]+src=["\']?([^"\'>\s]+)', html, re.IGNORECASE):
        result['js_urls'].append(urljoin(base_url, m.group(1)))

    for m in re.finditer(r'<link[^>]+href=["\']?([^"\'>\s]+\.js[^"\'>\s]*)', html, re.IGNORECASE):
        result['js_urls'].append(urljoin(base_url, m.group(1)))

    for m in re.finditer(r'<a[^>]+href=["\']?([^"\'>\s#]+)', html, re.IGNORECASE):
        u = urljoin(base_url, m.group(1))
        if urlparse(u).netloc == urlparse(base_url).netloc:
            result['links'].append(u)

    for m in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
        block = m.group(0)
        action_m = re.search(r'action=["\']?([^"\'>\s]*)', block, re.IGNORECASE)
        method_m = re.search(r'method=["\']?(get|post|put|delete)', block, re.IGNORECASE)
        inputs = [x.group(1) for x in re.finditer(r'name=["\']?([\w\-]+)', block, re.IGNORECASE)]
        result['forms'].append({
            'action': urljoin(base_url, action_m.group(1) if action_m else ''),
            'method': (method_m.group(1) if method_m else 'get').upper(),
            'inputs': inputs,
        })

    for m in re.finditer(r'[?&]([\w\-]{1,40})=', html):
        result['params'].add(m.group(1))

    result['params'] = sorted(result['params'])
    result['js_urls'] = list(dict.fromkeys(result['js_urls']))[:200]
    result['links'] = list(dict.fromkeys(result['links']))[:300]
    return result


# ============================================================================
# Content Discovery — Smart wordlist based on tech
# ============================================================================
COMMON_PATHS = [
    '.env', '.git/config', '.git/HEAD', '.svn/entries', '.hg/hgrc', '.DS_Store',
    'robots.txt', 'sitemap.xml', 'security.txt', '.well-known/security.txt',
    'admin', 'admin/', 'admin.php', 'administrator', 'wp-admin',
    'phpmyadmin', 'pma', 'db', 'dbadmin',
    'backup', 'backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql', 'dump.sql',
    'config', 'config.php', 'config.json', 'config.yml', 'settings.py', 'wp-config.php',
    'api', 'api/', 'api/v1', 'api/v2', 'api/docs', 'graphql', 'query',
    'swagger', 'swagger-ui.html', 'swagger/index.html', 'openapi.json', 'v2/api-docs', 'v3/api-docs',
    'actuator', 'actuator/env', 'actuator/heapdump', 'actuator/health', 'actuator/mappings',
    '.aws/credentials', 'aws.txt', 'credentials',
    'server-status', 'server-info', 'phpinfo.php', 'info.php', 'test.php',
    'debug', 'trace.axd', 'elmah.axd',
    'jenkins', 'jenkins/login', 'wp-json/wp/v2/users', '?rest_route=/wp/v2/users',
    'metrics', 'health', 'status', 'stats',
    'console', 'shell', 'terminal',
    'test', 'staging', 'dev', 'stage', 'preview',
    'upload', 'uploads', 'files', 'file', 'download',
    'login', 'signin', 'auth', 'oauth', 'sso',
    'user', 'users', 'account', 'profile',
    'log', 'logs', 'error.log', 'access.log',
    'readme', 'README', 'README.md', 'CHANGELOG', 'CHANGELOG.md',
    '.travis.yml', 'docker-compose.yml', 'Dockerfile', '.dockerignore',
    'composer.json', 'composer.lock', 'package.json', 'yarn.lock',
    'nginx.conf', 'httpd.conf', 'web.config', '.htaccess',
]

TECH_PATHS = {
    'wordpress': ['wp-login.php', 'wp-admin/', 'wp-json/', 'xmlrpc.php',
                  'wp-content/debug.log', 'wp-config.php.bak', 'wp-config.php~'],
    'drupal': ['user/login', 'CHANGELOG.txt', 'core/CHANGELOG.txt', 'sites/default/'],
    'joomla': ['administrator/', 'components/', 'modules/', 'templates/'],
    'laravel': ['telescope', 'horizon', '.env', '_ignition/execute-solution'],
    'django': ['admin/', 'accounts/login/', '__debug__/'],
    'rails': ['config/secrets.yml', 'config/database.yml', 'config/master.key'],
    'spring': ['actuator/', 'actuator/env', 'actuator/heapdump', 'actuator/mappings',
               'actuator/httptrace', 'actuator/threaddump'],
    'nextjs': ['_next/static/', 'api/', '_next/data/'],
    'aspnet': ['trace.axd', 'elmah.axd', 'App_Data/', 'bin/', 'Web.config'],
    'tomcat': ['manager/html', 'host-manager/html', 'manager/status'],
    'kubernetes': ['api/v1', 'api/v1/namespaces', 'api/v1/pods'],
}


async def content_discovery(client: AdaptiveHTTPClient, base_url: str,
                            techs: Optional[Set[str]] = None,
                            baseline: Optional[Response] = None,
                            extra_paths: Optional[List[str]] = None,
                            concurrency: int = 20) -> List[Dict]:
    """
    Smart content discovery guided by fingerprinted techs.
    Uses baseline diff to filter false 200s.
    """
    paths = set(COMMON_PATHS)
    for t in (techs or []):
        for p in TECH_PATHS.get(t, []):
            paths.add(p)
    for p in (extra_paths or []):
        paths.add(p.lstrip('/'))

    sem = asyncio.Semaphore(concurrency)
    findings = []
    baseline_fp = baseline.fingerprint() if baseline else None

    async def _test(p: str):
        async with sem:
            url = base_url.rstrip('/') + '/' + p
            r = await client.get(url, follow_redirects=False)
            if r.error:
                return
            # Interesting statuses
            if r.status in (200, 201, 401, 403, 500):
                # 200 must differ from baseline
                if r.status == 200 and baseline_fp and r.fingerprint() == baseline_fp:
                    return
                # v7.2: Skip generic WAF/CDN block pages (Akamai, Cloudflare, etc.)
                # These return 403 with a body echoing the URL — NOT a real
                # exposed path.
                body_l = (r.text or '').lower()[:3000]
                waf_markers = ['access denied', "you don't have permission",
                                'reference #', 'request blocked', 'cloudfront',
                                'not authorized to view', 'the request could not be satisfied',
                                '<title>attention required', 'error 1020', 'error 1015',
                                'incapsula_resource', 'imperva']
                if any(m in body_l for m in waf_markers):
                    return  # WAF block — skip
                findings.append({
                    'path': '/' + p,
                    'url': url,
                    'status': r.status,
                    'length': r.length,
                    'content_type': r.headers.get('Content-Type', ''),
                    'evidence': (r.text or '')[:200],
                })

    await asyncio.gather(*[_test(p) for p in paths], return_exceptions=True)
    findings.sort(key=lambda x: (x['status'], -x['length']))
    return findings


# ============================================================================
# Full Recon Orchestrator
# ============================================================================
async def run_recon(client: AdaptiveHTTPClient, base_url: str,
                    domain: str, techs: Optional[Set[str]] = None,
                    baseline: Optional[Response] = None,
                    depth: str = 'medium') -> Dict:
    """
    depth: 'shallow' | 'medium' | 'deep'
    """
    result = {
        'domain': domain, 'base_url': base_url,
        'urls_discovered': [], 'js_findings': {}, 'html_findings': {},
        'content_discovery': [],
    }

    # 1. External URL sources (skip on shallow)
    if depth != 'shallow':
        tasks = [
            _wayback_urls(client, domain),
            _otx_urls(client, domain),
            _urlscan_urls(client, domain),
        ]
        if depth == 'deep':
            tasks.append(_commoncrawl_urls(client, domain))
        collected = await asyncio.gather(*tasks, return_exceptions=True)
        urls: Set[str] = set()
        for c in collected:
            if isinstance(c, set):
                urls |= c
        result['urls_discovered'] = sorted(urls)[:3000]

    # 2. HTML analysis of base
    r = await client.get(base_url, follow_redirects=True)
    if not r.error:
        html_data = extract_from_html(r.text, base_url)
        result['html_findings'] = {
            'js_urls_count': len(html_data['js_urls']),
            'forms': html_data['forms'],
            'internal_links_count': len(html_data['links']),
            'params_found': html_data['params'][:50],
        }

        # 3. JS mining
        if html_data['js_urls']:
            result['js_findings'] = await mine_js_files(
                client, base_url, html_data['js_urls'])

    # 4. Content discovery
    if depth in ('medium', 'deep'):
        result['content_discovery'] = await content_discovery(
            client, base_url, techs=techs, baseline=baseline,
            concurrency=15 if depth == 'medium' else 30)

    return result
