"""
Master Orchestrator for the Weaponized Vulnerability Scanner v6.

Coordinates all scanner modules with intelligent, adaptive logic:
  1. Fingerprint target (tech + WAF + framework)
  2. Recon (URLs, JS mining, params)
  3. Content discovery (guided by fingerprint)
  4. Injection tests (context-aware payloads)
  5. Logic/access vulnerabilities
  6. Advanced (smuggling/cache/proto/graphql)
  7. Cloud/infra (buckets, k8s, docker, CVE templates)
  8. Secrets discovery
  9. Multi-step verification (reduce false positives)
"""
import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from .http_client import AdaptiveHTTPClient
from .fingerprint import fingerprint_target, Fingerprint
from .recon_engine import run_recon
from .injection_scanners import (
    scan_xss, scan_sqli, scan_nosqli, scan_cmd_injection,
    scan_ssti, scan_lfi, scan_xxe,
)
from .logic_scanners import (
    scan_ssrf, scan_open_redirect, scan_cors, scan_crlf, scan_jwt, scan_idor,
)
from .advanced_scanners import (
    scan_smuggling, scan_cache_poisoning, scan_prototype_pollution,
    scan_graphql, scan_deserialization,
)
from .cloud_scanner import (
    port_scan, enumerate_cloud_buckets, detect_infra_apis,
    run_cve_templates, find_secrets_in_text,
)
from .extended_scanners import (
    scan_host_header, scan_web_cache_deception, scan_client_proto_pollution,
    scan_csp, scan_directory_listing, scan_http_methods, scan_sri,
)
from .deep_crawler import deep_crawl
from .crawler_v2 import crawl_v2
from .verifier import verify_all, verification_stats
from .attack_chain import build_chains

# v7.5 — Batch 3 modules
from .api_security import scan_api_security
from .oauth_saml import scan_oauth_saml
from .mobile_backend import scan_mobile_backend
from .web3_scanner import scan_web3

# v7.7.2 — Total Annihilation modules
from .graphql_scanner import scan_graphql as scan_graphql_v2
from .websocket_scanner import scan_websocket
from .cve_correlator import correlate as cve_correlate


@dataclass
class VulnScanConfig:
    target: str
    concurrency: int = 30
    timeout: float = 12.0
    max_retries: int = 2
    verify_tls: bool = False
    depth: str = 'medium'         # 'shallow' | 'medium' | 'deep'
    passive_only: bool = False
    session_cookies: Optional[str] = None
    session_headers: Optional[Dict[str, str]] = None
    custom_payloads: Optional[Dict[str, List[str]]] = None
    proxy_pool: Optional[List[str]] = None
    rate_limit_delay: float = 0.0
    enabled_modules: Set[str] = field(default_factory=lambda: {
        'fingerprint', 'recon', 'crawler', 'xss', 'sqli', 'nosqli', 'cmd', 'ssti', 'lfi', 'xxe',
        'ssrf', 'open_redirect', 'cors', 'crlf', 'smuggling', 'cache_poisoning',
        'prototype_pollution', 'graphql', 'deserialization',
        'cloud_buckets', 'infra_apis', 'cve_templates', 'secrets', 'port_scan',
        'host_header', 'web_cache_deception', 'client_proto', 'csp', 'directory_listing',
        'http_methods', 'sri',
        # v7.5 — Batch 3
        'api_security', 'oauth_saml', 'mobile_backend', 'web3',
        # v7.7.2 — Total Annihilation
        'websocket', 'cve_correlate',
    })
    disabled_modules: Set[str] = field(default_factory=set)
    oob_host: Optional[str] = None                   # e.g., interact.sh domain
    session_a_cookies: Optional[Dict] = None          # For IDOR
    session_b_cookies: Optional[Dict] = None
    jwt_token: Optional[str] = None
    custom_params: Optional[List[str]] = None
    custom_paths: Optional[List[str]] = None
    proxy: Optional[str] = None
    log_cb: Optional[Callable[[str], None]] = None

    def is_enabled(self, module: str) -> bool:
        if module in self.disabled_modules:
            return False
        if self.passive_only:
            # In passive mode ONLY these read-only modules run
            passive_ok = {'fingerprint', 'recon', 'crawler', 'cors', 'csp',
                          'directory_listing', 'sri', 'secrets', 'cloud_buckets',
                          'infra_apis',
                          # v7.5 — Batch 3, all non-destructive
                          'api_security', 'oauth_saml', 'mobile_backend', 'web3'}
            return module in passive_ok and module in self.enabled_modules
        return module in self.enabled_modules


class VulnScanner:
    def __init__(self, config: VulnScanConfig):
        self.config = config
        self.findings: List[Dict] = []
        self.fingerprint: Optional[Fingerprint] = None
        self.recon: Dict = {}
        self.stats: Dict = {}
        self.errors: List[str] = []
        # v7.4 — Cooperative cancellation flag. External API can set
        # `scanner.cancel_event.set()` to abort mid-scan between phases.
        self.cancel_event = asyncio.Event()

    def _log(self, msg: str):
        if self.config.log_cb:
            try:
                self.config.log_cb(msg)
            except Exception:
                pass

    def request_cancel(self):
        """Signal that the scan should stop as soon as possible."""
        self.cancel_event.set()

    def _check_cancelled(self):
        """Raise CancelledError if cancellation was requested."""
        if self.cancel_event.is_set():
            raise asyncio.CancelledError('scan cancelled by user')

    def _normalize_url(self, target: str) -> str:
        target = target.strip()
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target.rstrip('/')

    def _origin_url(self, target: str) -> str:
        """Return scheme://host[:port] without any path or query.
        Used by CVE templates and infra checks so they build clean URLs.
        """
        from urllib.parse import urlparse
        p = urlparse(self._normalize_url(target))
        return f'{p.scheme}://{p.netloc}'

    async def _extract_urls_and_params(self) -> List[Dict]:
        """
        Extract testable URL+params combos from recon.
        Returns list of {url, params: [list], forms: [{action, method, inputs}]}.
        """
        tests = []
        base = self._normalize_url(self.config.target)
        # Base URL with any params from HTML/JS mining
        params = set(self.recon.get('html_findings', {}).get('params_found', []) or [])
        params |= set(self.recon.get('js_findings', {}).get('params', []) or [])
        if self.config.custom_params:
            params |= set(self.config.custom_params)
        tests.append({'url': base, 'params': sorted(params), 'forms': self.recon.get('html_findings', {}).get('forms', [])})

        # URLs discovered from wayback with query params
        for u in (self.recon.get('urls_discovered') or [])[:200]:
            if '?' in u and '=' in u:
                from urllib.parse import urlparse, parse_qs
                p = urlparse(u)
                if p.netloc and self.config.target.replace('www.', '') in p.netloc:
                    qparams = list(parse_qs(p.query).keys())
                    if qparams:
                        tests.append({'url': u, 'params': qparams, 'forms': []})
        return tests[:15]  # Cap to prevent explosion

    async def run(self) -> Dict[str, Any]:
        t0 = time.time()
        base_url = self._normalize_url(self.config.target)
        self._log(f'[*] Starting scan on {base_url}')

        # v7.6 · SEC-001 — pin the scan to its own root domain so the scanner
        # cannot be tricked (via redirects, recon URLs, or user-supplied
        # params) into fetching arbitrary hosts.
        try:
            from urllib.parse import urlparse
            from .ssrf_guard import (
                assert_safe, set_scope_allowlist, clear_scope_allowlist,
            )
            assert_safe(base_url)  # rejects internal/loopback targets outright
            root_host = (urlparse(base_url).hostname or '').lower()
            # Allow the exact host and all subdomains
            if root_host:
                # Strip common subdomain prefixes so *.example.com works when
                # target is www.example.com
                _root = root_host
                if _root.startswith('www.'):
                    _root = _root[4:]
                set_scope_allowlist({root_host, _root})
        except Exception as e:
            self._log(f'[!] SSRF guard rejected target: {e}')
            return {
                'target': base_url, 'findings': [], 'errors': [f'ssrf_guard: {e}'],
                'summary': {}, 'stats': {}, 'duration_seconds': 0.0,
                'status': 'rejected',
            }

        async with AdaptiveHTTPClient(
            concurrency=self.config.concurrency,
            timeout=self.config.timeout,
            max_retries=self.config.max_retries,
            verify_tls=self.config.verify_tls,
            proxy=self.config.proxy,
            session_cookies=self.config.session_cookies,
            session_headers=self.config.session_headers,
            proxy_pool=self.config.proxy_pool,
            rate_limit_delay=self.config.rate_limit_delay,
        ) as client:
            # ================= FINGERPRINT =================
            if self.config.is_enabled('fingerprint'):
                self._check_cancelled()
                self._log('[*] Fingerprinting target...')
                try:
                    self.fingerprint = await fingerprint_target(client, base_url)
                    self._log(f'[+] Fingerprint: waf={self.fingerprint.waf} '
                              f'techs={",".join(sorted(self.fingerprint.techs)[:10])}')
                except Exception as e:
                    self.errors.append(f'fingerprint: {e}')

            fp = self.fingerprint
            techs = fp.techs if fp else set()

            # ================= RECON =================
            if self.config.is_enabled('recon'):
                self._check_cancelled()
                self._log('[*] Running recon (Wayback/OTX/URLScan/JS mining)...')
                try:
                    hostname = base_url.replace('https://', '').replace('http://', '').split('/')[0]
                    self.recon = await run_recon(
                        client, base_url, hostname,
                        techs=techs, baseline=fp.baseline if fp else None,
                        depth=self.config.depth,
                    )
                    self._log(f'[+] Recon: {len(self.recon.get("urls_discovered", []))} URLs '
                              f'| {len(self.recon.get("content_discovery", []))} paths')
                except Exception as e:
                    self.errors.append(f'recon: {e}')

            # Register recon findings (content discovery + secrets in JS)
            for cd in self.recon.get('content_discovery', [])[:100]:
                sev = 'critical' if any(k in cd['path'].lower() for k in ['.env', 'wp-config', '.git/config',
                                                                          'id_rsa', 'credentials', 'secret',
                                                                          'heapdump']) else \
                      ('high' if cd['status'] in (200, 401, 403) and any(k in cd['path'].lower()
                                                                          for k in ['admin', 'actuator', 'phpmyadmin', 'swagger']) else 'medium')
                self.findings.append({
                    'type': 'exposed_path', 'severity': sev,
                    'cvss': 9.0 if sev == 'critical' else (7.5 if sev == 'high' else 5.0),
                    'url': cd['url'], 'path': cd['path'], 'status': cd['status'],
                    'evidence': cd.get('evidence', ''), 'confidence': 85,
                })

            # Secrets from JS
            for sec in self.recon.get('js_findings', {}).get('secrets', []):
                self.findings.append({
                    'type': 'secret_leak', 'secret_type': sec['type'],
                    'severity': 'critical' if any(x in sec['type'] for x in
                                                  ['aws', 'private_key', 'stripe', 'openai',
                                                   'anthropic', 'github', 'gitlab']) else 'high',
                    'cvss': 9.8, 'source': sec.get('source_url', ''),
                    'value_snippet': sec.get('value', '')[:100], 'confidence': 90,
                })

            # ================= DEEP CRAWLER v2 (Total Annihilation) =================
            crawl_result = {}
            if self.config.is_enabled('crawler'):
                self._check_cancelled()
                self._log('[*] Deep crawling site (BFS+priority · sitemap · robots · wayback · JS mining · hidden-param brute)...')
                try:
                    # v7.7.2 · aggressive defaults — thousands of URLs per depth
                    depth_map = {'shallow': 3, 'quick': 3, 'medium': 4, 'deep': 6, 'insane': 8}
                    pages_map = {'shallow': 500, 'quick': 500, 'medium': 2000, 'deep': 5000, 'insane': 10000}
                    crawl_result = await crawl_v2(
                        client, base_url,
                        max_depth=depth_map.get(self.config.depth, 4),
                        max_urls=pages_map.get(self.config.depth, 2000),
                        render_js=(self.config.depth in ('deep', 'insane')),
                        mine_hidden_params=True,
                        aggressive=True,
                        log_cb=self.config.log_cb,
                    )
                    self._log(f'[+] Crawler v2: {crawl_result.get("urls_count", 0)} URLs, '
                              f'{crawl_result.get("forms_count", 0)} forms, '
                              f'{crawl_result.get("endpoints_count", 0)} JS endpoints, '
                              f'{crawl_result.get("hidden_params_count", 0)} hidden params, '
                              f'{crawl_result.get("graphql_count", 0)} graphql, '
                              f'{crawl_result.get("websocket_count", 0)} websockets')
                    # Merge into recon
                    self.recon.setdefault('crawler', {})
                    self.recon['crawler'] = crawl_result
                    # Feed discovered params into recon params
                    hf = self.recon.setdefault('html_findings', {})
                    hf.setdefault('params_found', [])
                    all_params = set(hf['params_found'])
                    # Collect params from forms + hidden_params + endpoints with ?
                    for form in crawl_result.get('forms', []):
                        for inp in form.get('inputs', []):
                            if inp:
                                all_params.add(inp)
                    for u, ps in (crawl_result.get('hidden_params') or {}).items():
                        for p in ps:
                            all_params.add(p)
                    hf['params_found'] = sorted(all_params)[:500]
                    # Feed URLs
                    disc = self.recon.setdefault('urls_discovered', [])
                    seen = set(disc)
                    for u in crawl_result.get('urls', []):
                        if u not in seen:
                            disc.append(u)
                            seen.add(u)
                    # Feed GraphQL / WebSocket URLs for new specialised modules
                    self.recon['graphql_urls'] = crawl_result.get('graphql_urls', [])
                    self.recon['websocket_urls'] = crawl_result.get('websocket_urls', [])
                except Exception as e:
                    self.errors.append(f'crawler: {e}')

            self._check_cancelled()

            # ================= URLs & PARAMS =================
            tests = await self._extract_urls_and_params()

            # ================= INJECTION SCANNERS =================
            injection_tasks = []

            for t in tests[:8]:
                url = t['url']
                params = t['params']
                if self.config.is_enabled('xss'):
                    injection_tasks.append(('xss', scan_xss(client, url, params, fp)))
                if self.config.is_enabled('sqli'):
                    injection_tasks.append(('sqli', scan_sqli(client, url, params, fp)))
                if self.config.is_enabled('nosqli'):
                    injection_tasks.append(('nosqli', scan_nosqli(client, url, params)))
                if self.config.is_enabled('cmd'):
                    injection_tasks.append(('cmd', scan_cmd_injection(
                        client, url, params, oob_host=self.config.oob_host)))
                if self.config.is_enabled('ssti'):
                    injection_tasks.append(('ssti', scan_ssti(client, url, params)))
                if self.config.is_enabled('lfi'):
                    injection_tasks.append(('lfi', scan_lfi(client, url, params)))
                if self.config.is_enabled('open_redirect'):
                    injection_tasks.append(('open_redirect', scan_open_redirect(client, url, params)))
                if self.config.is_enabled('crlf'):
                    injection_tasks.append(('crlf', scan_crlf(client, url, params)))
                if self.config.is_enabled('ssrf'):
                    injection_tasks.append(('ssrf', scan_ssrf(client, url, params,
                                                              oob_host=self.config.oob_host)))
                if self.config.is_enabled('deserialization'):
                    injection_tasks.append(('deser', scan_deserialization(client, url, params)))

            self._log(f'[*] Running {len(injection_tasks)} injection scan tasks...')
            self._check_cancelled()
            results = await asyncio.gather(*[t[1] for t in injection_tasks], return_exceptions=True)
            for (label, _), res in zip(injection_tasks, results):
                if isinstance(res, list):
                    self.findings.extend(res)
                    if res:
                        self._log(f'[!] {label}: {len(res)} finding(s)')
                elif isinstance(res, Exception):
                    self.errors.append(f'{label}: {res}')

            # ================= XXE (form-agnostic on base URL) =================
            if self.config.is_enabled('xxe'):
                try:
                    self.findings.extend(await scan_xxe(client, base_url))
                except Exception as e:
                    self.errors.append(f'xxe: {e}')

            # ================= LOGIC / ADVANCED =================
            other_tasks = []
            if self.config.is_enabled('cors'):
                other_tasks.append(('cors', scan_cors(client, base_url)))
            if self.config.is_enabled('smuggling') and self.config.depth == 'deep':
                other_tasks.append(('smuggling', scan_smuggling(client, base_url)))
            if self.config.is_enabled('cache_poisoning'):
                other_tasks.append(('cache_poisoning', scan_cache_poisoning(client, base_url)))
            if self.config.is_enabled('prototype_pollution'):
                other_tasks.append(('proto', scan_prototype_pollution(client, base_url)))
            if self.config.is_enabled('graphql'):
                other_tasks.append(('graphql', scan_graphql(client, base_url)))
                # v7.7.2 · GraphQL v2 with introspection + batching + depth attacks
                other_tasks.append(('graphql_v2', scan_graphql_v2(client, base_url, log_cb=self.config.log_cb)))
            # v7.7.2 · WebSocket fuzzer — feeds off crawler-discovered ws URLs
            if self.config.is_enabled('websocket'):
                ws_urls = list(self.recon.get('websocket_urls', []))
                if ws_urls:
                    other_tasks.append(('websocket',
                                        scan_websocket(client, ws_urls, log_cb=self.config.log_cb)))
            if self.config.is_enabled('host_header'):
                other_tasks.append(('host_header', scan_host_header(client, base_url)))
            if self.config.is_enabled('web_cache_deception'):
                other_tasks.append(('web_cache_deception', scan_web_cache_deception(client, base_url)))
            if self.config.is_enabled('client_proto'):
                other_tasks.append(('client_proto', scan_client_proto_pollution(client, base_url)))
            if self.config.is_enabled('csp'):
                other_tasks.append(('csp', scan_csp(client, base_url)))
            if self.config.is_enabled('directory_listing'):
                other_tasks.append(('directory_listing', scan_directory_listing(client, base_url)))
            if self.config.is_enabled('http_methods'):
                other_tasks.append(('http_methods', scan_http_methods(client, base_url)))
            if self.config.is_enabled('sri'):
                other_tasks.append(('sri', scan_sri(client, base_url)))
            if self.config.is_enabled('infra_apis'):
                origin = self._origin_url(self.config.target)
                other_tasks.append(('infra', detect_infra_apis(client, origin)))
            # v7.5 — Batch 3 modules
            if self.config.is_enabled('api_security'):
                other_tasks.append(('api_security', scan_api_security(client, base_url, log_cb=self.config.log_cb)))
            if self.config.is_enabled('oauth_saml'):
                other_tasks.append(('oauth_saml', scan_oauth_saml(client, base_url, log_cb=self.config.log_cb)))
            if self.config.is_enabled('mobile_backend'):
                _baseline_text = (fp.baseline.text if fp and fp.baseline else '') or ''
                other_tasks.append(('mobile_backend',
                                    scan_mobile_backend(client, base_url,
                                                         baseline_text=_baseline_text,
                                                         log_cb=self.config.log_cb)))
            if self.config.is_enabled('web3'):
                _baseline_text = (fp.baseline.text if fp and fp.baseline else '') or ''
                other_tasks.append(('web3',
                                    scan_web3(client, base_url,
                                              baseline_text=_baseline_text,
                                              log_cb=self.config.log_cb)))
            if self.config.jwt_token:
                other_tasks.append(('jwt', scan_jwt(client, base_url, self.config.jwt_token)))
            if self.config.session_a_cookies and self.config.session_b_cookies:
                other_tasks.append(('idor', scan_idor(client, base_url,
                                                       self.config.session_a_cookies,
                                                       self.config.session_b_cookies)))

            self._log(f'[*] Running {len(other_tasks)} logic/advanced scan tasks...')
            self._check_cancelled()
            results = await asyncio.gather(*[t[1] for t in other_tasks], return_exceptions=True)
            for (label, _), res in zip(other_tasks, results):
                if isinstance(res, list):
                    self.findings.extend(res)
                    if res:
                        self._log(f'[!] {label}: {len(res)} finding(s)')
                elif isinstance(res, dict) and isinstance(res.get('findings'), list):
                    # v7.7.2 · new modules (graphql_v2, websocket, race) return {'findings': [...]}
                    self.findings.extend(res['findings'])
                    if res['findings']:
                        self._log(f'[!] {label}: {len(res["findings"])} finding(s)')
                elif isinstance(res, Exception):
                    self.errors.append(f'{label}: {res}')

            # ================= CVE AUTO-CORRELATION (v7.7.2) =================
            if fp and self.config.is_enabled('cve_correlate'):
                try:
                    fp_dict = {
                        'server': (fp.baseline.headers.get('server') if fp and fp.baseline else '') or '',
                        'x-powered-by': (fp.baseline.headers.get('x-powered-by') if fp and fp.baseline else '') or '',
                        'technologies': {t: '' for t in (fp.techs or [])},
                    }
                    matches = cve_correlate(fp_dict)
                    if matches:
                        self.findings.extend(matches)
                        self._log(f'[!] CVE correlator: {len(matches)} match(es)')
                except Exception as e:
                    self.errors.append(f'cve_correlate: {e}')

            # ================= CLOUD & CVE =================
            if self.config.is_enabled('cloud_buckets'):
                self._check_cancelled()
                try:
                    hostname = base_url.replace('https://', '').replace('http://', '').split('/')[0]
                    self._log('[*] Enumerating cloud buckets...')
                    buckets = await enumerate_cloud_buckets(client, hostname)
                    for b in buckets:
                        if b.get('issues'):
                            for issue in b['issues']:
                                self.findings.append({
                                    'type': 'cloud_bucket',
                                    'provider': b.get('provider'),
                                    'bucket': b.get('bucket') or b.get('account'),
                                    'subtype': issue['issue'],
                                    'severity': issue['severity'],
                                    'cvss': issue.get('cvss', 8),
                                    'url': issue.get('url') or (f"https://{b.get('bucket') or b.get('account')}.s3.amazonaws.com/"
                                                                if b.get('provider') == 'aws_s3' else ''),
                                    'evidence': issue.get('evidence', ''),
                                    'confidence': 90,
                                })
                except Exception as e:
                    self.errors.append(f'cloud_buckets: {e}')

            if self.config.is_enabled('cve_templates'):
                try:
                    origin = self._origin_url(self.config.target)
                    self._log('[*] Running CVE templates (nuclei-lite) against origin: ' + origin)
                    cve_findings = await run_cve_templates(client, origin, techs, self.config.oob_host)
                    self.findings.extend(cve_findings)
                    if cve_findings:
                        self._log(f'[!] CVE templates: {len(cve_findings)} finding(s)')
                except Exception as e:
                    self.errors.append(f'cve_templates: {e}')

            # ================= SECRETS in baseline body =================
            if self.config.is_enabled('secrets') and fp and fp.baseline:
                secs = find_secrets_in_text(fp.baseline.text or '', source=base_url)
                self.findings.extend(secs)

            # ================= PORT SCAN =================
            port_results = []
            if self.config.is_enabled('port_scan') and self.config.depth == 'deep':
                try:
                    hostname = base_url.replace('https://', '').replace('http://', '').split('/')[0]
                    self._log('[*] Port scanning...')
                    port_results = await port_scan(hostname, timeout=1.5, concurrency=150)
                    self._log(f'[+] Open ports: {port_results}')
                except Exception as e:
                    self.errors.append(f'port_scan: {e}')

            self.stats = {**client.stats, 'elapsed': time.time() - t0}

        # Dedupe findings
        self.findings = self._dedupe(self.findings)
        # STRICT VERIFICATION (v7.1) — drop false positives, mark verified
        pre_count = len(self.findings)
        self.findings = verify_all(self.findings)
        self._log(f'[+] Verifier: {pre_count} → {len(self.findings)} findings (dropped {pre_count - len(self.findings)} FPs)')
        verif_stats = verification_stats(self.findings)
        # Sort by severity, then by verified status (verified first)
        sev_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0, 'unknown': 0}
        self.findings.sort(key=lambda f: (-sev_order.get(f.get('severity', 'info'), 0),
                                           0 if f.get('verified') else 1))
        # Build attack chains from verified findings only
        try:
            chains = build_chains([f for f in self.findings if f.get('verified')])
        except Exception as e:
            self.errors.append(f'attack_chain: {e}')
            chains = []

        # v7.6 · SEC-001 — release the per-scan scope allow-list so the next
        # scan starts with a clean slate.
        try:
            from .ssrf_guard import clear_scope_allowlist
            clear_scope_allowlist()
        except Exception:
            pass

        return {
            'target': base_url,
            'started_at': t0, 'elapsed': time.time() - t0,
            'fingerprint': fp.to_dict() if fp else {},
            'recon': self.recon,
            'ports': port_results,
            'findings': self.findings,
            'attack_chains': chains,
            'verification': verif_stats,
            'stats': self.stats,
            'errors': self.errors,
            'summary': self._summary(),
        }

    def _summary(self) -> Dict[str, int]:
        s = {'total': len(self.findings), 'critical': 0, 'high': 0, 'medium': 0,
             'low': 0, 'info': 0, 'unknown': 0}
        by_type: Dict[str, int] = {}
        for f in self.findings:
            sev = f.get('severity', 'info')
            if sev in s:
                s[sev] += 1
            t = f.get('type', 'unknown')
            by_type[t] = by_type.get(t, 0) + 1
        s['by_type'] = by_type
        return s

    def _dedupe(self, findings: List[Dict]) -> List[Dict]:
        """
        Stronger dedupe: normalize URL (strip query values, keep only param names + host + path).
        Ensures same finding on same param on same endpoint (with different injected values)
        does NOT appear twice.
        """
        from urllib.parse import urlparse, parse_qsl
        seen = set()
        out = []
        for f in findings:
            url = f.get('url') or ''
            try:
                p = urlparse(url)
                norm_url = f'{p.scheme}://{p.netloc}{p.path}'
                param_names = tuple(sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)}))
            except Exception:
                norm_url = url
                param_names = ()
            key = (
                f.get('type'),
                f.get('subtype'),
                norm_url,
                f.get('param') or '',
                param_names,
                f.get('secret_type') or '',
                f.get('bucket') or '',
                f.get('id') or '',
                (f.get('cve') or '')[:20],
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out


# ============================================================================
# Convenience one-shot function
# ============================================================================
async def scan_target(target: str, **kwargs) -> Dict[str, Any]:
    cfg = VulnScanConfig(target=target, **kwargs)
    scanner = VulnScanner(cfg)
    return await scanner.run()
