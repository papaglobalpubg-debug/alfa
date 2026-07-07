"""
Cloud & Infrastructure Scanners.
- S3/GCS/Azure buckets discovery + takeover
- Kubernetes/Docker/etcd/Consul detection
- Fast async port scanner
- Nuclei-lite CVE templates
"""
import asyncio
import re
import socket
from typing import Dict, List, Optional, Set

from .http_client import AdaptiveHTTPClient
from .payloads import PAYLOADS


# ============================================================================
# PORT SCANNER (async TCP connect)
# ============================================================================
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 631,
    993, 995, 1080, 1433, 1521, 1723, 2049, 2181, 2375, 2376, 2379, 2380,
    3000, 3306, 3389, 3690, 4369, 4444, 4567, 4848, 5000, 5432, 5601, 5672,
    5900, 5984, 6379, 7001, 7002, 8000, 8001, 8008, 8009, 8080, 8081, 8088,
    8089, 8090, 8161, 8443, 8500, 8834, 8888, 9000, 9042, 9092, 9200, 9300,
    9418, 9443, 9600, 9990, 10000, 11211, 15672, 27017, 27018, 50000, 50070,
]


async def _check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return False


async def port_scan(host: str, ports: Optional[List[int]] = None,
                    concurrency: int = 200, timeout: float = 2.0) -> List[int]:
    ports = ports or COMMON_PORTS
    sem = asyncio.Semaphore(concurrency)

    async def _one(p):
        async with sem:
            if await _check_port(host, p, timeout):
                return p
        return None

    results = await asyncio.gather(*[_one(p) for p in ports])
    return sorted([p for p in results if p])


# ============================================================================
# CLOUD BUCKETS
# ============================================================================
S3_TAKEOVER_MARKERS = ['NoSuchBucket', 'The specified bucket does not exist']
S3_LISTABLE = ['<ListBucketResult']
S3_PUBLIC_WRITE_TEST_PATH = '/emergent-scan-test-write'


async def check_s3_bucket(client: AdaptiveHTTPClient, bucket_name: str,
                          target_domain: str = '') -> Dict:
    """
    Check S3 bucket. True takeover requires the target domain to CNAME to this bucket.
    Without DNS confirmation we only report "available_name" (low severity).
    """
    result = {'bucket': bucket_name, 'status': 'unknown', 'issues': []}
    urls = [
        f'https://{bucket_name}.s3.amazonaws.com/',
        f'https://s3.amazonaws.com/{bucket_name}/',
    ]
    for u in urls:
        r = await client.get(u)
        if r.error:
            continue
        text = r.text or ''
        if any(m in text for m in S3_TAKEOVER_MARKERS):
            # True takeover only if bucket name matches part of the target domain
            is_related = target_domain and (
                bucket_name.replace('-', '') in target_domain.replace('.', '').replace('-', '')
                or target_domain.split('.')[0] == bucket_name
            )
            result['status'] = 'available_name' if not is_related else 'takeover_possible'
            result['issues'].append({
                'issue': 's3_takeover' if is_related else 's3_name_available',
                'severity': 'critical' if is_related else 'info',
                'cvss': 9.8 if is_related else 0,
                'evidence': f'NoSuchBucket returned for {u}',
                'url': u,
            })
            return result
        if any(m in text for m in S3_LISTABLE):
            result['status'] = 'listable'
            result['issues'].append({
                'issue': 's3_listable', 'severity': 'high', 'cvss': 7.5,
                'evidence': f'Bucket content list exposed at {u}',
                'url': u,
            })
            return result
        if r.status == 403:
            result['status'] = 'exists_private'
        elif r.status == 200:
            result['status'] = 'accessible'
    return result


async def check_gcs_bucket(client: AdaptiveHTTPClient, bucket_name: str,
                           target_domain: str = '') -> Dict:
    result = {'bucket': bucket_name, 'status': 'unknown', 'issues': []}
    u = f'https://storage.googleapis.com/{bucket_name}/'
    r = await client.get(u)
    if r.error:
        return result
    text = r.text or ''
    is_related = target_domain and (
        bucket_name.replace('-', '') in target_domain.replace('.', '').replace('-', '')
        or target_domain.split('.')[0] == bucket_name
    )
    if 'NoSuchBucket' in text or 'The specified bucket does not exist' in text:
        # Only treat as takeover if bucket name relates to target — otherwise it's just
        # a public S3 name-available response (worthless noise)
        if is_related:
            result['status'] = 'takeover_possible'
            result['issues'].append({
                'issue': 'gcs_takeover', 'severity': 'critical', 'cvss': 9.8,
                'url': u, 'evidence': f'NoSuchBucket at {u}',
            })
    elif '<ListBucketResult' in text:
        result['status'] = 'listable'
        result['issues'].append({
            'issue': 'gcs_listable', 'severity': 'high', 'cvss': 7.5,
            'url': u, 'evidence': f'Bucket listable at {u}',
        })
    return result


async def check_azure_blob(client: AdaptiveHTTPClient, account_name: str) -> Dict:
    result = {'account': account_name, 'status': 'unknown', 'issues': []}
    u = f'https://{account_name}.blob.core.windows.net/'
    r = await client.get(u)
    if r.error:
        return result
    if 'ContainerNotFound' in (r.text or ''):
        result['status'] = 'account_exists'
    elif r.status == 400 and 'Value for one of the query parameters specified in the request URI is invalid' in (r.text or ''):
        result['status'] = 'account_exists'
    return result


async def enumerate_cloud_buckets(client: AdaptiveHTTPClient, domain: str,
                                  extra_names: Optional[List[str]] = None) -> List[Dict]:
    """
    Generate common bucket-name candidates and probe them.
    """
    parts = domain.replace('www.', '').split('.')
    base = parts[0]
    org = parts[-2] if len(parts) >= 2 else base

    candidates = set()
    prefixes = ['', 'dev-', 'staging-', 'prod-', 'test-', 'backup-', 'assets-',
                'files-', 'uploads-', 'static-', 'cdn-', 'media-']
    suffixes = ['', '-dev', '-staging', '-prod', '-test', '-backup', '-assets',
                '-files', '-uploads', '-media', '-cdn', '-data', '-app']
    bases = {base, org, base + org, org + base}
    for b in bases:
        for pre in prefixes:
            for suf in suffixes:
                candidates.add(f'{pre}{b}{suf}'.strip('-'))
    for e in (extra_names or []):
        candidates.add(e)
    candidates = [c for c in candidates if 3 <= len(c) <= 63 and re.match(r'^[a-z0-9\-]+$', c)]

    sem = asyncio.Semaphore(15)
    findings = []

    async def _test(name):
        async with sem:
            # S3
            r_s3 = await check_s3_bucket(client, name, target_domain=domain)
            # Only report S3 if it's a real, actionable finding (skip generic name_available spam)
            if r_s3['status'] in ('takeover_possible', 'listable', 'accessible'):
                findings.append({**r_s3, 'provider': 'aws_s3'})
            # GCS
            r_gcs = await check_gcs_bucket(client, name, target_domain=domain)
            if r_gcs['status'] in ('takeover_possible', 'listable'):
                findings.append({**r_gcs, 'provider': 'gcp_gcs'})
            # Azure
            r_az = await check_azure_blob(client, name)
            if r_az['status'] not in ('unknown',):
                findings.append({**r_az, 'provider': 'azure_blob'})

    await asyncio.gather(*[_test(c) for c in list(candidates)[:80]])
    return findings


# ============================================================================
# KUBERNETES / DOCKER / etcd / Consul detection
# ============================================================================
async def detect_infra_apis(client: AdaptiveHTTPClient, base_url: str) -> List[Dict]:
    findings = []
    checks = [
        # Kubernetes
        (f'{base_url}/api/v1', 'kubernetes_api', 'critical', 9.8,
         lambda r: 'APIVersions' in (r.text or '') or 'kind' in (r.text or '')),
        (f'{base_url}/api', 'kubernetes_api_root', 'critical', 9.8,
         lambda r: '"versions"' in (r.text or '')),
        (f'{base_url}/version', 'kubernetes_version', 'medium', 5.3,
         lambda r: 'gitVersion' in (r.text or '') and 'k8s' in (r.text or '').lower()),
        (f'{base_url}/api/v1/namespaces/kube-system/secrets', 'kubernetes_secrets_leak',
         'critical', 10.0, lambda r: r.status == 200 and 'items' in (r.text or '')),
        # Docker
        (f'{base_url}/v1.40/info', 'docker_api', 'critical', 9.8,
         lambda r: 'Containers' in (r.text or '') and 'Images' in (r.text or '')),
        (f'{base_url}/containers/json', 'docker_containers', 'critical', 9.8,
         lambda r: r.status == 200 and (r.text or '').strip().startswith('[')),
        # etcd
        (f'{base_url}/v2/keys/', 'etcd_v2', 'critical', 9.8,
         lambda r: 'node' in (r.text or '') and 'nodes' in (r.text or '')),
        (f'{base_url}/version', 'etcd_v3_version', 'medium', 5.0,
         lambda r: 'etcdserver' in (r.text or '')),
        # Consul
        (f'{base_url}/v1/catalog/services', 'consul_services', 'high', 7.5,
         lambda r: r.status == 200 and (r.text or '').startswith('{')),
        (f'{base_url}/v1/agent/self', 'consul_agent', 'high', 7.5,
         lambda r: 'Config' in (r.text or '')),
        # Vault
        (f'{base_url}/v1/sys/health', 'vault_health', 'medium', 5.0,
         lambda r: 'initialized' in (r.text or '')),
        # Prometheus
        (f'{base_url}/metrics', 'prometheus_metrics', 'low', 3.1,
         lambda r: '# HELP' in (r.text or '') and '# TYPE' in (r.text or '')),
        # Elasticsearch
        (f'{base_url}/_cat/indices', 'elasticsearch_open', 'high', 7.5,
         lambda r: r.status == 200),
        (f'{base_url}/', 'elasticsearch_root', 'medium', 5.0,
         lambda r: 'You Know, for Search' in (r.text or '') or '"cluster_name"' in (r.text or '')),
    ]
    for url, name, sev, cvss, matcher in checks:
        r = await client.get(url)
        if r.error:
            continue
        try:
            if matcher(r):
                findings.append({
                    'type': 'exposed_infra', 'subtype': name,
                    'url': url, 'status': r.status,
                    'severity': sev, 'cvss': cvss, 'confidence': 90,
                    'evidence': (r.text or '')[:300],
                })
        except Exception:
            continue
    return findings


# ============================================================================
# NUCLEI-LITE CVE TEMPLATES ENGINE
# ============================================================================
async def run_cve_templates(client: AdaptiveHTTPClient, base_url: str,
                            fingerprint_techs: Optional[Set[str]] = None,
                            oob_host: Optional[str] = None) -> List[Dict]:
    findings = []
    sem = asyncio.Semaphore(15)

    async def _run_template(tpl):
        async with sem:
            # Skip if requires specific fingerprint and target lacks it
            need_fp = tpl.get('fingerprint')
            if need_fp and fingerprint_techs is not None and need_fp not in fingerprint_techs:
                return

            paths = tpl.get('paths', [tpl.get('path')])
            paths = [p for p in paths if p]
            headers = tpl.get('headers', {}) or {}
            if tpl.get('oob') and oob_host:
                headers = {k: v.replace('{OOB}', oob_host) for k, v in headers.items()}

            for path in paths:
                url = base_url.rstrip('/') + path
                method = tpl.get('method', 'GET')
                body = tpl.get('body')
                if method == 'POST':
                    r = await client.post(url, data=body, headers=headers)
                else:
                    r = await client.get(url, headers=headers)
                if r.error:
                    continue

                hits = []
                # v7.1: NEVER match on status alone — status-only match causes
                # massive false positives on catch-all endpoints (httpbin, SPAs, etc.)
                # We require at least body/header/size evidence.
                status_matched = False
                if tpl.get('match_status') and r.status in tpl['match_status']:
                    status_matched = True
                if tpl.get('match_body'):
                    # v7.2: Strip the requested URL/path from response body BEFORE
                    # searching for markers. WAF "Access Denied" pages echo the
                    # requested URL, which would cause body_match to trigger on
                    # any substring of the URL (e.g. "kibana" in /app/kibana).
                    body_orig = r.text or ''
                    # Strip URL, path, and encoded variants from the search body
                    stripped_body = body_orig
                    from urllib.parse import quote
                    for tok in (url, path, quote(url, safe=''), quote(path, safe='')):
                        if tok:
                            stripped_body = stripped_body.replace(tok, '')
                    # Also strip HTML-entity-encoded variants (Akamai style)
                    def _html_entities(s):
                        return ''.join(f'&#{ord(c)};' if c in '/:.' else c for c in s)
                    stripped_body = stripped_body.replace(_html_entities(url), '')
                    stripped_body = stripped_body.replace(_html_entities(path), '')
                    body_hit = False
                    for m in tpl['match_body']:
                        if m in stripped_body:
                            hits.append(f'body_match={m[:40]}')
                            body_hit = True
                            break
                    if not body_hit:
                        continue  # No body match after URL strip — skip
                if tpl.get('match_headers'):
                    for h in tpl['match_headers']:
                        if h in r.headers:
                            hits.append(f'header_present={h}')
                if tpl.get('match_size_gt') and r.length > tpl['match_size_gt']:
                    hits.append(f'size>{tpl["match_size_gt"]}')
                if tpl.get('header_match'):
                    lc_headers = {k.lower(): v for k, v in r.headers.items()}
                    for hk, pattern in tpl['header_match'].items():
                        val = lc_headers.get(hk.lower(), '')
                        if val and re.search(pattern, val):
                            hits.append(f'header_regex={hk}')

                # STRICT: require at least ONE non-status hit
                has_content_evidence = bool(hits)
                if not has_content_evidence:
                    continue

                # v7.2: Additional WAF/CDN block detection — drop if body looks
                # like a generic Access Denied page.
                body_l = (r.text or '').lower()[:5000]
                waf_markers = ['access denied', "you don't have permission",
                                'reference #', 'blocked by', 'cloudfront error',
                                'request blocked', 'not authorized to view']
                if any(m in body_l for m in waf_markers):
                    continue  # WAF block page — not a real CVE hit

                # Only if status matched too (or template didn't require status)
                if tpl.get('match_status') and not status_matched:
                    continue

                if status_matched:
                    hits.insert(0, f'status={r.status}')

                findings.append({
                    'type': 'cve', 'id': tpl['id'], 'cve': tpl.get('cve'),
                    'name': tpl['name'], 'severity': tpl['severity'],
                    'cvss': tpl.get('cvss', 0),
                    'url': url, 'method': method,
                    'evidence': ' | '.join(hits), 'confidence': 88,
                    'verified': True,
                })
                break  # One path enough

    await asyncio.gather(*[_run_template(t) for t in PAYLOADS.cve])
    return findings


# ============================================================================
# SECRETS SCANNER (regex based, over responses/JS)
# ============================================================================
def find_secrets_in_text(text: str, source: str = '') -> List[Dict]:
    findings = []
    if not text:
        return findings
    for name, pattern in PAYLOADS.secrets.items():
        try:
            for m in re.findall(pattern, text)[:5]:
                val = m if isinstance(m, str) else (m[-1] if m else '')
                if val and 8 < len(val) < 500:
                    findings.append({
                        'type': 'secret_leak',
                        'secret_type': name,
                        'value_snippet': val[:100],
                        'source': source,
                        'severity': 'critical' if 'private_key' in name or 'aws' in name or 'stripe' in name else 'high',
                        'cvss': 9.8 if 'private_key' in name else 8.6,
                        'confidence': 90,
                    })
        except Exception:
            continue
    return findings
