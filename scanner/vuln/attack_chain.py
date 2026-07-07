"""
Attack Chain Builder — analyzes findings to construct multi-step
exploitation chains.

Each chain represents a realistic attacker workflow, e.g.:
  1. SSRF → cloud metadata leak → AWS credentials → S3 takeover
  2. Open redirect + XSS → phishing chain
  3. LFI + PHP wrapper → RCE
  4. Exposed .git → source code leak → hardcoded secrets → auth bypass
  5. GraphQL introspection → schema leak → mutation abuse
"""
from typing import Any, Dict, List


CHAIN_TEMPLATES = [
    {
        'id': 'ssrf_to_cloud_takeover',
        'name': 'SSRF → Cloud Credentials → Full Cloud Takeover',
        'severity': 'critical',
        'cvss': 10.0,
        'requires': [
            {'type': 'ssrf', 'subtype_starts_with': 'cloud_metadata_'},
        ],
        'boosts': [
            {'type': 'cloud_bucket'},
            {'type': 'exposed_infra'},
        ],
        'steps': [
            'Attacker triggers SSRF at the vulnerable parameter.',
            'SSRF fetches cloud instance-metadata endpoint (IMDSv1/2).',
            'Metadata returns temporary IAM/service-account credentials.',
            'Attacker uses credentials via cloud SDK to enumerate S3/GCS/Azure resources.',
            'If IAM role has *:* or overly-broad permissions → full account takeover.',
        ],
        'mitigation': [
            'Disable IMDSv1 (require IMDSv2 with hop-limit=1) on AWS.',
            'Set egress firewall rules blocking access to 169.254.169.254 from web tier.',
            'Apply least-privilege IAM roles.',
        ],
    },
    {
        'id': 'lfi_to_rce',
        'name': 'LFI + PHP Filter Wrapper → RCE',
        'severity': 'critical',
        'cvss': 9.8,
        'requires': [
            {'type': 'lfi'},
        ],
        'boosts': [
            {'type': 'exposed_path', 'path_contains': ['.env', 'wp-config']},
        ],
        'steps': [
            'Attacker verifies LFI on file/path parameter.',
            'Uses php://filter chains to read source code (base64-encoded).',
            'Locates credentials, DB creds, or session secrets in source.',
            'If log poisoning or /proc/self/environ writable → escalate to RCE.',
        ],
        'mitigation': [
            'Never pass user input to include/require/file_get_contents/readfile.',
            'Whitelist allowed filenames; use ID → path mapping.',
            'Disable allow_url_include and disable dangerous PHP wrappers.',
        ],
    },
    {
        'id': 'open_redirect_phishing',
        'name': 'Open Redirect + XSS → Credential Phishing',
        'severity': 'high',
        'cvss': 8.1,
        'requires': [
            {'type': 'open_redirect'},
            {'type': 'xss'},
        ],
        'steps': [
            'Attacker sends legitimate-looking link (target domain) with open-redirect payload.',
            'Victim clicks; browser redirects to attacker-controlled clone.',
            'XSS on the trusted domain executes attacker JS in same origin.',
            'Session cookie / OAuth token stolen. Full account takeover.',
        ],
        'mitigation': [
            'Whitelist redirect destinations. Never trust user-controlled URL params.',
            'Fix reflected XSS with strict output encoding.',
            'Enable strict CSP with nonce.',
        ],
    },
    {
        'id': 'git_leak_to_source_leak',
        'name': 'Exposed .git → Source Code Leak → Hard-coded Secrets',
        'severity': 'critical',
        'cvss': 9.5,
        'requires': [
            {'type': 'exposed_path', 'path_contains': ['.git']},
        ],
        'boosts': [
            {'type': 'secret_leak'},
        ],
        'steps': [
            'Attacker downloads .git/objects to reconstruct entire repo (git-dumper).',
            'Reviews source for hardcoded secrets, JWT signing keys, DB credentials.',
            'Uses leaked credentials against staging/prod endpoints.',
        ],
        'mitigation': [
            'Never deploy .git to production.',
            'Enforce pre-commit hooks that scan for secrets (gitleaks/trufflehog).',
            'Block deep-file access at web-server level (nginx: location ~ /\\.).',
        ],
    },
    {
        'id': 'sqli_to_authbypass',
        'name': 'SQLi → Authentication Bypass → Admin Access',
        'severity': 'critical',
        'cvss': 9.8,
        'requires': [
            {'type': 'sqli'},
        ],
        'steps': [
            'Attacker exploits SQL injection at authentication or session parameter.',
            'Uses boolean/error/time-based technique to dump users table.',
            'Cracks/uses password hashes; or crafts UNION SELECT to bypass login.',
        ],
        'mitigation': [
            'Use parameterized queries (prepared statements) ONLY.',
            'Never build SQL by string concatenation.',
            'Apply WAF as defence-in-depth (not primary).',
        ],
    },
    {
        'id': 'graphql_introspection_abuse',
        'name': 'GraphQL Introspection → Schema Leak → Mutation Abuse',
        'severity': 'high',
        'cvss': 7.5,
        'requires': [
            {'type': 'graphql'},
        ],
        'steps': [
            'Attacker runs full introspection query to enumerate all types and fields.',
            'Identifies hidden mutations (register, updateRole, setEmail, etc.).',
            'Crafts a mutation exploiting missing authorization checks.',
        ],
        'mitigation': [
            'Disable introspection in production (Apollo/Graphene config).',
            'Enforce authorization on every field & mutation.',
            'Rate-limit query depth and complexity.',
        ],
    },
    {
        'id': 'cmd_to_full_rce',
        'name': 'Command Injection → Reverse Shell → Lateral Movement',
        'severity': 'critical',
        'cvss': 10.0,
        'requires': [
            {'type': 'command_injection'},
        ],
        'steps': [
            'Attacker verifies command injection with `id` or time delay.',
            'Establishes reverse shell (bash/nc/python) to attacker C2.',
            'Enumerates internal network, escalates via kernel/misconfig.',
        ],
        'mitigation': [
            'Never pass user input to shell functions (system, exec, eval).',
            'Use process arg-list APIs (execve with arg array).',
            'Deploy egress firewall.',
        ],
    },
    {
        'id': 'cache_poisoning_defacement',
        'name': 'Web Cache Poisoning → Mass Defacement',
        'severity': 'high',
        'cvss': 8.6,
        'requires': [
            {'type': 'cache_poisoning'},
        ],
        'boosts': [
            {'type': 'host_header_injection'},
        ],
        'steps': [
            'Attacker discovers unkeyed header that influences cached response.',
            'Injects payload via unkeyed header → cache stores poisoned response.',
            'All subsequent legitimate users receive the poisoned response.',
        ],
        'mitigation': [
            'Include all headers that affect response in the cache key.',
            'Sanitize/reject unexpected headers (X-Forwarded-*, X-Original-*).',
            'Add "Vary" headers appropriately.',
        ],
    },
    {
        'id': 'actuator_to_heapdump_creds',
        'name': 'Spring Actuator → Heapdump → Credentials Leak',
        'severity': 'critical',
        'cvss': 9.5,
        'requires': [
            {'type': 'exposed_path', 'path_contains': ['actuator']},
        ],
        'steps': [
            'Attacker discovers exposed Spring actuator endpoints.',
            'Downloads /actuator/heapdump (JVM memory snapshot).',
            'Extracts credentials, session tokens, DB passwords using MAT/jhat.',
        ],
        'mitigation': [
            'Never expose actuator/env, /heapdump, /threaddump in production.',
            'Restrict management endpoints to internal network only.',
            'Require authentication for all actuator endpoints.',
        ],
    },
]


def _finding_matches(f: Dict, requirement: Dict) -> bool:
    """Check if a finding matches a chain-template requirement."""
    if requirement.get('type') and f.get('type') != requirement['type']:
        return False
    ss = requirement.get('subtype_starts_with')
    if ss and not (f.get('subtype') or '').startswith(ss):
        return False
    pc = requirement.get('path_contains')
    if pc:
        haystack = ((f.get('path') or '') + ' ' + (f.get('url') or '')).lower()
        if not any(kw.lower() in haystack for kw in pc):
            return False
    return True


def build_chains(findings: List[Dict]) -> List[Dict]:
    """
    Build attack chains from a list of (verified) findings.
    Each chain returned includes:
      - id, name, severity, cvss
      - triggering findings (list)
      - narrative steps
      - suggested mitigation
    Chains are only emitted when ALL required findings are present.
    """
    if not findings:
        return []

    chains = []
    for tmpl in CHAIN_TEMPLATES:
        triggering: List[Dict] = []
        matched_requirements = 0
        for req in tmpl['requires']:
            match = next((f for f in findings if _finding_matches(f, req)), None)
            if match is not None:
                triggering.append({
                    'type': match.get('type'),
                    'subtype': match.get('subtype'),
                    'url': match.get('url'),
                    'param': match.get('param'),
                    'payload': match.get('payload'),
                    'severity': match.get('severity'),
                })
                matched_requirements += 1
        if matched_requirements != len(tmpl['requires']):
            continue

        # Look for boosters (optional)
        boosters: List[Dict] = []
        for b in tmpl.get('boosts', []):
            m = next((f for f in findings if _finding_matches(f, b)), None)
            if m is not None:
                boosters.append({
                    'type': m.get('type'),
                    'subtype': m.get('subtype'),
                    'url': m.get('url'),
                })

        chains.append({
            'id': tmpl['id'],
            'name': tmpl['name'],
            'severity': tmpl['severity'],
            'cvss': tmpl['cvss'],
            'triggering_findings': triggering,
            'boosters': boosters,
            'steps': tmpl['steps'],
            'mitigation': tmpl['mitigation'],
            'confidence': 90 if not boosters else 95,
        })

    # Sort by CVSS desc
    chains.sort(key=lambda c: -c.get('cvss', 0))
    return chains
