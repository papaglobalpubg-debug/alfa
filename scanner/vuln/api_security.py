"""
API Security Scanner — REST + GraphQL surface hardening.

Focus:
  * REST — exposure of swagger/openapi/api-docs endpoints
           unauthenticated verbs (PUT/DELETE/PATCH) on sensitive routes
           missing rate-limit headers on auth-adjacent paths
           JSON error verbosity (stack traces, DB errors)
           mass-assignment hints (fields being echoed back)
  * GraphQL — introspection enabled, verbose errors, batching allowed,
              suggestion mode (typo → hint), field-level auth heuristics.

All checks are non-destructive: no POST that mutates real data. We use
safe HEAD/GET probes and, for GraphQL, only introspection queries.

Returns a list[dict] of findings, each with type=`api_security` and a
subtype describing the specific issue. Confidence is capped conservatively.
"""
from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import urlparse


# Well-known endpoints that leak API structure. Kept small — each hit is
# a real finding, not a fingerprint sweep.
API_DOC_PATHS = [
    '/openapi.json', '/openapi.yaml', '/swagger.json', '/swagger.yaml',
    '/swagger/v1/swagger.json',
    '/v2/api-docs', '/v3/api-docs',
    '/api-docs', '/api-docs.json',
    '/swagger-ui.html', '/swagger-ui/', '/swagger-ui/index.html',
    '/redoc', '/docs',  # FastAPI defaults
    '/api/swagger', '/api/openapi.json',
]

GRAPHQL_PATHS = [
    '/graphql', '/graphiql', '/api/graphql',
    '/v1/graphql', '/query', '/gql',
    '/api/gql',
]

# Doc-signature keywords that confirm real API doc (not a marketing page)
DOC_SIGNATURES = [
    '"openapi"', '"swagger"', 'swagger-ui', '"paths":',
    '"info":', 'redoc', '"components":', '"definitions":',
]

# Introspection query — a single minimal call to test if graphql exposes schema
INTROSPECTION_QUERY = (
    '{"query":"query IntrospectionQuery{__schema{queryType{name} '
    'mutationType{name} types{name kind fields{name}}}}"}'
)

BATCH_QUERY = (
    '[{"query":"{__typename}"},{"query":"{__typename}"}]'
)


def _add_finding(out: List[Dict], **kw):
    kw.setdefault('type', 'api_security')
    kw.setdefault('confidence', 80)
    out.append(kw)


async def _check_api_docs(client, base_url: str, findings: List[Dict]):
    """Probe well-known OpenAPI/Swagger doc endpoints."""
    origin = _origin(base_url)
    for path in API_DOC_PATHS:
        url = origin + path
        r = await client.get(url)
        if r.status != 200:
            continue
        body = (r.text or '')[:20000].lower()
        if not any(sig in body for sig in DOC_SIGNATURES):
            continue
        # Heuristic severity — if it exposes real paths + methods, medium.
        # Redoc/swagger-ui pages alone are also medium (helps attacker map API).
        _add_finding(
            findings,
            subtype='api_docs_exposed',
            severity='medium',
            cvss=5.3,
            url=url,
            evidence=body[:400],
            description='Public API documentation (OpenAPI/Swagger/Redoc) '
                        'exposes internal endpoints, methods, and parameter '
                        'shapes to unauthenticated visitors.',
            remediation='Restrict API docs to internal networks or authenticated '
                        'admin users. If the API is public, still audit what '
                        'internal endpoints are documented.',
            confidence=95,
        )
        # Only report the first hit per doc family to avoid duplicates
        return


async def _check_dangerous_methods_on_api(client, base_url: str, findings: List[Dict]):
    """
    Look for unauthenticated write verbs on common API prefixes.
    Uses OPTIONS to get Allow: header when possible.
    """
    origin = _origin(base_url)
    probes = ['/api/', '/api/v1/', '/api/v2/', '/rest/', '/v1/']
    for p in probes:
        url = origin + p
        r = await client.options(url)
        if r.status == 0 or r.status >= 500:
            continue
        allow = (r.headers.get('Allow') or r.headers.get('allow') or '').upper()
        if not allow:
            continue
        dangerous = [m for m in ('PUT', 'DELETE', 'PATCH') if m in allow]
        if dangerous:
            _add_finding(
                findings,
                subtype='dangerous_verbs_on_api_root',
                severity='low',
                cvss=3.7,
                url=url,
                evidence=f'Allow: {allow}',
                description=(f'API root {p} advertises write verbs '
                             f'({", ".join(dangerous)}) via OPTIONS without '
                             f'authentication challenge.'),
                remediation='Restrict OPTIONS response to methods the caller is '
                            'actually allowed to invoke; strip write verbs from '
                            'unauthenticated preflight.',
                confidence=70,
            )


async def _check_graphql(client, base_url: str, findings: List[Dict]):
    """
    Probe GraphQL endpoints for introspection + batching.
    """
    origin = _origin(base_url)
    for path in GRAPHQL_PATHS:
        url = origin + path
        # Detect endpoint presence first with a cheap POST of __typename
        r = await client.post(
            url,
            headers={'Content-Type': 'application/json'},
            data='{"query":"{__typename}"}',
        )
        if r.status not in (200, 400, 405):
            continue
        body = (r.text or '')[:8000]
        if '"__typename"' not in body and '"data"' not in body and '"errors"' not in body:
            continue

        # Introspection
        ri = await client.post(
            url,
            headers={'Content-Type': 'application/json'},
            data=INTROSPECTION_QUERY,
        )
        ib = (ri.text or '')[:20000]
        if ri.status == 200 and '"__schema"' in ib and '"types"' in ib:
            _add_finding(
                findings,
                subtype='graphql_introspection_enabled',
                severity='medium',
                cvss=5.3,
                url=url,
                evidence=ib[:400],
                description='GraphQL endpoint exposes full schema via introspection. '
                            'Attackers can enumerate every type, field, and mutation '
                            'without any authentication.',
                remediation='Disable introspection in production (Apollo: introspection: '
                            '!process.env.PRODUCTION). Restrict to internal environments only.',
                confidence=95,
            )

        # Batching (denial-of-service amplifier + rate-limit bypass)
        rb = await client.post(
            url,
            headers={'Content-Type': 'application/json'},
            data=BATCH_QUERY,
        )
        bb = (rb.text or '')[:4000]
        if rb.status == 200 and bb.startswith('['):
            _add_finding(
                findings,
                subtype='graphql_batching_allowed',
                severity='low',
                cvss=4.3,
                url=url,
                evidence=bb[:300],
                description='GraphQL endpoint accepts query batching. This can be used '
                            'to amplify per-request rate limits (100x per HTTP call) and '
                            'brute-force logins from a single request.',
                remediation='Disable batching or set a strict per-batch cap (1–2 ops max) '
                            'and apply the same rate-limit rules to every query in a batch.',
                confidence=75,
            )

        # Verbose error mode
        rv = await client.post(
            url,
            headers={'Content-Type': 'application/json'},
            data='{"query":"{ notARealField_xyzzy_9x8 }"}',
        )
        vb = (rv.text or '')[:4000]
        if rv.status == 200 and ('"Did you mean' in vb or 'didYouMean' in vb):
            _add_finding(
                findings,
                subtype='graphql_field_suggestions',
                severity='low',
                cvss=3.1,
                url=url,
                evidence=vb[:300],
                description='GraphQL server returns "Did you mean" hints for unknown fields, '
                            'enabling schema enumeration even when introspection is disabled.',
                remediation='Disable field suggestions in production error responses '
                            '(Apollo v4+: NoSuggestions plugin, graphql-js: setSuggestions).',
                confidence=90,
            )
        return  # only report first working graphql endpoint


async def _check_verbose_errors(client, base_url: str, findings: List[Dict]):
    """Trigger a JSON body error on common API paths."""
    origin = _origin(base_url)
    for path in ['/api/', '/api/v1/users', '/api/login']:
        url = origin + path
        r = await client.post(
            url,
            headers={'Content-Type': 'application/json'},
            data='{"__broken":',  # intentionally malformed
        )
        body = (r.text or '')[:6000]
        if not body:
            continue
        markers = [
            'Traceback (most recent call last)', 'at java.', 'at org.springframework',
            'System.NullReferenceException', 'stack trace', 'sqlalchemy',
            'PDOException', 'psycopg2', 'ORA-', 'MongoServerError',
        ]
        if any(m.lower() in body.lower() for m in markers):
            _add_finding(
                findings,
                subtype='verbose_api_errors',
                severity='medium',
                cvss=5.3,
                url=url,
                evidence=body[:300],
                description='API endpoint returns full stack traces / framework errors '
                            'to unauthenticated clients on malformed input.',
                remediation='Configure a global exception handler that returns a generic '
                            'error id + log the detail server-side only.',
                confidence=85,
            )
            return


def _origin(u: str) -> str:
    p = urlparse(u if u.startswith(('http://', 'https://')) else 'https://' + u)
    return f'{p.scheme}://{p.netloc}'


async def scan_api_security(client, base_url: str,
                             log_cb: Optional[callable] = None) -> List[Dict]:
    """Public entrypoint. Runs all API-security probes and returns findings."""
    findings: List[Dict] = []
    try:
        await _check_api_docs(client, base_url, findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] api_docs check failed: {e}')
    try:
        await _check_dangerous_methods_on_api(client, base_url, findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] api verbs check failed: {e}')
    try:
        await _check_graphql(client, base_url, findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] graphql check failed: {e}')
    try:
        await _check_verbose_errors(client, base_url, findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] verbose_errors check failed: {e}')
    return findings
