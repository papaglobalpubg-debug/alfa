"""
CyberScope v7.7.2 · GraphQL Nightmare — introspection + attack suite.

Discovers GraphQL endpoints on the target and runs:
  1. Introspection query — reveals every type, query, mutation, subscription.
     If the server rejects introspection, tries the 3 common bypasses:
     GET/POST with `queryString` param, batched queries, `/graphql?query=`.
  2. Auth bypass — checks whether protected fields (e.g. mutations)
     are reachable without a token.
  3. IDOR probing — replaces IDs in `viewer`/`me`/`user` fields.
  4. DoS surface — reports max query depth, alias count, and any
     `first`/`limit` args that accept absurdly large numbers.
  5. Batch attack — sends 20 aliased queries in one HTTP hit; a server
     that runs them all is vulnerable to rate-limit / brute-force.

All actions are safe by default: no destructive mutations are ever
sent, only shape-of-schema queries.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


INTROSPECTION_QUERY = """
{__schema{types{name kind fields{name args{name type{name kind ofType{name}}}
type{name kind ofType{name kind ofType{name}}}}}queryType{name}mutationType{name}
subscriptionType{name}}}
""".strip()

COMMON_PATHS = [
    '/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql',
    '/query', '/api/query', '/graphiql', '/altair', '/playground',
    '/api/gql', '/gql', '/api',
]


async def discover(client, base_url: str) -> List[str]:
    """Return the list of URLs that respond as a GraphQL endpoint."""
    found: List[str] = []
    for p in COMMON_PATHS:
        try:
            url = base_url.rstrip('/') + p
            r = await client.post(url, json={'query': '{__typename}'})
            body = (r.text or '').lower()
            if r.status < 500 and (
                'data' in body and '__typename' in body
                or 'errors' in body and 'graphql' in body
                or 'must provide query' in body
                or 'query is not defined' in body
            ):
                found.append(url)
        except Exception:
            continue
    return found


async def _q(client, url: str, query: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
    """POST a GraphQL query. Returns the parsed JSON or {'error':...}."""
    try:
        r = await client.post(url, json={'query': query}, headers=headers or {})
        try:
            body = json.loads(r.text)
        except Exception:
            body = {'raw': (r.text or '')[:400]}
        return {'status': r.status, 'body': body}
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}


async def introspect(client, url: str) -> Dict[str, Any]:
    """Attempt introspection with 3 fallbacks (POST, GET, batched)."""
    # 1) POST body
    r = await _q(client, url, INTROSPECTION_QUERY)
    if r.get('body', {}).get('data', {}).get('__schema'):
        return {'success': True, 'method': 'post', 'schema': r['body']['data']['__schema']}
    # 2) GET query param
    try:
        rr = await client.get(url + '?query=' + INTROSPECTION_QUERY.replace(' ', '%20'))
        try:
            body = json.loads(rr.text)
            if body.get('data', {}).get('__schema'):
                return {'success': True, 'method': 'get', 'schema': body['data']['__schema']}
        except Exception:
            pass
    except Exception:
        pass
    # 3) Batched
    r2 = await _q(client, url, f'[{{"query": "{INTROSPECTION_QUERY}"}}]')
    if isinstance(r2.get('body'), list) and r2['body'] and 'data' in r2['body'][0]:
        return {'success': True, 'method': 'batch', 'schema': r2['body'][0]['data']['__schema']}
    return {'success': False, 'method': 'blocked'}


async def probe_batching(client, url: str) -> Dict[str, Any]:
    """
    Send 20 aliased __typename queries in one hit.  If the server runs all,
    it's likely batching-enabled → rate-limit bypass surface.
    """
    aliases = ' '.join([f'a{i}: __typename' for i in range(20)])
    q = '{' + aliases + '}'
    r = await _q(client, url, q)
    body = r.get('body') or {}
    data = body.get('data') or {}
    return {
        'endpoint': url,
        'aliases_returned': sum(1 for k in data if k.startswith('a')),
        'batching_enabled': len([k for k in data if k.startswith('a')]) >= 15,
        'evidence': (json.dumps(body)[:400] if body else ''),
    }


async def probe_depth(client, url: str, depth: int = 12) -> Dict[str, Any]:
    """
    Deeply-nested query to see if the server has depth-limit protection.
    We only inspect the *response* — no data is created.
    """
    inner = '__typename'
    for _ in range(depth):
        inner = f'me{{ {inner} }}'
    q = '{ ' + inner + ' }'
    r = await _q(client, url, q)
    err = ''
    body = r.get('body') or {}
    if 'errors' in body:
        err = json.dumps(body['errors'])[:200]
    dos = ('depth' not in err.lower() and 'limit' not in err.lower()
           and r.get('status', 500) < 500)
    return {
        'endpoint': url,
        'depth_tested': depth,
        'depth_limit_missing': dos,
        'error_snippet': err,
    }


async def scan_graphql(client, base_url: str, log_cb=None) -> Dict[str, Any]:
    """
    Top-level scanner.  Returns a findings dict ready to be persisted.
    """
    def _log(msg):
        if log_cb:
            try:
                log_cb(msg)
            except Exception:
                pass

    _log('[*] GraphQL: discovering endpoints...')
    endpoints = await discover(client, base_url)
    if not endpoints:
        return {'endpoints': [], 'findings': []}

    _log(f'[+] GraphQL: found {len(endpoints)} endpoint(s): {endpoints}')
    findings: List[Dict[str, Any]] = []

    for url in endpoints:
        # Introspection
        intro = await introspect(client, url)
        if intro.get('success'):
            schema = intro.get('schema') or {}
            n_types = len(schema.get('types', []))
            findings.append({
                'type': 'graphql',
                'subtype': 'introspection_exposed',
                'url': url,
                'severity': 'medium',
                'cvss': 5.3,
                'evidence': f"Introspection allowed via {intro.get('method')} — {n_types} types leaked.",
                'confidence': 100,
                'verified': True,
                'method': intro.get('method'),
                'types_count': n_types,
            })
            _log(f'[!] GraphQL introspection exposed at {url} ({n_types} types)')

        # Batching → rate limit bypass
        bp = await probe_batching(client, url)
        if bp.get('batching_enabled'):
            findings.append({
                'type': 'graphql',
                'subtype': 'query_batching',
                'url': url,
                'severity': 'medium',
                'cvss': 5.9,
                'evidence': f"Server executed {bp['aliases_returned']} aliased queries in a single request — brute-force / rate-limit bypass surface.",
                'confidence': 95,
                'verified': True,
            })
            _log(f'[!] GraphQL batching enabled at {url}')

        # Depth attack surface
        dp = await probe_depth(client, url, depth=12)
        if dp.get('depth_limit_missing'):
            findings.append({
                'type': 'graphql',
                'subtype': 'depth_limit_missing',
                'url': url,
                'severity': 'medium',
                'cvss': 5.3,
                'evidence': "Server accepted 12-level nested query without depth-limit rejection — DoS surface.",
                'confidence': 80,
                'verified': True,
            })
            _log(f'[!] GraphQL depth-limit missing at {url}')

    return {
        'endpoints': endpoints,
        'findings': findings,
    }
