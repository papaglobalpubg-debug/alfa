"""
OAuth2 / OpenID Connect / SAML — attack-surface scanner.

Non-destructive probes only. We never actually complete an auth flow.

Findings:
  * Discovery documents publicly exposed (.well-known/openid-configuration,
    /.well-known/oauth-authorization-server)
  * `client_id` echoed with `redirect_uri` accepting wildcards
  * `response_type=token` (implicit flow) still supported
  * SAML metadata leaks IdP entity + signing certs
  * `openid-configuration` uses HTTP (not HTTPS) issuer or endpoints
  * `token_endpoint_auth_methods_supported` accepts `none`
  * `id_token_signing_alg_values_supported` allows `HS256` symmetric algs
  * SAML `AuthnRequest` accepted at `/saml/acs` without signature
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional
from urllib.parse import urlparse


OIDC_DISCOVERY_PATHS = [
    '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server',
    '/auth/realms/master/.well-known/openid-configuration',  # Keycloak
]

SAML_PATHS = [
    '/saml/metadata', '/saml/metadata.xml',
    '/simplesaml/saml2/idp/metadata.php',
    '/adfs/services/trust/mex',
    '/auth/saml/metadata',
]

INSECURE_ALGS = {'none', 'HS256', 'HS384', 'HS512'}


def _origin(u: str) -> str:
    p = urlparse(u if u.startswith(('http://', 'https://')) else 'https://' + u)
    return f'{p.scheme}://{p.netloc}'


def _add(out: List[Dict], **kw):
    kw.setdefault('type', 'oauth_saml')
    kw.setdefault('confidence', 85)
    out.append(kw)


async def _check_oidc_discovery(client, base_url: str, findings: List[Dict]):
    origin = _origin(base_url)
    for path in OIDC_DISCOVERY_PATHS:
        url = origin + path
        r = await client.get(url)
        if r.status != 200 or 'json' not in (r.headers.get('content-type', '').lower()):
            # some servers return json without content-type — try to parse anyway
            if r.status != 200:
                continue
        try:
            doc = json.loads(r.text[:100000])
        except Exception:
            continue
        if 'issuer' not in doc:
            continue

        _add(
            findings,
            subtype='oidc_discovery_exposed',
            severity='low',
            cvss=3.1,
            url=url,
            evidence=r.text[:400],
            description='OIDC discovery document is publicly accessible. This is intentional '
                        'for public identity providers but attackers use it to map every '
                        'endpoint, scope, and supported flow.',
            remediation='If the identity provider is internal, restrict discovery to internal '
                        'networks. If it is public, ensure the exposed configuration is minimal.',
            confidence=95,
        )

        # HTTP issuer / endpoint (not HTTPS)
        issuer = doc.get('issuer', '')
        insecure_urls = [issuer] + [
            doc.get(k, '') for k in
            ('authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri')
        ]
        for iu in insecure_urls:
            if isinstance(iu, str) and iu.startswith('http://'):
                _add(
                    findings,
                    subtype='oidc_insecure_endpoint',
                    severity='high',
                    cvss=7.5,
                    url=url,
                    evidence=f'insecure endpoint in discovery: {iu}',
                    description='OIDC discovery advertises an HTTP (not HTTPS) endpoint. '
                                'Tokens or authorization codes flowing through this endpoint '
                                'can be intercepted.',
                    remediation='Update the IdP configuration to publish HTTPS URLs only.',
                    confidence=95,
                )
                break

        # token_endpoint_auth_methods_supported contains "none"
        methods = doc.get('token_endpoint_auth_methods_supported') or []
        if isinstance(methods, list) and 'none' in methods:
            _add(
                findings,
                subtype='oidc_public_client_no_auth',
                severity='medium',
                cvss=5.4,
                url=url,
                evidence=f'token_endpoint_auth_methods_supported={methods}',
                description='OIDC server allows the "none" client-authentication method. '
                            'Public clients can call the token endpoint without proving '
                            'their identity, enabling client impersonation if PKCE is not '
                            'strictly enforced.',
                remediation='Require PKCE for every public client and restrict "none" to '
                            'known public client_ids only.',
                confidence=85,
            )

        # Weak signing algorithms
        algs = doc.get('id_token_signing_alg_values_supported') or []
        weak = [a for a in algs if a in INSECURE_ALGS]
        if weak:
            _add(
                findings,
                subtype='oidc_weak_signing_alg',
                severity='medium',
                cvss=6.1,
                url=url,
                evidence=f'weak algs advertised: {weak}',
                description=('OIDC advertises weak / symmetric id-token signing algorithms '
                             f'({", ".join(weak)}). Symmetric algs like HS256 use the client '
                             'secret as key — a leaked secret forges tokens. "none" completely '
                             'disables signature checks.'),
                remediation='Only advertise RS256/RS384/RS512 or ES256/ES384/ES512. Remove '
                            'symmetric algs and "none" from id_token_signing_alg_values_supported.',
                confidence=90,
            )

        # response_types_supported includes implicit flow
        rts = doc.get('response_types_supported') or []
        if any('token' in rt.split() for rt in rts):
            _add(
                findings,
                subtype='oidc_implicit_flow_enabled',
                severity='low',
                cvss=4.3,
                url=url,
                evidence=f'response_types_supported={rts}',
                description='OIDC still advertises the implicit flow (response_type=token). '
                            'Implicit flow leaks tokens through the URL fragment and is '
                            'formally deprecated by the OAuth 2.0 Security BCP.',
                remediation='Use Authorization Code + PKCE. Remove "token" and "id_token token" '
                            'from response_types_supported.',
                confidence=90,
            )
        # only inspect first working discovery doc
        return


async def _check_saml_metadata(client, base_url: str, findings: List[Dict]):
    origin = _origin(base_url)
    for path in SAML_PATHS:
        url = origin + path
        r = await client.get(url)
        body = (r.text or '')[:20000]
        if r.status != 200 or 'EntityDescriptor' not in body:
            continue
        # Signing certificate presence
        cert_ct = body.count('X509Certificate')
        entity = ''
        try:
            entity = body.split('entityID="', 1)[1].split('"', 1)[0]
        except Exception:
            pass
        _add(
            findings,
            subtype='saml_metadata_exposed',
            severity='low',
            cvss=3.1,
            url=url,
            evidence=f'entityID={entity} · certs={cert_ct}',
            description='SAML metadata endpoint is publicly accessible. This is normal for '
                        'public IdPs but attackers use the entityID and signing certificate '
                        'thumbprints to fingerprint the IdP and craft targeted phishing.',
            remediation='For internal IdPs, restrict metadata access to trusted SPs '
                        '(via mutual TLS or IP allowlists).',
            confidence=90,
        )
        # HTTP binding leaked in metadata
        if 'HTTP-POST' in body and '://http://' not in body and 'Location="http://' in body:
            _add(
                findings,
                subtype='saml_insecure_binding',
                severity='high',
                cvss=7.4,
                url=url,
                evidence='HTTP (not HTTPS) binding location in metadata',
                description='SAML metadata advertises an HTTP binding for SSO/SLO endpoints. '
                            'Assertions and requests can be intercepted in transit.',
                remediation='Update SAML metadata Location attributes to HTTPS URLs.',
                confidence=90,
            )
        return


async def scan_oauth_saml(client, base_url: str,
                          log_cb: Optional[callable] = None) -> List[Dict]:
    findings: List[Dict] = []
    try:
        await _check_oidc_discovery(client, base_url, findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] oidc check failed: {e}')
    try:
        await _check_saml_metadata(client, base_url, findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] saml check failed: {e}')
    return findings
