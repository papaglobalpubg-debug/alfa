"""
Technology Fingerprinting & WAF Detection.
Detects: framework, server, CMS, JS libs, WAF vendor, cloud provider.
Feeds intelligent payload selection.
"""
import re
from typing import Dict, List, Optional, Set

from .http_client import AdaptiveHTTPClient, Response


# ============================================================================
# Server / Framework signatures (headers + body)
# ============================================================================
TECH_SIGNATURES = {
    # Frameworks
    'php': {'headers': {'X-Powered-By': r'PHP', 'Set-Cookie': r'PHPSESSID'},
            'body': [r'<\?php', r'/wp-content/', r'\.php["\'\s]'], 'type': 'framework'},
    'aspnet': {'headers': {'X-AspNet-Version': r'.*', 'X-Powered-By': r'ASP\.NET',
                           'Set-Cookie': r'ASP\.NET_SessionId'}, 'type': 'framework'},
    'aspnet_mvc': {'headers': {'X-AspNetMvc-Version': r'.*'}, 'type': 'framework'},
    'nodejs_express': {'headers': {'X-Powered-By': r'Express'}, 'type': 'framework'},
    'django': {'headers': {'X-Powered-By': r'Django', 'Set-Cookie': r'csrftoken=|sessionid='},
               'body': [r'csrfmiddlewaretoken'], 'type': 'framework'},
    'flask': {'headers': {'Server': r'Werkzeug', 'Set-Cookie': r'session=\.eJ'},
              'body': [r'Werkzeug'], 'type': 'framework'},
    'rails': {'headers': {'X-Powered-By': r'Phusion Passenger', 'Set-Cookie': r'_rails_session'},
              'body': [r'csrf-token'], 'type': 'framework'},
    'laravel': {'headers': {'Set-Cookie': r'laravel_session|XSRF-TOKEN'},
                'body': [r'Laravel'], 'type': 'framework'},
    'spring': {'headers': {'X-Application-Context': r'.*'},
               'body': [r'Whitelabel Error Page', r'Spring Boot'], 'type': 'framework'},
    'symfony': {'headers': {'X-Debug-Token': r'.*'},
                'body': [r'Symfony', r'sf-toolbar'], 'type': 'framework'},
    'nextjs': {'headers': {'X-Powered-By': r'Next\.js'},
               'body': [r'__NEXT_DATA__', r'/_next/static/'], 'type': 'framework'},
    'nuxtjs': {'body': [r'__NUXT__'], 'type': 'framework'},
    'gatsby': {'body': [r'gatsby-'], 'type': 'framework'},
    # CMS
    'wordpress': {'body': [r'/wp-content/', r'/wp-includes/', r'wp-json', r'wp-emoji-release']},
    'drupal': {'headers': {'X-Generator': r'Drupal', 'X-Drupal-Cache': r'.*'},
               'body': [r'Drupal.settings', r'sites/default/files']},
    'joomla': {'body': [r'/media/system/js/', r'joomla-script-options', r'Joomla!']},
    'magento': {'headers': {'Set-Cookie': r'frontend='},
                'body': [r'Mage.Cookies', r'skin/frontend/']},
    'shopify': {'headers': {'X-ShopId': r'.*', 'X-ShardId': r'.*'},
                'body': [r'Shopify\.', r'shopify_pay']},
    'ghost': {'body': [r'Ghost ', r'ghost/api/v']},
    'strapi': {'body': [r'strapi', r'admin/init'], 'headers': {'X-Powered-By': r'Strapi'}},
    # Servers
    'nginx': {'headers': {'Server': r'nginx'}, 'type': 'server'},
    'apache': {'headers': {'Server': r'Apache'}, 'type': 'server'},
    'iis': {'headers': {'Server': r'Microsoft-IIS'}, 'type': 'server'},
    'litespeed': {'headers': {'Server': r'LiteSpeed'}, 'type': 'server'},
    'openresty': {'headers': {'Server': r'openresty'}, 'type': 'server'},
    'caddy': {'headers': {'Server': r'Caddy'}, 'type': 'server'},
    'tomcat': {'headers': {'Server': r'Apache-Coyote'},
               'body': [r'Apache Tomcat', r'/manager/html'], 'type': 'server'},
    'jetty': {'headers': {'Server': r'Jetty'}, 'type': 'server'},
    'nodejs': {'headers': {'X-Powered-By': r'Node\.js|Express'}, 'type': 'server'},
    # JS libs / frontend
    'react': {'body': [r'data-reactroot|_reactRootContainer|__reactContainer']},
    'angular': {'body': [r'ng-version|ng-app|angular\.js']},
    'vue': {'body': [r'__vue__|Vue\.js|data-v-']},
    'jquery': {'body': [r'jquery(-|\.)\d|jquery\.min\.js']},
    'bootstrap': {'body': [r'bootstrap(-|\.)\d|/bootstrap\.']},
    # DBs / services
    'graphql': {'body': [r'"__schema"|"__typename"|graphql'], 'type': 'api'},
    'swagger': {'body': [r'swagger-ui|openapi|"swagger":\s*"']},
    'kubernetes': {'body': [r'"kind":\s*"Status"|kubernetes\.io']},
}

# ============================================================================
# WAF Signatures
# ============================================================================
WAF_SIGNATURES = {
    'cloudflare': {
        'headers': {'Server': r'cloudflare', 'CF-Ray': r'.*', 'CF-Cache-Status': r'.*'},
        'cookies': [r'__cfduid', r'__cf_bm', r'cf_clearance'],
        'body': [r'Attention Required.*Cloudflare', r'Cloudflare Ray ID', r'/cdn-cgi/challenge-platform'],
        'blocked_status': [403, 503, 520, 521, 522, 523, 524, 525, 526, 527],
    },
    'akamai': {
        'headers': {'Server': r'AkamaiGHost|AkamaiNetStorage', 'X-Akamai-Transformed': r'.*'},
        'cookies': [r'ak_bmsc', r'bm_sv', r'_abck'],
        'body': [r'Access Denied.*Akamai', r'Reference #\d+\.'],
    },
    'aws_waf': {
        'headers': {'X-AMZ-CF-ID': r'.*', 'X-Amz-Cf-Pop': r'.*'},
        'body': [r'AWS WAF', r'blocked by AWS'],
    },
    'imperva_incapsula': {
        'headers': {'X-CDN': r'Incapsula', 'X-Iinfo': r'.*'},
        'cookies': [r'incap_ses', r'visid_incap'],
        'body': [r'Incapsula incident ID', r'_Incapsula_Resource'],
    },
    'sucuri': {
        'headers': {'Server': r'Sucuri/Cloudproxy', 'X-Sucuri-ID': r'.*', 'X-Sucuri-Cache': r'.*'},
        'body': [r'Access Denied.*Sucuri', r'Sucuri WebSite Firewall'],
    },
    'f5_bigip': {
        'headers': {'Server': r'BigIP', 'Set-Cookie': r'BIGipServer'},
        'body': [r'The requested URL was rejected'],
    },
    'barracuda': {
        'cookies': [r'barra_counter_session'],
        'body': [r'You have been blocked.*Barracuda'],
    },
    'wordfence': {
        'body': [r'Generated by Wordfence', r'Your access to this site has been limited'],
    },
    'modsecurity': {
        'headers': {'Server': r'Mod_Security|mod_security'},
        'body': [r'Mod_Security|NOYB'],
    },
    'fortiweb': {
        'cookies': [r'FORTIWAFSID'],
        'body': [r'Blocked.*FortiWeb'],
    },
    'citrix_netscaler': {
        'headers': {'Via': r'NS-CACHE', 'Cneonction': r'.*'},
        'cookies': [r'ns_af', r'citrix_ns_id'],
    },
    'wallarm': {
        'headers': {'Server': r'Wallarm|nginx-wallarm'},
    },
    'fastly': {
        'headers': {'X-Served-By': r'cache-.*', 'Fastly-Debug-Digest': r'.*'},
    },
    'stackpath': {
        'headers': {'Server': r'StackPath'},
    },
    'reblaze': {
        'cookies': [r'rbzid'],
        'body': [r'reblaze', r'rbzns'],
    },
    'radware': {
        'headers': {'X-SL-CompState': r'.*'},
        'body': [r'Unauthorized Activity Has Been Detected'],
    },
}


class Fingerprint:
    """Aggregated fingerprint result for a target."""

    def __init__(self):
        self.techs: Set[str] = set()
        self.tech_details: Dict[str, str] = {}
        self.waf: Optional[str] = None
        self.waf_details: Dict[str, str] = {}
        self.server: Optional[str] = None
        self.cloud: Optional[str] = None
        self.frameworks: Set[str] = set()
        self.cms: Optional[str] = None
        self.js_libs: Set[str] = set()
        self.probable_dbms: Set[str] = set()
        self.baseline: Optional[Response] = None

    def to_dict(self) -> Dict:
        return {
            'techs': sorted(self.techs),
            'tech_details': self.tech_details,
            'waf': self.waf,
            'waf_details': self.waf_details,
            'server': self.server,
            'cloud': self.cloud,
            'frameworks': sorted(self.frameworks),
            'cms': self.cms,
            'js_libs': sorted(self.js_libs),
            'probable_dbms': sorted(self.probable_dbms),
        }


def _match_headers(headers: Dict[str, str], patterns: Dict[str, str]) -> Optional[str]:
    lc_headers = {k.lower(): v for k, v in (headers or {}).items()}
    for hk, pattern in patterns.items():
        val = lc_headers.get(hk.lower())
        if val and re.search(pattern, val, re.IGNORECASE):
            return f'{hk}: {val[:80]}'
    return None


def _match_body(body: str, patterns: List[str]) -> Optional[str]:
    if not body:
        return None
    for p in patterns:
        m = re.search(p, body[:200000], re.IGNORECASE)
        if m:
            return m.group(0)[:100]
    return None


def _match_cookies(headers: Dict[str, str], patterns: List[str]) -> Optional[str]:
    sc = ''
    for k, v in (headers or {}).items():
        if k.lower() == 'set-cookie':
            sc += ' ' + str(v)
    for p in patterns:
        m = re.search(p, sc, re.IGNORECASE)
        if m:
            return m.group(0)[:80]
    return None


async def fingerprint_target(client: AdaptiveHTTPClient, base_url: str) -> Fingerprint:
    """
    Perform baseline + probe requests to fingerprint the target.
    """
    fp = Fingerprint()

    # 1. Baseline GET
    r = await client.get(base_url, follow_redirects=True)
    fp.baseline = r
    if r.error:
        return fp

    headers = r.headers or {}
    body = r.text or ''

    # 2. Detect WAF
    for waf_name, sig in WAF_SIGNATURES.items():
        hits = []
        h = _match_headers(headers, sig.get('headers', {}))
        c = _match_cookies(headers, sig.get('cookies', []))
        b = _match_body(body, sig.get('body', []))
        if h:
            hits.append(f'header: {h}')
        if c:
            hits.append(f'cookie: {c}')
        if b:
            hits.append(f'body: {b}')
        if hits:
            fp.waf = waf_name
            fp.waf_details = {'evidence': ' | '.join(hits)}
            break

    # 3. Detect tech
    for tech, sig in TECH_SIGNATURES.items():
        evidence = []
        if sig.get('headers'):
            h = _match_headers(headers, sig['headers'])
            if h:
                evidence.append(f'header: {h}')
        if sig.get('body'):
            b = _match_body(body, sig['body'])
            if b:
                evidence.append(f'body: {b}')
        if evidence:
            fp.techs.add(tech)
            fp.tech_details[tech] = ' | '.join(evidence)
            t = sig.get('type', '')
            if t == 'framework':
                fp.frameworks.add(tech)
            elif t == 'server':
                fp.server = tech
            elif tech in ('wordpress', 'drupal', 'joomla', 'magento', 'shopify', 'ghost', 'strapi'):
                fp.cms = tech
            elif tech in ('react', 'angular', 'vue', 'jquery', 'bootstrap'):
                fp.js_libs.add(tech)

    # 4. Cloud provider inference
    server_hdr = headers.get('Server', '') + ' ' + headers.get('server', '')
    if 'cloudfront' in server_hdr.lower() or 'X-Amz-Cf-Id' in headers:
        fp.cloud = 'aws'
    elif 'google' in server_hdr.lower() or 'X-GUploader-UploadID' in headers:
        fp.cloud = 'gcp'
    elif 'AzureCDN' in server_hdr or 'X-Azure-Ref' in headers:
        fp.cloud = 'azure'

    # 5. DBMS guess from framework
    if 'wordpress' in fp.techs or 'laravel' in fp.techs or 'php' in fp.techs:
        fp.probable_dbms.add('mysql')
    if 'django' in fp.techs or 'rails' in fp.techs:
        fp.probable_dbms.add('postgresql')
    if 'aspnet' in fp.techs:
        fp.probable_dbms.add('mssql')
    if 'nodejs_express' in fp.techs:
        fp.probable_dbms.add('mongodb')

    return fp


async def probe_waf_bypass(client: AdaptiveHTTPClient, base_url: str,
                           test_payload: str = "<script>alert(1)</script>") -> Dict[str, bool]:
    """
    Send known-malicious payload; if server responds normal but blocks known-bad,
    we have WAF. Returns which encodings pass.
    """
    tests = {
        'raw': test_payload,
        'url_encoded': '%3Cscript%3Ealert(1)%3C/script%3E',
        'double_url': '%253Cscript%253Ealert(1)%253C/script%253E',
        'unicode': '\u003cscript\u003ealert(1)\u003c/script\u003e',
    }
    results = {}
    for name, p in tests.items():
        r = await client.get(f'{base_url}?x={p}', follow_redirects=False)
        results[name] = r.status < 400 or r.status == 404
    return results
