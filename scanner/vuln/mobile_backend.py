"""
Mobile App Backend Scanner.

The goal is to find issues that impact mobile clients specifically:
  * Firebase Realtime DB / Firestore public read (JSON leak)
  * Google Maps / Firebase API keys leaked in web assets used by mobile
  * Insecure `.apk` / `.ipa` mirrors publicly hosted (leak binaries)
  * Mobile-only endpoints (/mobile/, /api/mobile/, /device/register) exposing
    device tokens or geolocation
  * CORS wide-open on mobile-specific APIs
  * Certificate transparency: exposed staging bundles
  * S3 buckets named `<host>-mobile`, `<host>-app`, `<host>-android`, `<host>-ios`
    (piggybacks on existing cloud_scanner if present, but adds mobile hints)
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

FIREBASE_DB_PATTERN = re.compile(
    r'https?://([a-z0-9\-]+)\.firebaseio\.com', re.IGNORECASE,
)
FIREBASE_PROJECT_PATTERN = re.compile(
    r'"projectId"\s*:\s*"([a-z0-9\-]+)"', re.IGNORECASE,
)
GOOGLE_API_KEY = re.compile(r'AIza[0-9A-Za-z\-_]{35}')
FIREBASE_CFG_KEYS = ('apiKey', 'projectId', 'authDomain', 'databaseURL', 'storageBucket')

MOBILE_PATHS = [
    '/mobile', '/mobile/', '/api/mobile', '/api/mobile/config',
    '/device/register', '/device/token', '/push/register',
    '/api/v1/device', '/api/app/config', '/api/mobile/version',
]

BINARY_PATHS = [
    '/app.apk', '/latest.apk', '/download/app.apk',
    '/releases/latest.apk', '/mobile.ipa', '/app.ipa',
    '/downloads/android.apk', '/apk/latest', '/ipa/latest',
]


def _origin(u: str) -> str:
    p = urlparse(u if u.startswith(('http://', 'https://')) else 'https://' + u)
    return f'{p.scheme}://{p.netloc}'


def _add(out: List[Dict], **kw):
    kw.setdefault('type', 'mobile_backend')
    kw.setdefault('confidence', 85)
    out.append(kw)


async def _check_firebase(client, base_url: str, seed_text: str, findings: List[Dict]):
    """
    Mine baseline HTML/JS for Firebase project IDs, then probe firebaseio.com
    Realtime DB for public read (`/.json`).
    """
    # Extract project ids / DB URLs from baseline
    dbs = set(m.group(1) for m in FIREBASE_DB_PATTERN.finditer(seed_text or ''))
    projs = set(m.group(1) for m in FIREBASE_PROJECT_PATTERN.finditer(seed_text or ''))
    dbs |= {p for p in projs if p}
    for pid in list(dbs)[:5]:
        db_url = f'https://{pid}.firebaseio.com/.json'
        r = await client.get(db_url)
        if r.status == 200 and r.text and r.text.strip() not in ('null', ''):
            _add(
                findings,
                subtype='firebase_public_read',
                severity='critical',
                cvss=9.1,
                url=db_url,
                evidence=(r.text or '')[:400],
                description=f'Firebase Realtime Database `{pid}` allows public reads. '
                            f'Any client can pull the entire tree over HTTPS with no auth.',
                remediation='Change Firebase rules to `{"rules":{".read":"auth != null",'
                            '".write":"auth != null"}}` or role-based rules per node.',
                confidence=98,
            )


async def _check_google_api_keys(client, base_url: str, seed_text: str, findings: List[Dict]):
    keys = list(set(GOOGLE_API_KEY.findall(seed_text or '')))[:5]
    for k in keys:
        # Non-destructive verification: hit a known-restricted-key API endpoint.
        # Google's Geocoding API returns 400 with an explicit REQUEST_DENIED
        # message when a key is restricted, and 200/OK when it's not.
        vurl = f'https://maps.googleapis.com/maps/api/geocode/json?address=Ottawa&key={k}'
        r = await client.get(vurl)
        body = (r.text or '')[:2000]
        if r.status == 200 and '"status" : "OK"' in body:
            _add(
                findings,
                subtype='google_api_key_unrestricted',
                severity='high',
                cvss=7.5,
                url=base_url,
                evidence=f'key={k[:12]}... geocode=OK',
                description=('A Google API key is embedded in the mobile client / web assets '
                             'and has no HTTP referer / API restriction — anyone can burn '
                             'the project quota or bill the account.'),
                remediation='In Google Cloud Console → APIs & Services → Credentials, restrict '
                            'the key to specific APIs and to app bundle IDs / referrers.',
                confidence=95,
            )
        elif r.status == 400 and 'REQUEST_DENIED' in body:
            # Restricted — informational only
            pass


async def _check_mobile_endpoints(client, base_url: str, findings: List[Dict]):
    origin = _origin(base_url)
    for path in MOBILE_PATHS:
        url = origin + path
        r = await client.get(url)
        if r.status != 200:
            continue
        body = (r.text or '')[:6000]
        lower = body.lower()
        if any(k in lower for k in ('device_token', 'fcm_token', 'push_token', 'apnsToken', 'device_id')):
            _add(
                findings,
                subtype='mobile_device_registry_leak',
                severity='high',
                cvss=7.5,
                url=url,
                evidence=body[:300],
                description='Mobile device-registration endpoint returns tokens (FCM/APNs/device) '
                            'that can be replayed to send unauthorized push notifications.',
                remediation='Require an authenticated session token to read device registries.',
                confidence=85,
            )
        elif len(body) > 100 and any(k in lower for k in ('"version"', '"apiurl"', '"apikey"', '"config"')):
            _add(
                findings,
                subtype='mobile_config_exposed',
                severity='low',
                cvss=3.7,
                url=url,
                evidence=body[:300],
                description='Public mobile config endpoint returns internal API URLs / feature '
                            'flags without auth. Useful for attackers mapping the backend.',
                remediation='Split public config (branding, feature flags) from private config '
                            '(URLs, keys). Serve private config over an authenticated channel.',
                confidence=75,
            )


async def _check_binary_mirrors(client, base_url: str, findings: List[Dict]):
    origin = _origin(base_url)
    for path in BINARY_PATHS:
        url = origin + path
        r = await client.head(url)
        if r.status == 200:
            ct = r.headers.get('content-type', '')
            cl = r.headers.get('content-length', '0')
            _add(
                findings,
                subtype='mobile_binary_public',
                severity='medium',
                cvss=5.3,
                url=url,
                evidence=f'HEAD 200 · content-type={ct} · size={cl}',
                description='Mobile binary (.apk / .ipa) is publicly downloadable. Attackers '
                            'can reverse it to extract API keys, endpoints, and pinning bypasses.',
                remediation='Ship mobile binaries through app stores only or a signed CDN with '
                            'auth. Never leave `.apk` / `.ipa` on the public webroot.',
                confidence=85,
            )


async def scan_mobile_backend(client, base_url: str, baseline_text: str = '',
                              log_cb: Optional[callable] = None) -> List[Dict]:
    findings: List[Dict] = []
    try:
        await _check_firebase(client, base_url, baseline_text or '', findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] firebase check failed: {e}')
    try:
        await _check_google_api_keys(client, base_url, baseline_text or '', findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] google key check failed: {e}')
    try:
        await _check_mobile_endpoints(client, base_url, findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] mobile_endpoints check failed: {e}')
    try:
        await _check_binary_mirrors(client, base_url, findings)
    except Exception as e:
        if log_cb:
            log_cb(f'[!] binary_mirrors check failed: {e}')
    return findings
