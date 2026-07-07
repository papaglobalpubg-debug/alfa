"""
Iteration 23 · v7.7.3 · Playwright browser install + heal_paths fix.
Verifies the deep crawler now launches headless Chromium via Playwright
instead of falling back to HTML-only mode.
"""
import os
import time
import re
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL').rstrip('/')
API = f'{BASE_URL}/api'


@pytest.fixture(scope='module')
def s():
    sess = requests.Session()
    sess.headers.update({'Content-Type': 'application/json'})
    return sess


# ─── 1. Health regression — startup heal fn must not crash boot ─────
def test_health_after_heal(s):
    r = s.get(f'{API}/health', timeout=15)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get('ok') is True
    assert j.get('version') == '7.7.2', j


# ─── 2. vuln/info regression — v7.7.2, 44+ modules ─────────────────
def test_vuln_info_modules(s):
    r = s.get(f'{API}/vuln/info', timeout=30)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j['version'] == '7.7.2', j
    mods = j['modules']
    assert len(mods) >= 44, f'expected 44+ modules, got {len(mods)}'
    for req in ['jwt_cracker', 'websocket', 'race_condition',
                'graphql_v2', 'cve_correlate', 'crawler_v2']:
        assert req in mods, f'missing {req}'


# ─── 3. Deep scan · Playwright MUST launch, no "unavailable" warn ──
@pytest.fixture(scope='module')
def deep_scan(s):
    body = {
        'target': 'https://example.com',
        'depth': 'deep',
        'modules': ['fingerprint', 'recon', 'crawler', 'directory_listing'],
        'concurrency': 8,
        'timeout': 8.0,
    }
    r = s.post(f'{API}/vuln/scans', json=body, timeout=90)
    assert r.status_code == 200, r.text
    sid = r.json().get('scan_id') or r.json().get('id')
    assert sid
    deadline = time.time() + 240  # 4-min budget
    last = None
    while time.time() < deadline:
        rr = s.get(f'{API}/vuln/scans/{sid}', timeout=30)
        if rr.status_code == 200:
            last = rr.json()
            if last.get('status') in ('completed', 'failed', 'cancelled'):
                break
        time.sleep(5)
    return sid, last


def test_deep_scan_completed(deep_scan):
    sid, last = deep_scan
    assert last is not None, 'scan never returned'
    assert last.get('status') == 'completed', (
        f"status={last.get('status')} last={str(last)[:500]}")


def test_deep_scan_no_playwright_warning(deep_scan):
    sid, last = deep_scan
    logs = last.get('logs') or []
    joined = '\n'.join(logs)
    # The FIX must eliminate any "Playwright unavailable" line
    assert 'Playwright unavailable' not in joined, (
        f'Playwright fallback triggered: {[ln for ln in logs if "Playwright" in ln]}'
    )


def test_deep_scan_has_deep_crawling_log(deep_scan):
    sid, last = deep_scan
    logs = last.get('logs') or []
    joined = '\n'.join(logs)
    # crawler_v2 emits "[*] Deep crawling https://example.com ..." when render_js=True
    assert 'Deep crawling' in joined, (
        f'no "Deep crawling" log line found; tail={joined[-600:]}'
    )


def test_deep_scan_urls_discovered(deep_scan):
    sid, last = deep_scan
    logs = last.get('logs') or []
    joined = '\n'.join(logs)
    # Crawler summary line: "[+] Crawler v2: N URLs, ..."
    m = re.search(r'Crawler v2: (\d+) URLs', joined)
    assert m, f'no crawler_v2 summary in logs; tail={joined[-500:]}'
    urls = int(m.group(1))
    assert urls > 0, 'crawler found 0 URLs for example.com'


# ─── 4. Regression: JWT crack still works ───────────────────────────
DEMO_JWT = (
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
    'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.'
    'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
)


def test_jwt_crack_demo(s):
    r = s.post(f'{API}/vuln/jwt/crack',
               json={'token': DEMO_JWT, 'max_secrets': 100000},
               timeout=180)
    assert r.status_code == 200, r.text
    hs = ((r.json().get('attacks') or {}).get('hs_crack')) or {}
    assert hs.get('success') is True, f'HS crack failed: {hs}'
    assert hs.get('secret') == 'your-256-bit-secret'


# ─── 5. Regression: dashboard-stats ─────────────────────────────────
def test_dashboard_stats(s):
    r = s.get(f'{API}/vuln/dashboard-stats', timeout=30)
    assert r.status_code == 200, r.text
    j = r.json()
    for k in ['total_scans', 'running_count', 'severities_last30',
             'by_type_last30', 'monitors_count', 'recent_scans']:
        assert k in j, f'missing {k}'


# ─── 6. Regression: monitors-v2 list ────────────────────────────────
def test_monitors_v2_list(s):
    r = s.get(f'{API}/vuln/monitors-v2', timeout=30)
    assert r.status_code == 200, r.text
    j = r.json()
    assert 'monitors' in j and isinstance(j['monitors'], list)


# ─── 7. Code review: verify crawler_v2 log truncation is single-line
def test_playwright_error_truncation_code():
    """Static check: _init_browser must truncate the error message."""
    with open('/app/scanner/vuln/crawler_v2.py') as f:
        src = f.read()
    # The fix should split on newline and cap at 200 chars
    assert "split('\\n', 1)[0][:200]" in src, (
        'expected error truncation missing in _init_browser'
    )
    assert 'HTML-only mode' in src
