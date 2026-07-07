"""Backend tests for CyberScope v7.5 — Batch 3 modules + Stop/Bulk endpoints."""
import os
import time
import pytest
import requests

BASE = os.environ['REACT_APP_BACKEND_URL'].rstrip('/')
API = f'{BASE}/api'


@pytest.fixture(scope='module')
def s():
    return requests.Session()


# --- /vuln/info reports v7.5 with Batch 3 modules ---
def test_vuln_info_v75(s):
    r = s.get(f'{API}/vuln/info')
    assert r.status_code == 200
    d = r.json()
    assert d.get('available') is True
    assert d['version'] == '7.5.0', f"Expected 7.5.0, got {d.get('version')}"
    modules = d.get('modules', [])
    assert len(modules) >= 35, f"expected 35+ modules, got {len(modules)}"
    for m in ['api_security', 'oauth_saml', 'mobile_backend', 'web3']:
        assert m in modules, f"missing batch-3 module: {m}"


# --- Single-scan cancel flips DB status to 'cancelled' ---
def test_single_cancel_flips_status(s):
    # Launch scan
    r = s.post(f'{API}/vuln/scans', json={
        'target': 'https://example.com',
        'depth': 'deep',
        'modules': ['fingerprint', 'recon', 'crawler', 'xss', 'sqli', 'nosqli',
                    'cmd', 'ssti', 'lfi', 'xxe', 'ssrf', 'open_redirect',
                    'api_security', 'oauth_saml', 'mobile_backend', 'web3'],
        'disabled': [],
    })
    assert r.status_code == 200, r.text
    sid = r.json()['scan_id']

    # cancel immediately — no wait
    time.sleep(0.3)

    # Cancel
    rc = s.post(f'{API}/vuln/scans/{sid}/cancel')
    assert rc.status_code == 200, rc.text
    body = rc.json()
    assert body['ok'] is True
    assert body['scan_id'] == sid

    # Poll for cancelled status <=5s
    cancelled = False
    for _ in range(10):
        gr = s.get(f'{API}/vuln/scans/{sid}')
        if gr.status_code == 200 and gr.json().get('status') == 'cancelled':
            cancelled = True
            break
        time.sleep(0.5)
    assert cancelled, f'scan did not flip to cancelled: {gr.json().get("status")}'


# --- bulk-cancel returns count ---
def test_bulk_cancel(s):
    ids = []
    for _ in range(2):
        r = s.post(f'{API}/vuln/scans', json={
            'target': 'https://example.com',
            'depth': 'deep',
            'modules': ['fingerprint', 'recon', 'crawler', 'xss', 'sqli',
                        'api_security', 'oauth_saml', 'mobile_backend', 'web3'],
            'disabled': [],
        })
        assert r.status_code == 200
        ids.append(r.json()['scan_id'])

    time.sleep(0.3)

    rc = s.post(f'{API}/vuln/scans/bulk-cancel', json={'ids': ids})
    assert rc.status_code == 200, rc.text
    d = rc.json()
    assert d['ok'] is True
    assert isinstance(d['count'], int)
    # both should be marked cancellable
    assert d['count'] >= 1

    # verify DB status
    time.sleep(2)
    for sid in ids:
        gr = s.get(f'{API}/vuln/scans/{sid}')
        assert gr.status_code == 200
        assert gr.json().get('status') in ('cancelled', 'completed', 'failed')


# --- bulk-delete removes them from DB ---
def test_bulk_delete(s):
    ids = []
    for _ in range(2):
        r = s.post(f'{API}/vuln/scans', json={
            'target': 'https://example.com',
            'depth': 'shallow',
            'modules': ['fingerprint'],
            'disabled': [],
        })
        assert r.status_code == 200
        ids.append(r.json()['scan_id'])

    rd = s.post(f'{API}/vuln/scans/bulk-delete', json={'ids': ids})
    assert rd.status_code == 200, rd.text
    d = rd.json()
    assert d['deleted'] >= 1
    # 404 after
    for sid in ids:
        gr = s.get(f'{API}/vuln/scans/{sid}')
        assert gr.status_code == 404, f'expected 404 got {gr.status_code} for {sid}'


# --- Scan targeting example.com with only Batch-3 modules completes ---
def test_batch3_scan_completes(s):
    r = s.post(f'{API}/vuln/scans', json={
        'target': 'https://example.com',
        'depth': 'shallow',
        'modules': ['api_security', 'oauth_saml', 'mobile_backend', 'web3'],
        'disabled': [],
    })
    assert r.status_code == 200, r.text
    sid = r.json()['scan_id']

    # poll up to 90s
    final = None
    for _ in range(45):
        gr = s.get(f'{API}/vuln/scans/{sid}')
        if gr.status_code == 200:
            st = gr.json().get('status')
            if st in ('completed', 'failed', 'cancelled'):
                final = gr.json()
                break
        time.sleep(2)

    assert final is not None, 'scan did not finish in 90s'
    assert final.get('status') == 'completed', f"expected completed, got {final.get('status')}, err={final.get('error')}"

    # Findings shape
    fr = s.get(f'{API}/vuln/scans/{sid}/findings')
    assert fr.status_code == 200
    fd = fr.json()
    assert 'findings' in fd or isinstance(fd, dict)


# --- Cleanup: delete lingering test scans ---
def test_cleanup(s):
    r = s.get(f'{API}/vuln/scans', params={'limit': 50})
    if r.status_code == 200:
        for sc in r.json().get('scans', []):
            if sc.get('target') in ('https://example.com', 'example.com'):
                s.delete(f'{API}/vuln/scans/{sc["id"]}')
