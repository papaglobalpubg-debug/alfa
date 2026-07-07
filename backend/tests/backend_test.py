"""Backend API tests for Subdomain Takeover Scanner v5 Dashboard."""
import os
import time
import pytest
import requests

BASE = os.environ['REACT_APP_BACKEND_URL'].rstrip('/') if os.environ.get('REACT_APP_BACKEND_URL') else 'https://language-arabic-38.preview.emergentagent.com'
API = f'{BASE}/api'


@pytest.fixture(scope='module')
def s():
    return requests.Session()


# --- Root & meta ---
def test_root(s):
    r = s.get(f'{API}/')
    assert r.status_code == 200
    d = r.json()
    assert d['app'] == 'Subdomain Takeover Scanner'
    assert d['version'] == '5.0.0'
    assert d['services'] >= 76


def test_stats(s):
    r = s.get(f'{API}/stats')
    assert r.status_code == 200
    d = r.json()
    for k in ['total_scans', 'active_scans', 'total_verified_claimable',
              'total_claimable', 'total_subs_analyzed', 'available_services', 'recent_scans']:
        assert k in d
    assert isinstance(d['recent_scans'], list)


def test_services(s):
    r = s.get(f'{API}/services')
    assert r.status_code == 200
    d = r.json()
    assert d['count'] >= 76
    sv = d['services'][0]
    for k in ['name', 'priority', 'claimable', 'cnames', 'has_verifier']:
        assert k in sv


def test_sources(s):
    r = s.get(f'{API}/sources')
    assert r.status_code == 200
    d = r.json()
    assert len(d['free']) >= 17
    assert len(d['with_api_key']) == 6
    assert len(d['external_tool']) == 3


# --- Settings ---
def test_settings_get_and_update(s):
    r = s.put(f'{API}/settings', json={
        'api_keys': {'securitytrails': 'TEST_abcd1234efgh5678'},
        'webhooks': {'slack': 'https://hooks.slack.test/abc'},
        'telegram': {'token': 'TEST_tgtoken', 'chat_id': '123'},
    })
    assert r.status_code == 200
    r2 = s.get(f'{API}/settings')
    assert r2.status_code == 200
    d = r2.json()
    assert 'securitytrails' in d['api_keys_masked']
    assert d['api_keys_masked']['securitytrails'].startswith('****')
    assert d['webhooks'].get('slack')
    assert d['telegram']['token_set'] is True
    assert d['telegram']['chat_id'] == '123'


# --- Monitors CRUD ---
def test_monitors_crud(s):
    r = s.post(f'{API}/monitors', json={'domain': 'TEST_monitor.example.com', 'interval_hours': 12, 'enabled': True})
    assert r.status_code == 200
    mid = r.json()['id']

    r = s.get(f'{API}/monitors')
    assert r.status_code == 200
    assert any(m['id'] == mid for m in r.json()['monitors'])

    r = s.put(f'{API}/monitors/{mid}', json={'enabled': False})
    assert r.status_code == 200

    r = s.delete(f'{API}/monitors/{mid}')
    assert r.status_code == 200
    assert r.json()['deleted'] == 1


# --- Scan lifecycle ---
@pytest.fixture(scope='module')
def scan_id(s):
    r = s.post(f'{API}/scans', json={
        'domain': 'example.com',
        'sources': ['bruteforce', 'tls_san'],
        'threads': 30, 'timeout': 5, 'verify': False,
    })
    assert r.status_code == 200
    sid = r.json()['scan_id']
    assert sid
    return sid


def test_scan_progress_and_completion(s, scan_id):
    # Poll up to 90s
    completed = False
    for _ in range(45):
        r = s.get(f'{API}/scans/{scan_id}')
        assert r.status_code == 200
        st = r.json().get('status')
        if st in ('discovering', 'analyzing', 'verifying'):
            pass  # observed running state
        if st == 'completed':
            completed = True
            break
        if st == 'failed':
            pytest.fail(f"Scan failed: {r.json().get('error')}")
        time.sleep(2)
    assert completed, 'Scan did not complete in time'
    # (saw_running best-effort; may transition too fast)
    doc = s.get(f'{API}/scans/{scan_id}').json()
    summary = doc.get('summary', {})
    assert summary.get('total_analyzed', 0) > 0


def test_scan_results_and_filters(s, scan_id):
    r = s.get(f'{API}/scans/{scan_id}/results')
    assert r.status_code == 200
    d = r.json()
    assert 'results' in d
    # Filter by classification
    r2 = s.get(f'{API}/scans/{scan_id}/results', params={'classification': 'NXDOMAIN'})
    assert r2.status_code == 200
    # Search filter
    r3 = s.get(f'{API}/scans/{scan_id}/results', params={'search': 'www'})
    assert r3.status_code == 200


def test_scan_logs(s, scan_id):
    r = s.get(f'{API}/scans/{scan_id}/logs')
    assert r.status_code == 200
    logs = r.json()['logs']
    assert isinstance(logs, list)
    assert len(logs) > 0


@pytest.mark.parametrize('fmt,ctype', [
    ('json', 'application/json'),
    ('csv', 'text/csv'),
    ('html', 'text/html'),
    ('txt', 'text/plain'),
])
def test_exports(s, scan_id, fmt, ctype):
    r = s.get(f'{API}/scans/{scan_id}/export/{fmt}')
    assert r.status_code == 200, f'export {fmt} failed: {r.text[:200]}'
    assert ctype in r.headers.get('content-type', '')
    assert len(r.content) > 0


def test_scans_list_filters(s, scan_id):
    r = s.get(f'{API}/scans', params={'domain': 'example.com'})
    assert r.status_code == 200
    d = r.json()
    assert any(sc['id'] == scan_id for sc in d['scans'])
    r2 = s.get(f'{API}/scans', params={'status': 'completed'})
    assert r2.status_code == 200


def test_scan_delete(s):
    # Create a new scan to delete (don't kill fixture)
    r = s.post(f'{API}/scans', json={
        'domain': 'example.com', 'sources': ['bruteforce'],
        'threads': 20, 'timeout': 5, 'verify': False,
    })
    sid = r.json()['scan_id']
    time.sleep(2)
    dr = s.delete(f'{API}/scans/{sid}')
    assert dr.status_code == 200
    # GET should return 404
    g = s.get(f'{API}/scans/{sid}')
    assert g.status_code == 404
