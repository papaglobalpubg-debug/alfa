"""Backend tests for Phase 1+2+3 features: playbooks, bulk scan, cancel, graph, recon, bug bounty report."""
import os
import time
import pytest
import requests

BASE = os.environ['REACT_APP_BACKEND_URL'].rstrip('/')
API = f'{BASE}/api'


@pytest.fixture(scope='module')
def s():
    return requests.Session()


# --- Root: services=183 ---
def test_root_services_183(s):
    r = s.get(f'{API}/')
    assert r.status_code == 200
    d = r.json()
    assert d['services'] == 183, f"expected 183, got {d.get('services')}"


def test_services_183(s):
    r = s.get(f'{API}/services')
    assert r.status_code == 200
    d = r.json()
    assert d['count'] == 183, f"expected 183, got {d.get('count')}"
    assert len(d['services']) == 183


# --- Playbooks ---
def test_playbooks_list(s):
    r = s.get(f'{API}/playbooks')
    assert r.status_code == 200
    pbs = r.json()['playbooks']
    assert len(pbs) == 49, f"expected 49 playbooks, got {len(pbs)}"
    keys = {'key', 'service_name', 'severity', 'cvss_base'}
    for pb in pbs:
        assert keys.issubset(pb.keys()), f"missing keys in {pb}"


def test_playbook_aws_s3(s):
    r = s.get(f'{API}/playbooks/aws-s3')
    assert r.status_code == 200
    pb = r.json()
    assert pb['service_name'] == 'AWS S3'
    assert len(pb['exploitation_steps']) == 7
    assert len(pb['report_template']) > 1000  # ~1900 chars
    assert isinstance(pb['references'], list) and len(pb['references']) > 0
    assert isinstance(pb['poc_snippets'], dict) and len(pb['poc_snippets']) > 0
    assert pb['remediation']


def test_playbook_generic_fallback(s):
    r = s.get(f'{API}/playbooks/generic')
    assert r.status_code == 200
    pb = r.json()
    assert 'exploitation_steps' in pb
    assert 'report_template' in pb


# --- Bulk scan ---
def test_bulk_scan_valid(s):
    r = s.post(f'{API}/scans/bulk', json={
        'domains': ['example.com', 'example.org'],
        'sources': ['bruteforce', 'tls_san'],
        'threads': 30, 'timeout': 5, 'verify': False,
    })
    assert r.status_code == 200, r.text
    d = r.json()
    assert d['count'] == 2
    assert len(d['scan_ids']) == 2


def test_bulk_scan_empty(s):
    r = s.post(f'{API}/scans/bulk', json={'domains': [], 'sources': ['bruteforce']})
    assert r.status_code == 400


def test_bulk_scan_too_many(s):
    r = s.post(f'{API}/scans/bulk', json={
        'domains': [f'ex{i}.com' for i in range(101)],
        'sources': ['bruteforce'],
    })
    assert r.status_code == 400


# --- Cancel scan ---
def test_cancel_nonexistent(s):
    r = s.post(f'{API}/scans/nonexistent-id/cancel')
    assert r.status_code == 404


def test_cancel_running_scan(s):
    # Kick off a scan with many sources so it runs long enough
    r = s.post(f'{API}/scans', json={
        'domain': 'example.com',
        'sources': ['bruteforce', 'tls_san', 'crtsh', 'hackertarget', 'threatcrowd',
                    'anubis', 'alienvault', 'urlscan', 'wayback', 'commoncrawl'],
        'threads': 5, 'timeout': 10, 'verify': True,
    })
    assert r.status_code == 200
    sid = r.json()['scan_id']
    # Give it a moment to start
    time.sleep(1.5)
    c = s.post(f'{API}/scans/{sid}/cancel')
    assert c.status_code == 200, c.text
    # Poll for cancelled status. Cancel is honored between phases, so allow up to 90s.
    cancelled = False
    st = None
    for _ in range(90):
        st = s.get(f'{API}/scans/{sid}').json().get('status')
        if st == 'cancelled':
            cancelled = True
            break
        if st in ('completed', 'failed'):
            break
        time.sleep(1)
    assert cancelled, f"final status={st} (expected cancelled)"


# --- Graph ---
@pytest.fixture(scope='module')
def completed_scan_id(s):
    r = s.post(f'{API}/scans', json={
        'domain': 'example.com',
        'sources': ['bruteforce', 'tls_san'],
        'threads': 30, 'timeout': 5, 'verify': False,
    })
    sid = r.json()['scan_id']
    for _ in range(60):
        st = s.get(f'{API}/scans/{sid}').json().get('status')
        if st == 'completed':
            return sid
        if st == 'failed':
            pytest.fail('scan failed')
        time.sleep(2)
    pytest.fail('scan did not complete in time')


def test_graph_endpoint(s, completed_scan_id):
    r = s.get(f'{API}/scans/{completed_scan_id}/graph')
    assert r.status_code == 200
    d = r.json()
    for k in ('node_count', 'edge_count', 'nodes', 'edges'):
        assert k in d
    assert isinstance(d['nodes'], list)
    assert isinstance(d['edges'], list)


def test_bug_bounty_report_404_for_missing(s, completed_scan_id):
    r = s.get(f'{API}/scans/{completed_scan_id}/report/bug-bounty/nonexistent.example.com')
    assert r.status_code == 404


# --- Recon ---
def test_recon_ports(s):
    r = s.post(f'{API}/recon', json={'host': 'example.com', 'features': ['ports']}, timeout=90)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d['host'] == 'example.com'
    assert 'ports' in d
    assert isinstance(d['ports'], list)


# --- Regression: existing endpoints ---
def test_sources_still_working(s):
    r = s.get(f'{API}/sources')
    assert r.status_code == 200
    assert len(r.json()['free']) >= 17


def test_stats_still_working(s):
    r = s.get(f'{API}/stats')
    assert r.status_code == 200
    assert 'total_scans' in r.json()


def test_monitors_still_working(s):
    r = s.get(f'{API}/monitors')
    assert r.status_code == 200
    assert 'monitors' in r.json()


def test_settings_still_working(s):
    r = s.get(f'{API}/settings')
    assert r.status_code == 200
