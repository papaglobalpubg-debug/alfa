"""Batch 6.1 tests: burp.zip download, history-diff endpoint, batch6-info regression."""
import io
import os
import time
import zipfile

import pytest
import requests

BASE_URL = os.environ['REACT_APP_BACKEND_URL'].rstrip('/')
API = f"{BASE_URL}/api"


@pytest.fixture(scope='module')
def client():
    s = requests.Session()
    s.headers.update({'Content-Type': 'application/json'})
    return s


@pytest.fixture(scope='module')
def completed_scan(client):
    """Reuse a completed scan on example.com if available, else create one."""
    # Try reuse
    try:
        rr = client.get(f"{API}/vuln/scans", params={'limit': 20}, timeout=15)
        if rr.status_code == 200:
            data = rr.json()
            scans = data.get('scans') if isinstance(data, dict) else data
            for s in (scans or []):
                if s.get('target') == 'https://example.com' and s.get('status') == 'completed':
                    return s.get('id')
    except Exception:
        pass
    # Otherwise create
    r = client.post(f"{API}/vuln/scans", json={
        'target': 'https://example.com',
        'depth': 'shallow',
    }, timeout=30)
    if r.status_code == 429:
        pytest.skip('rate-limited — restart backend to reset bucket')
    if r.status_code == 502:
        pytest.skip('upstream 502 while creating scan')
    assert r.status_code in (200, 201), r.text
    body = r.json()
    scan_id = body.get('scan_id') or body.get('id')
    assert scan_id, body
    # poll up to 90s
    deadline = time.time() + 120
    while time.time() < deadline:
        rr = client.get(f"{API}/vuln/scans/{scan_id}")
        if rr.status_code == 200 and rr.json().get('status') in ('completed', 'failed'):
            break
        time.sleep(3)
    return scan_id


# --- batch6-info regression ---
def test_batch6_info_still_770(client):
    r = client.get(f"{API}/vuln/batch6-info")
    assert r.status_code == 200
    data = r.json()
    assert data['version'] == '7.7.0'
    assert data['features']['crawler_v2'] is True
    assert data['features']['wordlist_encyclopedia'] is True


# --- history-diff ---
def test_history_diff_empty_target_ok(client):
    """Even a target with 0 hits must return structured JSON."""
    r = client.get(f"{API}/vuln/history-diff", params={'target': 'https://never-scanned-xyz.invalid'})
    assert r.status_code == 200
    data = r.json()
    assert data['target'] == 'https://never-scanned-xyz.invalid'
    assert 'points' in data and isinstance(data['points'], list)
    assert data['count'] == len(data['points'])


def test_history_diff_after_scan(client, completed_scan):
    r = client.get(f"{API}/vuln/history-diff", params={'target': 'https://example.com'})
    assert r.status_code == 200
    data = r.json()
    assert data['count'] >= 1
    p0 = data['points'][0]
    for k in ('scan_id', 'started_at', 'critical', 'high', 'medium', 'low', 'total'):
        assert k in p0


# --- burp.zip ---
def test_burp_zip_download(client, completed_scan):
    r = client.get(f"{API}/vuln/scans/{completed_scan}/burp.zip")
    assert r.status_code == 200, r.text
    assert r.headers.get('content-type') == 'application/zip'
    assert r.headers.get('content-disposition', '').startswith('attachment')

    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert 'README.md' in names
    # Even zero-findings scan should still contain README (no repeater/intruder is allowed)
    has_repeater = any(n.startswith('repeater/') for n in names)
    has_intruder = any(n.startswith('intruder/') for n in names)
    # If there were findings, both should exist
    fr = client.get(f"{API}/vuln/scans/{completed_scan}/findings", params={'limit': 5})
    if fr.status_code == 200 and fr.json().get('findings'):
        assert has_repeater, f'expected repeater/ files, got: {names}'
        assert has_intruder, f'expected intruder/ files, got: {names}'


def test_burp_zip_404_missing(client):
    r = client.get(f"{API}/vuln/scans/does-not-exist-xyz/burp.zip")
    assert r.status_code in (403, 404)


# --- Batch 6 endpoints still reachable (light regression) ---
def test_mutate_still_works(client):
    r = client.post(f"{API}/vuln/mutate", json={
        'payload': '<script>alert(1)</script>',
        'waf': 'cloudflare',
    })
    assert r.status_code == 200
    d = r.json()
    assert len(d.get('mutations', [])) >= 10
    assert len(d.get('waf_bypasses', [])) >= 3


def test_semantic_diff_still_works(client):
    r = client.post(f"{API}/vuln/semantic-diff", json={
        'a': 'hello world foo',
        'b': 'hello bar baz',
    })
    assert r.status_code == 200
    assert 'similarity' in r.json()
