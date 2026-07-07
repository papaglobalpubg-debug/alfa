"""Batch 4: AI False-Positive Predictor endpoint tests."""
import os
import time
import requests
import pytest

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL').rstrip('/')
API = f'{BASE_URL}/api'


@pytest.fixture(scope='module')
def scan_id():
    """Create a small scan on example.com and wait for completion."""
    payload = {
        'target': 'example.com',
        'depth': 'shallow',
        'modules': ['fingerprint', 'csp', 'cors', 'directory_listing'],
    }
    r = requests.post(f'{API}/vuln/scans', json=payload, timeout=15)
    assert r.status_code in (200, 201), f'create scan failed: {r.status_code} {r.text[:200]}'
    sid = r.json().get('id') or r.json().get('scan_id')
    assert sid, f'no scan id in response: {r.json()}'

    # Wait up to 60s
    for _ in range(60):
        s = requests.get(f'{API}/vuln/scans/{sid}', timeout=10)
        if s.status_code == 200 and s.json().get('status') in ('completed', 'failed', 'stopped'):
            break
        time.sleep(1)
    return sid


class TestFPPredictor:
    def test_heuristic_only(self, scan_id):
        r = requests.post(f'{API}/vuln/scans/{scan_id}/fp-predict', timeout=30)
        assert r.status_code == 200, r.text[:300]
        data = r.json()
        assert data['scan_id'] == scan_id
        assert data['used_llm'] is False
        assert 'count' in data
        assert 'scores' in data
        assert 'buckets' in data
        assert set(data['buckets'].keys()) == {'likely_real', 'review', 'likely_fp'}
        for s in data['scores']:
            assert 0.0 <= s['fp_score'] <= 1.0
            assert s['fp_layer'] == 'heuristic'
            assert 'fp_reason' in s
            assert s['bucket'] in ('likely_real', 'review', 'likely_fp')

    def test_with_llm(self, scan_id):
        r = requests.post(f'{API}/vuln/scans/{scan_id}/fp-predict?use_llm=true', timeout=120)
        assert r.status_code == 200, r.text[:300]
        data = r.json()
        assert data['used_llm'] is True
        # Graceful degradation - always returns 200 with scores
        assert 'scores' in data
        assert 'buckets' in data

    def test_not_found(self):
        r = requests.post(f'{API}/vuln/scans/nonexistent-scan-id/fp-predict', timeout=10)
        assert r.status_code == 404
