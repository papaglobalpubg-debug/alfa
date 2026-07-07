"""Backend regression tests for Weaponized Vuln Scanner v6."""
import asyncio
import os
import time

import pytest
import requests


BASE = os.environ.get('TEST_BACKEND', 'http://localhost:8001') + '/api'


def test_vuln_info():
    r = requests.get(f'{BASE}/vuln/info', timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert d['available'] is True
    assert d['payload_counts']['TOTAL'] > 500
    assert 'xss' in d['modules']
    assert 'sqli' in d['modules']
    assert 'ssrf' in d['modules']
    assert 'cve_templates' in d['modules']


def test_vuln_scan_lifecycle():
    """Create a shallow scan, poll for completion, verify findings shape."""
    r = requests.post(f'{BASE}/vuln/scans', json={
        'target': 'httpbin.org',
        'depth': 'shallow',
        'concurrency': 10,
        'timeout': 8,
        'modules': ['fingerprint', 'cors', 'infra_apis', 'cve_templates'],
    }, timeout=10)
    assert r.status_code == 200
    scan_id = r.json()['scan_id']

    # Poll
    for _ in range(60):
        r2 = requests.get(f'{BASE}/vuln/scans/{scan_id}', timeout=10)
        assert r2.status_code == 200
        status = r2.json().get('status')
        if status in ('completed', 'failed'):
            break
        time.sleep(2)
    else:
        pytest.fail(f'Scan {scan_id} did not complete within 2min')

    # Findings shape
    r3 = requests.get(f'{BASE}/vuln/scans/{scan_id}/findings', timeout=10)
    assert r3.status_code == 200
    body = r3.json()
    assert 'findings' in body
    assert 'ports' in body
    assert 'recon_summary' in body

    # Logs
    r4 = requests.get(f'{BASE}/vuln/scans/{scan_id}/logs', timeout=10)
    assert r4.status_code == 200
    logs = r4.json().get('logs', [])
    assert len(logs) > 0
    assert any('Fingerprinting' in ll or 'Starting' in ll for ll in logs)

    # Cleanup
    requests.delete(f'{BASE}/vuln/scans/{scan_id}', timeout=10)


def test_vuln_scan_list():
    r = requests.get(f'{BASE}/vuln/scans', timeout=10)
    assert r.status_code == 200
    d = r.json()
    assert 'scans' in d and 'total' in d


def test_orchestrator_import():
    """Sanity test that the scanner engine imports cleanly."""
    from scanner.vuln import PAYLOADS, VulnScanConfig, VulnScanner
    from scanner.vuln.payloads import count_payloads
    c = count_payloads()
    assert c['TOTAL'] > 500
    assert c['xss'] > 50
    assert c['sqli'] > 50


def test_payload_registry_completeness():
    from scanner.vuln.payloads import PAYLOADS
    assert len(PAYLOADS.cve) >= 40
    assert len(PAYLOADS.secrets) >= 40
    assert len(PAYLOADS.open_redirect) >= 20


def test_fingerprint_module():
    """Direct fingerprint test."""
    async def _run():
        from scanner.vuln.http_client import AdaptiveHTTPClient
        from scanner.vuln.fingerprint import fingerprint_target
        async with AdaptiveHTTPClient(concurrency=5, timeout=10) as client:
            fp = await fingerprint_target(client, 'https://httpbin.org')
            assert fp is not None
            return fp
    fp = asyncio.get_event_loop().run_until_complete(_run())
    assert isinstance(fp.techs, set)


if __name__ == '__main__':
    test_vuln_info()
    print('OK: /api/vuln/info')
    test_orchestrator_import()
    print('OK: orchestrator imports')
    test_payload_registry_completeness()
    print('OK: payload registry complete')
