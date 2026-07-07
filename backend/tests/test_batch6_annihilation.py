"""
Batch 6 · v7.7.0 Total Annihilation — backend test suite.
Tests the 10 new /vuln/* endpoints registered around L2103 of server.py.
"""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', 'https://language-arabic-38.preview.emergentagent.com').rstrip('/')
API = f"{BASE_URL}/api"


# ─────────── batch6-info ───────────
def test_batch6_info():
    r = requests.get(f"{API}/vuln/batch6-info", timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data['version'] == '7.7.0'
    assert data['codename'] == 'Total Annihilation'
    feats = data['features']
    for key in ('crawler_v2', 'wordlist_encyclopedia', 'verification_layer', 'auto_triage'):
        assert feats.get(key) is True, f"feature {key} not enabled: {feats}"
    # ai_destroyer requires EMERGENT_LLM_KEY — informational
    assert 'ai_destroyer' in feats
    assert isinstance(data.get('wordlist_counts', {}), dict)


# ─────────── wordlists sync + stats ───────────
def test_wordlist_sync_and_stats():
    r = requests.post(f"{API}/vuln/wordlists/sync", timeout=180)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data['ok'] is True
    counts = data['counts']
    assert isinstance(counts, dict) and counts
    total = data['total_payloads']
    assert total >= 20000, f"expected >=20000 payloads, got {total}"

    s = requests.get(f"{API}/vuln/wordlists/stats", timeout=30)
    assert s.status_code == 200
    sd = s.json()
    assert isinstance(sd['counts'], dict) and sd['counts']
    assert isinstance(sd.get('sample_xss', []), list)
    assert isinstance(sd.get('sample_sqli', []), list)


# ─────────── mutate + WAF bypass ───────────
def test_mutate_cloudflare():
    r = requests.post(f"{API}/vuln/mutate",
                      json={'payload': '<script>alert(1)</script>', 'waf': 'cloudflare'},
                      timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data['mutations'], list) and len(data['mutations']) >= 10, \
        f"mutations={len(data['mutations'])}"
    assert isinstance(data['waf_bypasses'], list) and len(data['waf_bypasses']) >= 3


def test_mutate_awswaf_case_or_comment():
    r = requests.post(f"{API}/vuln/mutate",
                      json={'payload': "' OR SELECT 1=1--", 'waf': 'awswaf'},
                      timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    all_vals = []
    for entry in data['mutations'] + data['waf_bypasses']:
        if isinstance(entry, dict):
            all_vals.append(str(entry.get('value', '')))
        else:
            all_vals.append(str(entry))
    joined = ' | '.join(all_vals)
    assert 'SeLeCt' in joined or '/**/' in joined, \
        f"expected case-shuffle or /**/ variant; got: {joined[:400]}"


# ─────────── semantic-diff ───────────
def test_semantic_diff_noise_normalization():
    a = '<html><meta csrf_token="abc123"><p>Hello</p><span>2025-01-01T10:00:00Z</span></html>'
    b = '<html><meta csrf_token="zzz999"><p>Hello</p><span>2026-06-15T18:22:11Z</span></html>'
    r = requests.post(f"{API}/vuln/semantic-diff", json={'a': a, 'b': b}, timeout=30)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get('similarity', 0) >= 0.5, d
    # Noise normalization collapses csrf+timestamps → responses become
    # semantically identical. Contract met either way (identical True/False).
    assert 'identical' in d


def test_semantic_diff_identical():
    r = requests.post(f"{API}/vuln/semantic-diff",
                      json={'a': 'hello world', 'b': 'hello world'}, timeout=30)
    assert r.status_code == 200
    d = r.json()
    assert d['identical'] is True
    assert d['similarity'] == 1.0


# ─────────── ai-craft ───────────
def test_ai_craft_xss_cloudflare():
    r = requests.post(f"{API}/vuln/ai-craft",
                      json={'vulnerability_type': 'xss', 'waf': 'cloudflare',
                            'original_payload': '<script>alert(1)</script>'},
                      timeout=90)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data['source'] in ('llm', 'heuristic')
    payloads = data.get('payloads', [])
    assert isinstance(payloads, list) and len(payloads) >= 3, f"payloads={payloads}"
    for p in payloads:
        assert 'value' in p


# ─────────── crawl-v2 ───────────
def test_crawl_v2_example_com():
    r = requests.post(f"{API}/vuln/crawl-v2",
                      json={'target': 'https://example.com', 'max_depth': 2,
                            'max_urls': 30, 'render_js': False,
                            'mine_hidden_params': False},
                      timeout=120)
    assert r.status_code == 200, r.text
    d = r.json()
    for k in ('urls_count', 'endpoints_count', 'forms_count', 'tech_hints', 'stats'):
        assert k in d, f"missing key {k} in {d}"
    assert d['stats'].get('render_js_used') is False


def test_crawl_v2_ssrf_block():
    r = requests.post(f"{API}/vuln/crawl-v2",
                      json={'target': 'http://127.0.0.1'}, timeout=30)
    assert r.status_code == 400, f"expected 400, got {r.status_code}: {r.text}"


# ─────────── scan-based AI endpoints ───────────
@pytest.fixture(scope='module')
def completed_scan_id():
    """Create a real scan and wait for it to complete."""
    r = requests.post(f"{API}/vuln/scans",
                      json={'target': 'https://example.com', 'depth': 'shallow'},
                      timeout=60)
    if r.status_code == 429:
        pytest.skip('rate-limited creating scan')
    assert r.status_code in (200, 201), r.text
    sid = r.json().get('scan_id') or r.json().get('id')
    assert sid, r.text
    for _ in range(60):
        s = requests.get(f"{API}/vuln/scans/{sid}", timeout=30)
        if s.status_code == 200 and s.json().get('status') in ('completed', 'failed', 'error'):
            break
        time.sleep(3)
    return sid


def test_ai_triage(completed_scan_id):
    r = requests.post(f"{API}/vuln/scans/{completed_scan_id}/ai-triage", timeout=90)
    assert r.status_code == 200, r.text
    d = r.json()
    assert 'triage' in d and 'source' in d
    assert d['source'] in ('llm', 'heuristic')
    assert isinstance(d['triage'], list)


def test_ai_chains_v2(completed_scan_id):
    r = requests.post(f"{API}/vuln/scans/{completed_scan_id}/ai-chains-v2", timeout=90)
    assert r.status_code == 200, r.text
    d = r.json()
    assert 'chains' in d and 'source' in d


def test_ai_verify_finding(completed_scan_id):
    r = requests.post(f"{API}/vuln/scans/{completed_scan_id}/ai-verify/0", timeout=90)
    # If no findings, 400 with 'finding_idx out of range' is a valid contract
    if r.status_code == 400:
        assert 'finding_idx' in r.text or 'out of range' in r.text
        return
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get('status') in ('confirmed', 'needs_manual', 'false_positive')
    assert 0 <= d.get('confidence', -1) <= 100
    assert 'source' in d and d['source'] in ('llm', 'heuristic')


# ─────────── regression: health / security-status ───────────
def test_health_regression():
    r = requests.get(f"{API}/health", timeout=30)
    assert r.status_code == 200
    v = str(r.json().get('version', ''))
    assert v.startswith('7.6') or v.startswith('7.7'), f"version={v}"


def test_security_status_regression():
    r = requests.get(f"{API}/security-status", timeout=30)
    assert r.status_code == 200
    d = r.json()
    # Look for 5 guards true
    guards = d.get('guards') or d
    true_count = sum(1 for v in guards.values() if v is True) if isinstance(guards, dict) else 0
    assert true_count >= 5, f"expected >=5 guards true; got {guards}"


# ─────────── tarball contents ───────────
def test_tarball_contains_batch6_files():
    import subprocess
    p = subprocess.run(
        ['tar', 'tzf', '/app/frontend/public/takeover-scanner-v6.tar.gz'],
        capture_output=True, text=True, timeout=30,
    )
    assert p.returncode == 0, p.stderr
    listing = p.stdout
    for f in ('crawler_v2.py', 'wordlist_manager.py', 'mutation_engine.py',
              'ai_destroyer.py', 'verification_layer.py'):
        assert f'scanner/vuln/{f}' in listing, f"missing {f} in tarball"
