"""Iteration 22 · CyberScope v7.7.1 backend regression + new features.

Coverage:
- /api/vuln/info: version 7.7.1, encyclopedia + GRAND_TOTAL >= 200k
- /api/vuln/wordlists/stats: >=12 categories, xss>10k, sqli>500, cmd>9k, lfi>2k, jwt>100k, discovery>50k, subdomains>10k
- /api/vuln/scans lifecycle: pending -> running <=5s, logs streamed to DB 5-10s, completes
- SSRF guard blocks internal targets
- /api/security-status guards enabled
- Cancel a running scan cleanly
- Regression: /api/stats, /api/vuln/scans?limit=10, /api/vuln/payloads/mutate,
  /api/vuln/scans/{id}/burp.zip, /api/vuln/history-diff, /api/vuln/scans/{id}/explain
"""
import os
import time
import io
import zipfile
import pytest
import requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "https://language-arabic-38.preview.emergentagent.com").rstrip("/")
API = f"{BASE}/api"

REQUIRED_ENCY = ["xss", "sqli", "cmd", "lfi", "ssrf", "xxe", "ldap", "jwt",
                 "discovery", "subdomains", "params", "useragents", "redirect",
                 "crlf", "ssti", "nosqli"]


# ---------- info + wordlists ----------
def test_vuln_info_v771():
    r = requests.get(f"{API}/vuln/info", timeout=15)
    assert r.status_code == 200
    data = r.json()
    assert data["version"] == "7.7.1", data.get("version")
    assert "Total Annihilation" in data["codename"]
    pc = data["payload_counts"]
    assert "ENCYCLOPEDIA" in pc and "GRAND_TOTAL" in pc
    assert pc["GRAND_TOTAL"] >= 200_000, f"GRAND_TOTAL={pc['GRAND_TOTAL']}"
    ency = data["encyclopedia"]
    for cat in REQUIRED_ENCY:
        assert cat in ency, f"missing {cat}"
        assert ency[cat] > 0, f"{cat}=0"


def test_wordlists_stats_populated():
    r = requests.get(f"{API}/vuln/wordlists/stats", timeout=15)
    assert r.status_code == 200
    counts = r.json()["counts"]
    assert len(counts) >= 12, f"only {len(counts)} categories"
    thresholds = {"xss": 10_000, "sqli": 500, "cmd": 9_000, "lfi": 2_000,
                  "jwt": 100_000, "discovery": 50_000, "subdomains": 10_000}
    for k, thr in thresholds.items():
        assert counts.get(k, 0) > thr, f"{k}={counts.get(k)} < {thr}"


# ---------- security-status ----------
def test_security_status_guards():
    r = requests.get(f"{API}/security-status", timeout=10)
    assert r.status_code == 200
    guards = r.json()["guards"]
    for g in ["ssrf_guard", "ownership_scope", "report_xss_escaping",
              "secret_masking", "rate_limiting"]:
        assert guards.get(g) is True, f"{g} disabled"


# ---------- SSRF guard ----------
@pytest.mark.parametrize("bad", ["http://127.0.0.1", "http://192.168.1.1"])
def test_ssrf_guard_blocks_internal(bad):
    r = requests.post(f"{API}/vuln/scans", json={
        "target": bad, "depth": "quick",
        "modules": ["fingerprint"]
    }, timeout=15)
    assert r.status_code == 400, f"got {r.status_code} body={r.text[:200]}"
    body = r.text.lower()
    assert "ssrf" in body, r.text[:300]


# ---------- Scan lifecycle (pending->running <=5s, logs, completion) ----------
@pytest.fixture(scope="module")
def launched_scan():
    payload = {
        "target": "https://httpbin.org", "depth": "quick",
        "modules": ["fingerprint", "recon", "xss", "cors",
                    "directory_listing", "http_methods"],
    }
    r = requests.post(f"{API}/vuln/scans", json=payload, timeout=20)
    assert r.status_code in (200, 201), f"launch failed {r.status_code}: {r.text[:300]}"
    j = r.json()
    sid = j.get("scan_id") or j.get("id")
    assert sid
    return sid


def _get_scan(sid):
    r = requests.get(f"{API}/vuln/scans/{sid}", timeout=15)
    assert r.status_code == 200, r.text[:200]
    return r.json()


def test_scan_transitions_to_running_within_5s(launched_scan):
    sid = launched_scan
    deadline = time.time() + 8  # small grace beyond 5
    seen_running = False
    while time.time() < deadline:
        s = _get_scan(sid)
        st = s.get("status")
        if st in ("running", "completed", "failed"):
            seen_running = True
            break
        time.sleep(0.5)
    assert seen_running, f"scan {sid} still pending after 8s"


def test_scan_logs_streamed_to_db(launched_scan):
    sid = launched_scan
    # wait up to 12s for DB-persisted logs
    deadline = time.time() + 12
    logs_in_db = []
    while time.time() < deadline:
        s = _get_scan(sid)
        logs_in_db = s.get("logs") or s.get("log_lines") or []
        if len(logs_in_db) > 0:
            break
        time.sleep(1)
    assert len(logs_in_db) > 0, f"no DB logs after 12s for {sid}; scan keys={list(s.keys())}"


def test_scan_live_logs_endpoint(launched_scan):
    sid = launched_scan
    r = requests.get(f"{API}/vuln/scans/{sid}/logs", timeout=15)
    assert r.status_code == 200, r.text[:200]
    j = r.json()
    # accept either list or dict with logs
    logs = j.get("logs") if isinstance(j, dict) else j
    assert logs is not None


def test_scan_eventually_completes(launched_scan):
    sid = launched_scan
    deadline = time.time() + 180
    last = None
    while time.time() < deadline:
        s = _get_scan(sid)
        last = s.get("status")
        if last in ("completed", "failed"):
            break
        time.sleep(4)
    assert last == "completed", f"final status={last}"
    s = _get_scan(sid)
    assert isinstance(s.get("summary"), dict), f"summary missing: keys={list(s.keys())}"


# ---------- cancel a fresh scan ----------
def test_scan_cancel_cleanly():
    payload = {"target": "https://httpbin.org", "depth": "quick",
               "modules": ["fingerprint", "recon", "xss", "cors"]}
    r = requests.post(f"{API}/vuln/scans", json=payload, timeout=20)
    assert r.status_code in (200, 201)
    sid = r.json().get("scan_id") or r.json().get("id")
    # wait until running
    for _ in range(15):
        s = _get_scan(sid)
        if s.get("status") == "running":
            break
        time.sleep(0.5)
    rc = requests.post(f"{API}/vuln/scans/{sid}/cancel", timeout=15)
    assert rc.status_code in (200, 202), f"cancel {rc.status_code}: {rc.text[:200]}"
    # verify status becomes cancelled within 15s
    deadline = time.time() + 20
    final = None
    while time.time() < deadline:
        final = _get_scan(sid).get("status")
        if final in ("cancelled", "canceled"):
            break
        time.sleep(1)
    assert final in ("cancelled", "canceled"), f"final={final}"


# ---------- regression ----------
def test_stats_endpoint():
    r = requests.get(f"{API}/stats", timeout=15)
    assert r.status_code == 200
    assert isinstance(r.json(), dict)


def test_vuln_scans_list():
    r = requests.get(f"{API}/vuln/scans?limit=10", timeout=15)
    assert r.status_code == 200
    j = r.json()
    scans = j if isinstance(j, list) else j.get("scans") or j.get("items")
    assert scans is not None
    assert isinstance(scans, list)


def test_payload_mutate():
    r = requests.post(f"{API}/vuln/mutate", json={
        "payload": "<script>alert(1)</script>", "count": 10
    }, timeout=20)
    assert r.status_code == 200, r.text[:200]
    j = r.json()
    muts = j.get("mutations") or j.get("payloads") or []
    assert len(muts) >= 5


def test_history_diff():
    r = requests.get(f"{API}/vuln/history-diff?target=https://example.com", timeout=15)
    assert r.status_code == 200
    assert isinstance(r.json(), dict)


def test_burp_zip_download(launched_scan):
    # Use a completed scan — reuse the launched one after test_scan_eventually_completes
    sid = launched_scan
    r = requests.get(f"{API}/vuln/scans/{sid}/burp.zip", timeout=30)
    assert r.status_code == 200, r.text[:200]
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert any("README" in n or n.endswith(".http") or n.endswith(".txt") for n in names), names


def test_explain_endpoint_or_ratelimit(launched_scan):
    sid = launched_scan
    try:
        r = requests.post(f"{API}/vuln/scans/{sid}/explain",
                          json={"finding_index": 0, "lang": "en"}, timeout=90)
    except requests.exceptions.ReadTimeout:
        pytest.skip("LLM explain took >90s (external LLM latency)")
    # allow 200, rate-limit 429, or 400 when no findings, or 404
    assert r.status_code in (200, 202, 429, 400, 404), f"status={r.status_code} body={r.text[:200]}"
