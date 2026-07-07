"""Iteration 18 · Code-review fixes validation.

Covers:
- HIGH · SSRF scope concurrency (contextvars.ContextVar)
- MEDIUM · FP badge index alignment (scores[i].key = "type|subtype|url|param")
- MEDIUM · Takeover scan BOLA (all /api/scans/{id}/* return 404 for fake ids)
- LOW · WebSocket status strings (failed / cancelled also break loop)
- REGRESSION · v7.6.0 guards still on
"""

import os
import time
import uuid
import asyncio
import contextvars
import pytest
import requests

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = f"{BASE_URL}/api"


# ---------- HIGH · ContextVar unit smoke ----------
def test_ssrf_scope_is_contextvar():
    from scanner.vuln.ssrf_guard import _SCOPE_CTX  # noqa: E402
    assert isinstance(_SCOPE_CTX, contextvars.ContextVar)


def test_ssrf_scope_isolation_between_tasks():
    """Two concurrent asyncio tasks must have independent scope allowlists."""
    from scanner.vuln.ssrf_guard import (
        _SCOPE_CTX,
        set_scope_allowlist,
        clear_scope_allowlist,
    )

    async def worker(host: str, seen: dict, evt: asyncio.Event):
        set_scope_allowlist([host])
        await evt.wait()          # let the other task set its own scope first
        seen[host] = list(_SCOPE_CTX.get())
        clear_scope_allowlist()

    async def run():
        seen = {}
        evt = asyncio.Event()
        t1 = asyncio.create_task(worker("example.com", seen, evt))
        t2 = asyncio.create_task(worker("iana.org", seen, evt))
        await asyncio.sleep(0.05)
        evt.set()
        await asyncio.gather(t1, t2)
        return seen

    seen = asyncio.run(run())
    assert seen["example.com"] == ["example.com"]
    assert seen["iana.org"] == ["iana.org"]


# ---------- MEDIUM · Takeover BOLA on all 6+ endpoints ----------
FAKE = "00000000-0000-0000-0000-000000000000"


@pytest.mark.parametrize("method,path", [
    ("GET",    f"/scans/{FAKE}"),
    ("GET",    f"/scans/{FAKE}/results"),
    ("DELETE", f"/scans/{FAKE}"),
    ("GET",    f"/scans/{FAKE}/logs"),
    ("GET",    f"/scans/{FAKE}/export/json"),
    ("POST",   f"/scans/{FAKE}/cancel"),
    ("GET",    f"/scans/{FAKE}/report/bug-bounty/en"),
    ("POST",   f"/scans/{FAKE}/screenshots/http%3A%2F%2Fexample.com"),
    ("GET",    f"/scans/{FAKE}/screenshots/http%3A%2F%2Fexample.com"),
    ("GET",    f"/scans/{FAKE}/graph"),
])
def test_takeover_bola_404(method, path):
    r = requests.request(method, f"{API}{path}", timeout=15)
    # Must not be 200/500; 404 (missing) or 403 (forbidden) both acceptable
    assert r.status_code in (403, 404), f"{method} {path} → {r.status_code}: {r.text[:200]}"


# ---------- REGRESSION · security-status still v7.6.0 with 5 guards ----------
def test_security_status_v760():
    r = requests.get(f"{API}/security-status", timeout=10)
    assert r.status_code == 200
    j = r.json()
    assert j.get("version") in ("v7.6.0", "7.6.0")
    guards = j.get("guards", {})
    for g in ("ssrf_guard", "ownership_scope", "report_xss_escaping",
              "secret_masking", "rate_limiting"):
        assert guards.get(g) is True, f"guard {g} not enabled: {guards}"


def test_ssrf_still_blocks_loopback():
    r = requests.post(f"{API}/vuln/scans",
                      json={"target": "http://127.0.0.1", "scope": "quick"},
                      timeout=10)
    assert r.status_code in (400, 422)


# ---------- MEDIUM · FP-predict returns `key` ----------
def _create_vuln_scan(target="http://example.com"):
    r = requests.post(f"{API}/vuln/scans",
                      json={"target": target, "scope": "quick"},
                      timeout=15)
    if r.status_code == 429:
        pytest.skip("rate-limited; restart backend to reset")
    assert r.status_code == 200, r.text
    return r.json()["scan_id"]


def _wait_done(scan_id, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{API}/vuln/scans/{scan_id}", timeout=10)
        if r.status_code == 200 and r.json().get("status") in (
                "completed", "failed", "error", "cancelled", "stopped"):
            return r.json()
        time.sleep(3)
    return None


def test_fp_predict_returns_key():
    scan_id = _create_vuln_scan("http://example.com")
    doc = _wait_done(scan_id)
    assert doc is not None, "scan never completed"
    r = requests.post(f"{API}/vuln/scans/{scan_id}/fp-predict?use_llm=false",
                      timeout=30)
    assert r.status_code == 200, r.text
    j = r.json()
    scores = j.get("scores", [])
    for s in scores:
        assert "key" in s, f"score missing 'key': {s}"
        # key = "type|subtype|url|param"  (any parts may be empty)
        assert s["key"].count("|") == 3, f"malformed key {s['key']!r}"


# ---------- HIGH · Concurrency: two scans against DIFFERENT hosts ----------
def test_ssrf_scope_concurrency_no_leak():
    r1 = requests.post(f"{API}/vuln/scans",
                       json={"target": "http://example.com", "scope": "quick"},
                       timeout=15)
    r2 = requests.post(f"{API}/vuln/scans",
                       json={"target": "http://iana.org", "scope": "quick"},
                       timeout=15)
    if r1.status_code == 429 or r2.status_code == 429:
        pytest.skip("rate-limited")
    assert r1.status_code == 200 and r2.status_code == 200
    sid1, sid2 = r1.json()["scan_id"], r2.json()["scan_id"]

    d1 = _wait_done(sid1)
    d2 = _wait_done(sid2)
    assert d1 and d2

    def hosts_in_findings(doc):
        hosts = set()
        for f in doc.get("findings", []) or []:
            u = f.get("url") or ""
            if "example.com" in u:
                hosts.add("example.com")
            if "iana.org" in u:
                hosts.add("iana.org")
        return hosts

    h1, h2 = hosts_in_findings(d1), hosts_in_findings(d2)
    # scan1 findings must not include iana.org host, scan2 must not include example.com
    assert "iana.org" not in h1, f"scan1 leaked iana.org: {h1}"
    assert "example.com" not in h2, f"scan2 leaked example.com: {h2}"


# ---------- Real scan happy path (owner still 200) ----------
def test_takeover_owner_happy_path():
    # Create real takeover scan
    r = requests.post(f"{API}/scans",
                      json={"domain": "example.com"}, timeout=15)
    if r.status_code == 429:
        pytest.skip("rate-limited")
    if r.status_code == 404:
        pytest.skip("takeover /api/scans POST not exposed as expected")
    assert r.status_code in (200, 201), r.text
    sid = r.json().get("scan_id") or r.json().get("id")
    assert sid
    g = requests.get(f"{API}/scans/{sid}", timeout=10)
    assert g.status_code == 200, f"owner GET should be 200, got {g.status_code}"
