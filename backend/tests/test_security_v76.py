"""SEC-001..005 + hardening tests for CyberScope v7.6.0.

NOTE: SEC-005 rate-limit (20 scan-launches/hour per IP) is session-shared.
We therefore group scan-creation tests carefully.
"""
import os
import sys
import time

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # Fallback: try to read frontend/.env directly
    try:
        with open("/app/frontend/.env") as f:
            for line in f:
                if line.startswith("REACT_APP_BACKEND_URL="):
                    BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
                    break
    except Exception:
        pass


@pytest.fixture(scope="session")
def api():
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s


# ---------------- /security-status ----------------
def test_security_status(api):
    r = api.get(f"{BASE_URL}/api/security-status", timeout=10)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["version"] == "7.6.0"
    for g in ("ssrf_guard", "ownership_scope", "report_xss_escaping",
              "secret_masking", "rate_limiting"):
        assert j["guards"][g] is True, f"guard {g} not enabled"
    assert "cookies_secure" in j["hardening"]
    assert j["hardening"]["cookies_samesite"] == "strict"
    assert "rate_limits" in j and "scan_launch_per_hour_anon" in j["rate_limits"]


# ---------------- SEC-001 SSRF guard ----------------
@pytest.mark.parametrize("bad", [
    "http://127.0.0.1",
    "http://169.254.169.254",
    "http://10.0.0.5",
    "http://192.168.1.1",
    "file:///etc/passwd",
    "gopher://x",
])
def test_ssrf_blocks_bad_targets(api, bad):
    r = api.post(f"{BASE_URL}/api/vuln/scans", json={"target": bad}, timeout=15)
    assert r.status_code == 400, f"{bad} → {r.status_code} {r.text}"
    assert "SSRF" in r.text or "ssrf" in r.text.lower()


# ---------------- SEC-003 report generator helpers ----------------
def test_report_helpers_escape_and_block():
    sys.path.insert(0, "/app/scanner")
    from vuln.report_generator import _safe_href, _inline_md, _html_escape
    assert _safe_href("javascript:alert(1)") == "#blocked"
    assert _safe_href("data:text/html,x") == "#blocked"
    assert _safe_href("https://example.com") == "https://example.com"
    assert "&lt;script&gt;" in _inline_md("<script>x</script>")
    assert _html_escape("<a>") == "&lt;a&gt;"


# ---------------- SEC-004 secret masking (notify-config) ----------------
def test_notify_config_masks_secrets(api):
    payload = {
        "slack_webhook": "https://hooks.slack.com/services/T00/B00/verysecretwebhookvalue",
        "discord_webhook": "https://discord.com/api/webhooks/1234567890/discsecrettoken",
        "telegram_bot_token": "123456:ABC-DEF_verysecretbottoken",
        "telegram_chat_id": "-1001234567890",
        "generic_webhook": "https://example.com/hook?token=supersecrettoken",
    }
    r = api.post(f"{BASE_URL}/api/vuln/notify-config", json=payload, timeout=10)
    assert r.status_code == 200, r.text
    r = api.get(f"{BASE_URL}/api/vuln/notify-config", timeout=10)
    assert r.status_code == 200
    j = r.json()
    # No raw secret must leak
    for secret_field in ("slack_webhook", "discord_webhook",
                         "telegram_bot_token", "generic_webhook"):
        assert secret_field not in j, f"raw {secret_field} leaked"
        assert j.get(f"{secret_field}_configured") is True
        preview = j.get(f"{secret_field}_preview")
        assert preview and "…" in preview
    # Preserve secrets when re-POSTing empty
    r = api.post(f"{BASE_URL}/api/vuln/notify-config", json={}, timeout=10)
    assert r.status_code == 200
    r = api.get(f"{BASE_URL}/api/vuln/notify-config", timeout=10)
    j = r.json()
    assert j.get("slack_webhook_configured") is True


# ---------------- SEC-002 BOLA — 404 on nonexistent scan ----------------
def test_bola_404_on_missing_scan(api):
    fake = "00000000-0000-0000-0000-deadbeefcafe"
    assert api.get(f"{BASE_URL}/api/vuln/scans/{fake}", timeout=10).status_code == 404
    assert api.delete(f"{BASE_URL}/api/vuln/scans/{fake}", timeout=10).status_code == 404
    assert api.post(f"{BASE_URL}/api/vuln/scans/{fake}/cancel", timeout=10).status_code == 404


# ---------------- SEC-002 bulk-delete ownership filtering ----------------
def test_bulk_delete_filters_to_owned(api):
    # Create one scan as guest
    r = api.post(f"{BASE_URL}/api/vuln/scans",
                 json={"target": "https://example.com", "depth": "shallow",
                       "modules": ["fingerprint"], "disabled": []},
                 timeout=15)
    assert r.status_code == 200, r.text
    sid = r.json()["scan_id"]
    fake = "00000000-0000-0000-0000-notarealscanid"
    r = api.post(f"{BASE_URL}/api/vuln/scans/bulk-delete",
                 json={"ids": [sid, fake]}, timeout=15)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["requested"] == 2
    assert j["authorized"] == 1
    assert j["deleted"] == 1


# ---------------- SEC-005 rate limit — notify-test 10/hr ----------------
def test_notify_test_rate_limit(api):
    got_429 = False
    for i in range(12):
        r = api.post(f"{BASE_URL}/api/vuln/notify-test",
                     json={"slack_webhook": "https://example.invalid/x"},
                     timeout=10)
        if r.status_code == 429:
            got_429 = True
            assert "Retry-After" in r.headers
            break
    assert got_429, "notify-test should have rate-limited before request #12"


# ---------------- SEC-005 rate limit — scan-launch 20/hr ----------------
# Runs LAST so we don't exhaust the budget for earlier tests.
@pytest.mark.order("last")
def test_scan_launch_rate_limit(api):
    successes = 0
    got_429 = False
    for i in range(25):
        r = api.post(f"{BASE_URL}/api/vuln/scans",
                     json={"target": "https://example.com", "depth": "shallow",
                           "modules": ["fingerprint"], "disabled": []},
                     timeout=15)
        if r.status_code == 200:
            successes += 1
        elif r.status_code == 429:
            got_429 = True
            assert "Retry-After" in r.headers
            break
    assert got_429, f"expected 429 after 20 scan creates (got {successes} successes)"
