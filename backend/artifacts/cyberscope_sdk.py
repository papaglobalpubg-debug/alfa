"""
CyberScope Python SDK (v7.9.2)

Requires: Enterprise or Lifetime plan.
Install: pip install requests

Usage:
    from cyberscope_sdk import CyberScope
    cs = CyberScope(api_key="cs_...", base="https://your-cyberscope-instance.com")
    scan = cs.scan("https://example.com", depth="deep")
    print(cs.wait(scan["scan_id"]))
    triage = cs.triage(scan["scan_id"])
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests


class CyberScopeError(Exception):
    """Raised when the CyberScope API returns a non-2xx response."""


class CyberScope:
    def __init__(self, api_key: str, base: str = "https://cyberscope.io", timeout: int = 60):
        if not api_key or not api_key.startswith("cs_"):
            raise ValueError("api_key must start with 'cs_'")
        self.api_key = api_key
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key, "User-Agent": "cyberscope-sdk-py/7.9.2"})

    # ---------- internals ----------
    def _req(self, method: str, path: str, **kwargs) -> Any:
        url = f"{self.base}{path}"
        try:
            r = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as e:
            raise CyberScopeError(f"network_error: {e}") from e
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail")
            except Exception:
                detail = r.text[:200]
            raise CyberScopeError(f"HTTP {r.status_code}: {detail}")
        return r.json() if r.content else {}

    # ---------- public ----------
    def info(self) -> Dict[str, Any]:
        return self._req("GET", "/api/pub/v1/info")

    def scan(self, target: str, depth: str = "medium",
             modules: Optional[List[str]] = None) -> Dict[str, Any]:
        payload = {"target": target, "depth": depth}
        if modules:
            payload["modules"] = modules
        return self._req("POST", "/api/pub/v1/scan", json=payload)

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        return self._req("GET", f"/api/pub/v1/scan/{scan_id}")

    def triage(self, scan_id: str, max_items: int = 20) -> Dict[str, Any]:
        return self._req("GET", f"/api/pub/v1/scan/{scan_id}/triage",
                          params={"max_items": max_items})

    def wait(self, scan_id: str, poll_interval: float = 5.0,
             max_wait: float = 900.0) -> Dict[str, Any]:
        """Block until the scan reaches a terminal status or max_wait elapses."""
        deadline = time.time() + max_wait
        while time.time() < deadline:
            s = self.get_scan(scan_id)
            if s.get("status") in ("done", "failed", "canceled"):
                return s
            time.sleep(poll_interval)
        raise CyberScopeError("timeout_waiting_for_scan")


if __name__ == "__main__":
    import os
    cs = CyberScope(api_key=os.environ["CYBERSCOPE_API_KEY"],
                    base=os.environ.get("CYBERSCOPE_BASE", "https://cyberscope.io"))
    print(cs.info())
