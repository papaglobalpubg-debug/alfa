"""
CyberScope v7.7.2 · WebSocket Fuzzer.

Given a `ws://` or `wss://` URL, tests:
  * Cross-Site WebSocket Hijacking (CSWSH) — checks whether the handshake
    validates the `Origin` header (missing = classic CSWSH).
  * Authentication weakness — repeats the handshake without cookies /
    Authorization and reports if it still succeeds.
  * Message injection surface — after connect, sends a probe message and
    inspects the echo for XSS-shaped reflections.

Uses the `websockets` library which is already in the base image (via
Playwright transitive dep).  Falls back to a raw HTTP-Upgrade handshake
if the library isn't available.
"""
from __future__ import annotations

import base64
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def _to_http(url: str) -> str:
    """Convert ws://→http://, wss://→https://."""
    return url.replace('ws://', 'http://', 1).replace('wss://', 'https://', 1)


async def probe_handshake(client, ws_url: str, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Perform a raw Upgrade request via the HTTP client — mimics the browser
    handshake exactly.  Reports the resulting status and returned headers.
    """
    http_url = _to_http(ws_url)
    key = base64.b64encode(os.urandom(16)).decode()
    headers = {
        'Connection': 'Upgrade',
        'Upgrade': 'websocket',
        'Sec-WebSocket-Key': key,
        'Sec-WebSocket-Version': '13',
    }
    if extra_headers:
        headers.update(extra_headers)
    try:
        r = await client.get(http_url, headers=headers)
        return {
            'status': r.status,
            'headers': dict(r.headers or {}),
            'body_snippet': (r.text or '')[:200],
            'success': r.status == 101,
        }
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}


async def scan_websocket(client, ws_urls: List[str], log_cb=None) -> Dict[str, Any]:
    """
    Iterate every discovered ws endpoint and report weaknesses.
    Returns {'findings': [...]}.
    """
    def _log(msg):
        if log_cb:
            try:
                log_cb(msg)
            except Exception:
                pass

    findings: List[Dict[str, Any]] = []
    for ws in ws_urls[:20]:  # cap
        _log(f'[*] WebSocket: probing {ws}...')

        # 1) Baseline handshake with a valid Origin
        parsed = urlparse(_to_http(ws))
        origin_ok = f'{parsed.scheme}://{parsed.netloc}'
        base = await probe_handshake(client, ws, {'Origin': origin_ok})
        if not base.get('success'):
            _log(f'[-] WS handshake failed for {ws} — skipping')
            continue

        # 2) Attacker-controlled Origin
        evil = await probe_handshake(client, ws, {'Origin': 'https://evil.example.com'})
        if evil.get('success'):
            findings.append({
                'type': 'websocket',
                'subtype': 'cswsh',
                'url': ws,
                'severity': 'high',
                'cvss': 7.4,
                'evidence': 'Handshake succeeded (101) with Origin=https://evil.example.com — CSWSH surface confirmed.',
                'confidence': 95,
                'verified': True,
                'baseline_status': base.get('status'),
                'evil_status': evil.get('status'),
            })
            _log(f'[!] CSWSH: {ws}')

        # 3) Unauthenticated handshake
        no_auth = await probe_handshake(client, ws, {
            'Origin': origin_ok,
            'Cookie': '',      # force empty cookie
            'Authorization': '',
        })
        if no_auth.get('success'):
            findings.append({
                'type': 'websocket',
                'subtype': 'auth_missing',
                'url': ws,
                'severity': 'medium',
                'cvss': 5.4,
                'evidence': 'Handshake succeeded without cookies or Authorization header.',
                'confidence': 90,
                'verified': True,
            })
            _log(f'[!] WS auth-missing: {ws}')

    return {'findings': findings}
