"""
Intelligent HTTP client with adaptive rate limiting, retries, and response fingerprinting.
Uses httpx.AsyncClient for maximum concurrency.

v7.6 · SEC-001 — every outbound request is now checked by ssrf_guard before it hits the wire.
"""
import asyncio
import hashlib
import random
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .ssrf_guard import assert_safe, SSRFGuardError


USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
]


class Response:
    """Wrapper around httpx.Response with fingerprint methods."""
    __slots__ = ('url', 'status', 'headers', 'body', 'text', 'elapsed', 'error', 'redirect_url', 'method')

    def __init__(self, url='', status=0, headers=None, body=b'', text='', elapsed=0.0,
                 error=None, redirect_url=None, method='GET'):
        self.url = url
        self.status = status
        self.headers = headers or {}
        self.body = body
        self.text = text
        self.elapsed = elapsed
        self.error = error
        self.redirect_url = redirect_url
        self.method = method

    @property
    def length(self) -> int:
        return len(self.body) if self.body else len(self.text or '')

    def fingerprint(self) -> str:
        """Stable fingerprint for baseline comparison (status + length + first 500 tokens)."""
        preview = (self.text or '')[:500]
        # Strip dynamic tokens (CSRF, timestamps)
        preview = re.sub(r'[a-f0-9]{16,}', 'X', preview)
        preview = re.sub(r'\d{10,}', 'N', preview)
        h = hashlib.sha1(preview.encode('utf-8', errors='ignore')).hexdigest()[:12]
        return f'{self.status}:{self.length // 100}:{h}'

    def has_marker(self, marker: str) -> bool:
        return marker.lower() in (self.text or '').lower()


class AdaptiveHTTPClient:
    """
    High-concurrency HTTP client with:
    - Adaptive rate limiting (backs off on 429/503)
    - Retries with jitter
    - Random UA rotation
    - Response fingerprinting
    - Rate limit awareness (X-RateLimit-*)
    """

    def __init__(self, concurrency: int = 30, timeout: float = 12.0,
                 max_retries: int = 2, follow_redirects: bool = False,
                 verify_tls: bool = False, proxy: Optional[str] = None,
                 session_cookies: Optional[str] = None,
                 session_headers: Optional[Dict[str, str]] = None,
                 proxy_pool: Optional[list] = None,
                 rate_limit_delay: float = 0.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.max_retries = max_retries
        self.follow_redirects = follow_redirects
        self.verify_tls = verify_tls
        self.proxy = proxy
        self.session_cookies = session_cookies  # Cookie header string
        self.session_headers = session_headers or {}  # Custom headers (e.g. Authorization)
        # v7.3: Rate limit + proxy pool
        self.proxy_pool = list(proxy_pool or [])  # rotate through these
        self._proxy_idx = 0
        self.rate_limit_delay = max(0.0, float(rate_limit_delay))
        self._last_req_ts = 0.0
        self._sem = asyncio.Semaphore(concurrency)
        self._rate_limit_hits = 0
        self._backoff = 0.0
        transport = httpx.AsyncHTTPTransport(retries=0, verify=verify_tls, proxy=proxy)
        limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=timeout / 2),
            transport=transport,
            follow_redirects=follow_redirects,
            limits=limits,
            http2=False,
            verify=verify_tls,
        )
        # Build client pool for proxy rotation
        self._pool_clients = []
        for prx in self.proxy_pool:
            try:
                self._pool_clients.append(httpx.AsyncClient(
                    timeout=httpx.Timeout(timeout, connect=timeout / 2),
                    transport=httpx.AsyncHTTPTransport(retries=0, verify=verify_tls, proxy=prx),
                    follow_redirects=follow_redirects, http2=False, verify=verify_tls,
                    limits=limits,
                ))
            except Exception:
                continue
        self.stats = {'requests': 0, 'errors': 0, 'rate_limited': 0, 'total_bytes': 0}

    async def close(self):
        await self._client.aclose()
        for c in self._pool_clients:
            try:
                await c.aclose()
            except Exception:
                pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        }
        # Session (login-aware): cookies + auth headers
        if self.session_cookies:
            h['Cookie'] = self.session_cookies
        if self.session_headers:
            h.update(self.session_headers)
        if extra:
            h.update(extra)
        return h

    async def _adaptive_wait(self):
        if self._backoff > 0:
            await asyncio.sleep(self._backoff + random.uniform(0, 0.3))
        # v7.3: rate-limit throttle
        if self.rate_limit_delay > 0:
            now = time.time()
            gap = now - self._last_req_ts
            if gap < self.rate_limit_delay:
                await asyncio.sleep(self.rate_limit_delay - gap + random.uniform(0, 0.05))
            self._last_req_ts = time.time()

    def _next_client(self):
        """Return the client to use for the next request. Rotates through proxy pool."""
        if not self._pool_clients:
            return self._client
        # Round-robin
        c = self._pool_clients[self._proxy_idx % len(self._pool_clients)]
        self._proxy_idx += 1
        return c

    def _observe(self, r: httpx.Response):
        if r.status_code == 429:
            self._rate_limit_hits += 1
            self.stats['rate_limited'] += 1
            self._backoff = min(self._backoff + 0.5, 5.0)
        elif r.status_code >= 500:
            self._backoff = min(self._backoff + 0.2, 3.0)
        else:
            self._backoff = max(self._backoff - 0.1, 0.0)

    async def request(self, method: str, url: str, *,
                      params=None, data=None, json=None, headers=None,
                      cookies=None, follow_redirects=None) -> Response:
        # v7.6 · SEC-001 — SSRF guard runs BEFORE the semaphore so blocked
        # URLs don't consume concurrency budget and can be counted separately.
        try:
            assert_safe(url)
        except SSRFGuardError as e:
            self.stats['ssrf_blocked'] = self.stats.get('ssrf_blocked', 0) + 1
            return Response(url=url, status=0,
                            error=f'SSRFBlocked: {e}', method=method)
        async with self._sem:
            await self._adaptive_wait()
            attempt = 0
            last_exc = None
            fr = self.follow_redirects if follow_redirects is None else follow_redirects
            while attempt <= self.max_retries:
                attempt += 1
                self.stats['requests'] += 1
                t0 = time.time()
                try:
                    client = self._next_client()
                    r = await client.request(
                        method, url, params=params, data=data, json=json,
                        headers=self._headers(headers), cookies=cookies,
                        follow_redirects=fr,
                    )
                    elapsed = time.time() - t0
                    self._observe(r)
                    body = r.content or b''
                    try:
                        text = r.text
                    except Exception:
                        text = body.decode('utf-8', errors='ignore')
                    self.stats['total_bytes'] += len(body)
                    return Response(
                        url=str(r.url), status=r.status_code,
                        headers=dict(r.headers), body=body, text=text,
                        elapsed=elapsed, method=method,
                        redirect_url=r.headers.get('Location'),
                    )
                except (httpx.TimeoutException, httpx.ReadError,
                        httpx.ConnectError, httpx.RemoteProtocolError) as e:
                    last_exc = e
                    if attempt <= self.max_retries:
                        await asyncio.sleep(0.3 * attempt + random.uniform(0, 0.3))
                    continue
                except Exception as e:  # noqa
                    last_exc = e
                    break
            self.stats['errors'] += 1
            return Response(url=url, error=f'{type(last_exc).__name__}: {last_exc}', method=method)

    async def get(self, url, **kw):
        return await self.request('GET', url, **kw)

    async def post(self, url, **kw):
        return await self.request('POST', url, **kw)

    async def put(self, url, **kw):
        return await self.request('PUT', url, **kw)

    async def delete(self, url, **kw):
        return await self.request('DELETE', url, **kw)

    async def head(self, url, **kw):
        return await self.request('HEAD', url, **kw)

    async def options(self, url, **kw):
        return await self.request('OPTIONS', url, **kw)


# Convenience: response diffing
def response_similarity(a: Response, b: Response) -> float:
    """0.0 = totally different, 1.0 = identical."""
    if a.status != b.status:
        return 0.0
    if a.length == 0 and b.length == 0:
        return 1.0
    la, lb = a.length, b.length
    ratio = min(la, lb) / max(la, lb) if max(la, lb) > 0 else 0.0
    if a.fingerprint() == b.fingerprint():
        return 1.0
    return ratio


def different_enough(a: Response, b: Response, threshold: float = 0.85) -> bool:
    return response_similarity(a, b) < threshold
