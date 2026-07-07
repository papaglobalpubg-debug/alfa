"""CyberScope v7.9.x - Public API Rate Limiter."""
import logging
import os
import threading
import time
from collections import deque
from typing import Deque, Dict, Tuple

log = logging.getLogger('cyberscope.rate')


class SimpleRateLimiter:
    def __init__(self, limit: int = 60, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self._buckets: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            dq = self._buckets.setdefault(key, deque())
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= self.limit:
                retry = max(1, int(self.window_seconds - (now - dq[0])))
                return False, retry
            dq.append(now)
            return True, 0

    def reset(self, key: str = None) -> None:
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


public_api_limiter = SimpleRateLimiter(
    limit=int(os.environ.get('PUBLIC_API_RATE_LIMIT', '60')),
    window_seconds=int(os.environ.get('PUBLIC_API_RATE_WINDOW', '60')),
)
